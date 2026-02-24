#!/opt/conda/envs/morpheus/bin/python
"""
NVIDIA Morpheus Hybrid Pipeline
With Peer Group DFP Anomaly Detection
"""
import os
import re
import logging
import torch
import json
import numpy as np
import cupy as cp
import pandas as pd
import cudf
import ipaddress
import math
import typing
import mrc

from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from transformers import AutoTokenizer, AutoModelForCausalLM
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from sklearn.cluster import MiniBatchKMeans

from morpheus.config import Config
from morpheus.pipeline.linear_pipeline import LinearPipeline
from morpheus.stages.input.kafka_source_stage import KafkaSourceStage
from morpheus.stages.preprocess.deserialize_stage import DeserializeStage
from morpheus.stages.general.monitor_stage import MonitorStage
from morpheus.pipeline.pass_thru_type_mixin import PassThruTypeMixin
from morpheus.pipeline.single_port_stage import SinglePortStage
from morpheus.messages import ControlMessage, MessageMeta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# STAGE 1: REGEX DETECTOR

class RegexDetector:
    """Fast pattern matching for known attack signatures"""

    def __init__(self):
        self.patterns = {
            'sql_injection': [
                r"(\bUNION\b.*\bSELECT\b|\bOR\b.*=.*)",
                r"(\b(DROP|DELETE|INSERT|UPDATE)\b.*\b(TABLE|FROM|INTO)\b)"
            ],
            'xss_attack': [
                r"(<script|javascript:|onerror=|onload=)",
                r"(alert\(|eval\(|document\.cookie)"
            ],
            'command_injection': [
                r"(;|\||&&|`|\$\(.*\))",
                r"(\.\./|\.\.\\|/etc/passwd)"
            ],
            'brute_force': [
                r"(failed.*password|authentication.*failed).*(\d+.*times?)",
                r"(too many.*attempts|account.*locked)"
            ],
            'malware': [
                r"(virus|trojan|ransomware|malware|infected)",
                r"(cryptominer|rootkit|keylogger)"
            ],
            'port_scan': [
                r"(SYN.*flood|port.*scan|nmap|masscan)"
            ],
            'web_attack': [
                r"(\.\./|\.\./\.\./|path.*traversal)",
                r"(cmd\.exe|/bin/bash|powershell)"
            ]
        }

        self.compiled = {}
        for category, patterns in self.patterns.items():
            self.compiled[category] = [re.compile(p, re.IGNORECASE) for p in patterns]

        logging.info(f"Regex: {len(self.patterns)} threat categories loaded")

    def detect(self, text):
        """Returns threat info if pattern matches"""
        for category, patterns in self.compiled.items():
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    return {
                        'regex_match': True,
                        'regex_category': category,
                        'regex_confidence': 0.95,
                        'regex_pattern': pattern.pattern[:50]
                    }
        return {'regex_match': False}

# DFP: AUTOENCODER MODEL

class NetworkAutoencoder(torch.nn.Module):
    """
    Autoencoder for network traffic behavioral modeling.
    Learns normal patterns per entity (srcip) and detects anomalies.
    """
    def __init__(self, input_dim, encoding_dim=16):
        super().__init__()

        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 32),
            torch.nn.ReLU(),
            torch.nn.BatchNorm1d(32),
            torch.nn.Dropout(0.2),
            torch.nn.Linear(32, encoding_dim),
            torch.nn.ReLU()
        )

        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(encoding_dim, 32),
            torch.nn.ReLU(),
            torch.nn.BatchNorm1d(32),
            torch.nn.Dropout(0.2),
            torch.nn.Linear(32, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# DFP: PEER GROUP PROFILE

class PeerGroupProfile:
    """
    Holds aggregated statistics for a single peer group.
    Used to compare an entity's current behaviour against its peers.
    """

    def __init__(self, group_id: int):
        self.group_id = group_id
        self.entity_ids: set = set()
        self.feature_stats: Dict = {}   # feat_name -> {mean, std, percentile_95}
        self.last_updated: Optional[datetime] = None

    def update_statistics(self, entity_profiles: Dict, dfp_features: List[str]):
        """Recompute group statistics from every member's recent history."""
        if not self.entity_ids:
            return

        feature_vectors = []
        for entity_id in self.entity_ids:
            if entity_id not in entity_profiles:
                continue
            profile = entity_profiles[entity_id]
            if len(profile['history']) == 0:
                continue
            # Use up to last 10 samples per entity
            for sample in list(profile['history'])[-10:]:
                vector = [sample.get(feat, 0.0) for feat in dfp_features]
                feature_vectors.append(vector)

        if not feature_vectors:
            return

        arr = np.array(feature_vectors, dtype=np.float32)
        self.feature_stats = {}

        for idx, feat_name in enumerate(dfp_features):
            col = arr[:, idx]
            valid = col[np.isfinite(col)]
            if len(valid) > 0:
                self.feature_stats[feat_name] = {
                    'mean': float(np.mean(valid)),
                    'std': float(np.std(valid)),
                    'percentile_95': float(np.percentile(valid, 95))
                }
            else:
                self.feature_stats[feat_name] = {
                    'mean': 0.0,
                    'std': 1.0,
                    'percentile_95': 0.0
                }

        self.last_updated = datetime.now()

    def compute_peer_score(self, features: Dict, dfp_features: List[str]) -> float:
        """
        Return a peer-anomaly score in [0, 1].
        Higher means the entity looks unusual compared to its peer group.
        Uses Z-score capped at 3-sigma then mapped to [0, 1].
        """
        if not self.feature_stats:
            return 0.0

        scores = []
        for feat_name in dfp_features:
            if feat_name not in self.feature_stats:
                continue
            value = features.get(feat_name, 0.0)
            if not np.isfinite(value):
                continue

            stats = self.feature_stats[feat_name]
            std = stats['std']

            if std < 1e-6:
                # Constant feature in peer group — any deviation is anomalous
                scores.append(1.0 if abs(value - stats['mean']) > 1e-6 else 0.0)
            else:
                z = abs((value - stats['mean']) / std)
                scores.append(min(z / 3.0, 1.0))

        return float(np.mean(scores)) if scores else 0.0

# DFP: DIGITAL FINGERPRINTING STAGE  (individual baseline + peer comparison)

class DFPAnomalyStage(PassThruTypeMixin, SinglePortStage):
    """
    Digital Fingerprinting Stage for behavioural anomaly detection.

    Detection has two layers:
      1. Individual baseline  — per-entity autoencoder reconstruction error
      2. Peer comparison      — statistical deviation from similar entities
                                (MiniBatchKMeans clustering, refreshed periodically)

    Final anomaly score = individual_weight * individual_score
                        + peer_weight       * peer_score
    """

    def __init__(self, c: Config):
        super().__init__(c)

        self.device = torch.device('cuda:0')

        # DFP core config 
        self.dfp_enabled        = True
        self.entity_field       = 'srcip'
        self.window_size        = 20
        self.training_samples   = 15
        self.anomaly_threshold  = 0.98   # percentile for individual threshold

        # Feature sets 
        self.traffic_features = [
            'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt',
            'duration', 'sentdelta', 'rcvddelta',
            'srcport', 'dstport',
            'is_tcp', 'is_udp', 'is_icmp',
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 'is_night',
            'bytes_per_packet_sent', 'bytes_per_packet_rcvd',
            'total_bytes', 'total_packets', 'bytes_ratio',
            'bytes_sent_ratio', 'packets_sent_ratio',
            'is_external', 'is_internal_src', 'is_internal_dst',
            'is_high_port', 'is_common_port', 'is_suspicious_port',
            'action_deny', 'action_accept',
            'port_entropy', 'byte_variance'
        ]

        self.utm_features = [
            'srcport', 'dstport',
            'is_tcp', 'is_udp', 'is_icmp',
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 'is_night',
            'appid', 'apprisk_low', 'apprisk_medium', 'apprisk_high', 'apprisk_critical',
            'action_deny', 'action_accept',
            'is_external', 'is_internal_src', 'is_internal_dst',
            'is_high_port', 'is_common_port', 'is_suspicious_port',
            'port_entropy'
        ]

        self.dfp_features = self.traffic_features   # default; auto-switched per log

        # Per-entity state
        self.entity_profiles       = {}   # entity -> profile dict
        self.trained_entities      = set()
        self.max_entities          = 1000
        self.entity_message_counts = {}
        self.min_messages_for_training = 10

        # Peer group infrastructure
        self.peer_groups                = {}   # group_id -> PeerGroupProfile
        self.peer_group_assignments     = {}   # entity   -> group_id
        self.peer_grouping_enabled      = True
        self.peer_group_update_interval = 100  # update every N messages
        self.messages_since_peer_update = 0
        self.min_peer_group_size        = 3
        self.max_peer_groups            = 50

        # Combined scoring weights
        self.individual_weight = 0.6
        self.peer_weight       = 0.4

        # Statistics 
        self.dfp_stats = {
            'total_entities'         : 0,
            'trained_models'         : 0,
            'anomalies_detected'     : 0,
            'profiles_created'       : 0,
            'messages_processed'     : 0,
            'peer_groups_created'    : 0,
            'peer_anomalies_detected': 0,
            'peer_grouping_runs'     : 0,
        }

        logging.info("=" * 70)
        logging.info("DFP Anomaly Detection — GPU ACCELERATED + PEER COMPARISON")
        logging.info(f"Entity field        : {self.entity_field}")
        logging.info(f"Window size         : {self.window_size}")
        logging.info(f"Training samples    : {self.training_samples}")
        logging.info(f"Max entities        : {self.max_entities}")
        logging.info(f"Features (traffic)  : {len(self.traffic_features)}")
        logging.info(f"Peer grouping       : {'ENABLED' if self.peer_grouping_enabled else 'DISABLED'}")
        logging.info(f"Peer update interval: {self.peer_group_update_interval} messages")
        logging.info(f"Min peer group size : {self.min_peer_group_size}")
        logging.info(f"Max peer groups     : {self.max_peer_groups}")
        logging.info(f"Score weights       : individual={self.individual_weight}, peer={self.peer_weight}")
        logging.info("=" * 70)

    # Morpheus boilerplate 
    @property
    def name(self) -> str:
        return "dfp-anomaly-detection"

    def accepted_types(self) -> typing.Tuple:
        return (ControlMessage,)

    def supports_cpp_node(self):
        return False

    # Feature extraction 
    def _extract_features(self, log_data: Dict) -> Dict:
        """Extract and engineer features for DFP. Auto-detects log type."""

        features = {}

        def safe_float(val, default=0.0):
            if val is None:
                return default
            try:
                return float(val)
            except (ValueError, TypeError):
                return default

        # Detect log type
        has_traffic_metrics = (
            'sentbyte' in log_data or
            'rcvdbyte' in log_data or
            'duration' in log_data
        )
        log_type = log_data.get('type', '').lower()
        subtype  = log_data.get('subtype', '').lower()
        is_traffic_log = has_traffic_metrics or log_type == 'traffic' or subtype == 'forward'

        # 1. Temporal features
        try:
            ts = log_data.get('@timestamp') or log_data.get('timestamp') or log_data.get('eventtime')
            if ts:
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                elif isinstance(ts, int):
                    dt = datetime.fromtimestamp(
                        ts / 1e9 if ts > 1e15 else (ts / 1000 if ts > 1e10 else ts)
                    )
                else:
                    dt = datetime.fromtimestamp(ts)
                features['hour']              = dt.hour
                features['day_of_week']       = dt.weekday()
                features['is_weekend']        = 1 if dt.weekday() >= 5 else 0
                features['is_business_hours'] = 1 if 9 <= dt.hour <= 17 else 0
                features['is_night']          = 1 if dt.hour >= 22 or dt.hour <= 6 else 0
            else:
                features.update({'hour': 0, 'day_of_week': 0, 'is_weekend': 0,
                                  'is_business_hours': 0, 'is_night': 0})
        except Exception as e:
            logging.debug(f"Timestamp parsing error: {e}")
            features.update({'hour': 0, 'day_of_week': 0, 'is_weekend': 0,
                              'is_business_hours': 0, 'is_night': 0})

        # 2. Port features
        features['srcport'] = safe_float(log_data.get('srcport'))
        features['dstport'] = safe_float(log_data.get('dstport'))

        # 3. Traffic metrics
        if is_traffic_log:
            sent_bytes   = safe_float(log_data.get('sentbyte'))
            rcvd_bytes   = safe_float(log_data.get('rcvdbyte'))
            sent_packets = safe_float(log_data.get('sentpkt'))
            rcvd_packets = safe_float(log_data.get('rcvdpkt'))

            features['sentbyte']  = sent_bytes
            features['rcvdbyte']  = rcvd_bytes
            features['sentpkt']   = sent_packets
            features['rcvdpkt']   = rcvd_packets
            features['duration']  = safe_float(log_data.get('duration'))
            features['sentdelta'] = safe_float(log_data.get('sentdelta'))
            features['rcvddelta'] = safe_float(log_data.get('rcvddelta'))

            features['total_bytes']   = sent_bytes + rcvd_bytes
            features['total_packets'] = sent_packets + rcvd_packets

            features['bytes_per_packet_sent'] = (
                sent_bytes / sent_packets if sent_packets > 0 else 0.0
            )
            features['bytes_per_packet_rcvd'] = (
                rcvd_bytes / rcvd_packets if rcvd_packets > 0 else 0.0
            )
            features['bytes_sent_ratio'] = (
                sent_bytes / features['total_bytes'] if features['total_bytes'] > 0 else 0.0
            )
            features['packets_sent_ratio'] = (
                sent_packets / features['total_packets'] if features['total_packets'] > 0 else 0.0
            )
            features['bytes_ratio'] = (
                sent_bytes / (rcvd_bytes + 1.0) if (sent_bytes or rcvd_bytes) else 0.0
            )
            features['byte_variance'] = 0.0   # filled in _update_entity_profile

        # 4. Protocol features
        raw_proto = log_data.get('proto')
        if isinstance(raw_proto, int):
            proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(raw_proto, "")
        else:
            proto = str(raw_proto or "").lower()

        features['is_tcp']  = 1.0 if proto in ("tcp",  "6")  else 0.0
        features['is_udp']  = 1.0 if proto in ("udp",  "17") else 0.0
        features['is_icmp'] = 1.0 if proto in ("icmp", "1")  else 0.0

        # 5. Application features (UTM)
        if not is_traffic_log or 'appid' in log_data:
            features['appid'] = safe_float(log_data.get('appid'))
            apprisk = str(log_data.get('apprisk') or '').lower()
            features['apprisk_low']      = 1 if apprisk == 'low'      else 0
            features['apprisk_medium']   = 1 if apprisk == 'medium'   else 0
            features['apprisk_high']     = 1 if apprisk == 'high'     else 0
            features['apprisk_critical'] = 1 if apprisk == 'critical' else 0

        # 6. Action features
        action = str(log_data.get('action') or '').lower()
        features['action_deny']   = 1 if action in ('deny', 'block', 'drop', 'reset', 'reject') else 0
        features['action_accept'] = 1 if action in ('allow', 'accept', 'permit', 'pass')         else 0

        # 7. IP classification
        def is_internal_ip(ip):
            try:
                return ipaddress.ip_address(ip).is_private
            except Exception:
                return False

        src_ip = log_data.get('srcip')
        dst_ip = log_data.get('dstip')
        src_internal = is_internal_ip(src_ip) if src_ip else False
        dst_internal = is_internal_ip(dst_ip) if dst_ip else False

        features['is_internal_src'] = 1 if src_internal else 0
        features['is_internal_dst'] = 1 if dst_internal else 0
        features['is_external']     = 1 if (src_internal != dst_internal) else 0

        # 8. Port classification
        COMMON_PORTS     = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389}
        SUSPICIOUS_PORTS = {1337, 4444, 5555, 6666, 6667, 9001, 31337}
        dst_port = int(features['dstport']) if features['dstport'] else 0

        features['is_common_port']     = 1 if dst_port in COMMON_PORTS     else 0
        features['is_high_port']       = 1 if dst_port > 1024              else 0
        features['is_suspicious_port'] = 1 if dst_port in SUSPICIOUS_PORTS else 0

        # 9. Stateful features (filled in _update_entity_profile)
        features['port_entropy']    = 0.0
        features['_is_traffic_log'] = is_traffic_log

        return features

    # Entity profile management 
    def _update_entity_profile(self, entity: str, features: Dict):
        """Update or create an entity profile; enforces max_entities limit."""

        self.entity_message_counts[entity] = self.entity_message_counts.get(entity, 0) + 1

        if entity not in self.entity_profiles:
            if len(self.entity_profiles) >= self.max_entities:
                if self.entity_message_counts[entity] < self.min_messages_for_training:
                    return None
                if self.entity_profiles:
                    least_active = min(
                        self.entity_profiles.keys(),
                        key=lambda e: self.entity_message_counts.get(e, 0)
                    )
                    if self.entity_message_counts[entity] > self.entity_message_counts.get(least_active, 0):
                        logging.info(
                            f"Evicting {least_active} "
                            f"({self.entity_message_counts.get(least_active, 0)} msgs) "
                            f"for {entity} ({self.entity_message_counts[entity]} msgs)"
                        )
                        del self.entity_profiles[least_active]
                        self.trained_entities.discard(least_active)
                        # Clean up peer group membership
                        if least_active in self.peer_group_assignments:
                            gid = self.peer_group_assignments.pop(least_active)
                            if gid in self.peer_groups:
                                self.peer_groups[gid].entity_ids.discard(least_active)
                    else:
                        return None

            self.entity_profiles[entity] = {
                'history'              : deque(maxlen=self.window_size * 2),
                'model'                : None,
                'scaler_mean'          : None,
                'scaler_std'           : None,
                'reconstruction_errors': deque(maxlen=100),
                'last_trained'         : None,
                'port_history'         : deque(maxlen=20),
                'byte_history'         : deque(maxlen=20),
            }
            self.dfp_stats['profiles_created'] += 1
            logging.info(
                f"Created profile for {entity} "
                f"(total: {len(self.entity_profiles)}/{self.max_entities})"
            )

        profile = self.entity_profiles[entity]

        # Update stateful derived features
        profile['port_history'].append(features.get('dstport', 0))
        profile['byte_history'].append(features.get('total_bytes', 0))

        if len(profile['port_history']) > 1:
            features['port_entropy'] = self._entropy(list(profile['port_history']))
        if len(profile['byte_history']) > 1:
            features['byte_variance'] = float(np.var(list(profile['byte_history'])))

        profile['history'].append(features)
        return profile

    def _entropy(self, values: list) -> float:
        """Shannon entropy."""
        if not values:
            return 0.0
        counts = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        total = sum(counts.values())
        return float(
            -sum((c / total) * np.log2(c / total) for c in counts.values() if c > 0)
        )

    # Autoencoder training 
    def _train_entity_model(self, entity: str) -> bool:
        """Train autoencoder for entity — GPU accelerated via CuPy."""
        import time
        t0 = time.time()

        profile = self.entity_profiles[entity]
        if len(profile['history']) < self.training_samples:
            return False

        data = [
            [s.get(feat, 0.0) for feat in self.dfp_features]
            for s in profile['history']
        ]

        X_np = np.array(data, dtype=np.float32)
        if not np.all(np.isfinite(X_np)):
            X_np = np.nan_to_num(X_np, nan=0.0, posinf=0.0, neginf=0.0)

        # Normalise on GPU with CuPy
        X_gpu        = cp.asarray(X_np)
        mean_gpu     = X_gpu.mean(axis=0)
        std_gpu      = X_gpu.std(axis=0)
        std_gpu      = cp.where(std_gpu < 1e-6, 1.0, std_gpu)
        X_scaled_gpu = (X_gpu - mean_gpu) / std_gpu

        if not cp.all(cp.isfinite(X_scaled_gpu)):
            X_scaled_gpu = cp.nan_to_num(X_scaled_gpu, nan=0.0, posinf=0.0, neginf=0.0)

        profile['scaler_mean'] = cp.asnumpy(mean_gpu)
        profile['scaler_std']  = cp.asnumpy(std_gpu)

        # Zero-copy CuPy -> PyTorch tensor on GPU
        X_tensor  = torch.as_tensor(X_scaled_gpu, device=self.device)

        model     = NetworkAutoencoder(len(self.dfp_features)).to(self.device)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        criterion = torch.nn.MSELoss()

        model.train()
        for _ in range(10):   
            optimizer.zero_grad()
            loss = criterion(model(X_tensor), X_tensor)
            loss.backward()
            optimizer.step()
        model.eval()

        profile['model']        = model
        profile['last_trained'] = datetime.now()
        self.dfp_stats['trained_models'] += 1

        logging.warning(
            f"DFP TRAINING: entity={entity}, "
            f"samples={len(profile['history'])}, "
            f"time={time.time() - t0:.3f}s"
        )
        return True

    # Peer group management 
    def _compute_entity_feature_vector(self, entity: str) -> Optional[np.ndarray]:
        """
        Aggregate an entity's recent history into a single vector for clustering.
        Each DFP feature is represented by its mean, std, and max over the last 10 samples.
        """
        profile = self.entity_profiles.get(entity)
        if profile is None or len(profile['history']) < 5:
            return None

        recent = list(profile['history'])[-10:]
        agg = []
        for feat_name in self.dfp_features:
            vals  = [s.get(feat_name, 0.0) for s in recent]
            valid = [v for v in vals if np.isfinite(v)]
            if valid:
                agg.extend([np.mean(valid), np.std(valid), np.max(valid)])
            else:
                agg.extend([0.0, 0.0, 0.0])

        vec = np.array(agg, dtype=np.float32)
        return vec if np.all(np.isfinite(vec)) else None

    def _update_peer_groups(self):
        """
        Cluster all profiled entities by behaviour and refresh group statistics.
        Uses MiniBatchKMeans for streaming-friendly efficiency.
        Called automatically every peer_group_update_interval messages.
        """
        self.dfp_stats['peer_grouping_runs'] += 1

        eligible = []
        vecs     = []

        for entity, profile in self.entity_profiles.items():
            if len(profile['history']) >= self.min_peer_group_size:
                vec = self._compute_entity_feature_vector(entity)
                if vec is not None:
                    eligible.append(entity)
                    vecs.append(vec)

        if len(eligible) < self.min_peer_group_size:
            logging.debug(f"Peer grouping skipped — only {len(eligible)} eligible entities")
            return

        X = np.vstack(vecs)

        n_clusters = min(
            max(3, len(eligible) // 10),
            self.max_peer_groups
        )

        try:
            kmeans = MiniBatchKMeans(
                n_clusters=n_clusters,
                random_state=42,
                batch_size=256,
                max_iter=100
            )
            labels = kmeans.fit_predict(X)
        except Exception as e:
            logging.error(f"Peer group clustering error: {e}")
            return

        # Rebuild groups
        self.peer_groups.clear()
        self.peer_group_assignments.clear()

        for gid in range(n_clusters):
            self.peer_groups[gid] = PeerGroupProfile(gid)

        for entity, label in zip(eligible, labels):
            gid = int(label)
            self.peer_group_assignments[entity] = gid
            self.peer_groups[gid].entity_ids.add(entity)

        # Refresh statistics for groups that are large enough
        for group in self.peer_groups.values():
            if len(group.entity_ids) >= self.min_peer_group_size:
                group.update_statistics(self.entity_profiles, self.dfp_features)

        self.dfp_stats['peer_groups_created'] = len(self.peer_groups)
        avg_size = float(np.mean([len(g.entity_ids) for g in self.peer_groups.values()]))

        logging.info(
            f"Peer groups updated: {n_clusters} groups | "
            f"avg size={avg_size:.1f} | "
            f"entities={len(eligible)}"
        )

    # Anomaly detection — individual + peer
    def _detect_anomaly(self, entity: str, features: Dict) -> Tuple[bool, float, Dict]:
        """
        Returns (is_anomaly, combined_score, details_dict).

        Step 1: autoencoder reconstruction error  → individual_score  [0,1]
        Step 2: peer group Z-score deviation       → peer_score        [0,1]
        Step 3: weighted combination               → combined_score    [0,1]

        Anomaly if:
          combined_score > 0.7, OR
          individual_score > 0.8 AND peer_score > 0.5, OR
          individual_score > 0.5 AND peer_score > 0.8
        """
        profile = self.entity_profiles.get(entity)
        if not profile or profile['model'] is None:
            return False, 0.0, {'method': 'no_model', 'individual_score': 0.0, 'peer_score': 0.0, 'combined_score': 0.0, 'peer_group_id': None, 'peer_group_size': 0, 'reconstruction_error': 0.0, 'threshold': 0.0}

        # Step 1: individual autoencoder score
        X = np.array(
            [[features.get(feat, 0.0) for feat in self.dfp_features]],
            dtype=np.float32
        )
        if not np.all(np.isfinite(X)):
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        X_scaled = (X - profile['scaler_mean']) / profile['scaler_std']
        if not np.all(np.isfinite(X_scaled)):
            X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        with torch.no_grad():
            recon     = profile['model'](X_tensor)
            recon_err = torch.nn.functional.mse_loss(
                recon, X_tensor, reduction='none'
            ).mean(dim=1).cpu().numpy()[0]

        if not np.isfinite(recon_err):
            logging.warning(f"Invalid reconstruction error for {entity}: {recon_err}")
            return False, 0.0, {'method': 'invalid_error', 'individual_score': 0.0, 'peer_score': 0.0, 'combined_score': 0.0, 'peer_group_id': None, 'peer_group_size': 0, 'reconstruction_error': 0.0, 'threshold': 0.0}

        profile['reconstruction_errors'].append(recon_err)

        if len(profile['reconstruction_errors']) < 10:
            return False, 0.0, {'method': 'insufficient_history', 'individual_score': 0.0, 'peer_score': 0.0, 'combined_score': 0.0, 'peer_group_id': None, 'peer_group_size': 0, 'reconstruction_error': 0.0, 'threshold': 0.0}

        errors = np.array(list(profile['reconstruction_errors']))
        errors = errors[np.isfinite(errors)]
        if len(errors) < 10:
            return False, 0.0, {'method': 'insufficient_valid_errors', 'individual_score': 0.0, 'peer_score': 0.0, 'combined_score': 0.0, 'peer_group_id': None, 'peer_group_size': 0, 'reconstruction_error': 0.0, 'threshold': 0.0}

        threshold = np.percentile(errors, self.anomaly_threshold * 100)
        recon_err = float(recon_err)

        e_min, e_max = float(np.min(errors)), float(np.max(errors))
        e_range      = e_max - e_min

        if not np.isfinite(e_range) or e_range < 1e-8:
            individual_score = 0.5 if recon_err > threshold else 0.0
        else:
            individual_score = float(np.clip((recon_err - e_min) / e_range, 0.0, 1.0))
            if not np.isfinite(individual_score):
                individual_score = 0.5 if recon_err > threshold else 0.0
            elif individual_score < 1e-10:
                individual_score = 0.0

        individual_anomaly = recon_err > threshold

        # Step 2: peer group score
        peer_score      = 0.0
        peer_group_id   = None
        peer_group_size = 0

        if self.peer_grouping_enabled and entity in self.peer_group_assignments:
            gid   = self.peer_group_assignments[entity]
            group = self.peer_groups.get(gid)
            if group and group.feature_stats:
                peer_score      = group.compute_peer_score(features, self.dfp_features)
                peer_group_id   = gid
                peer_group_size = len(group.entity_ids)

        # Step 3: combine
        if peer_score > 0.0:
            combined_score = (
                self.individual_weight * individual_score +
                self.peer_weight       * peer_score
            )
            is_anomaly = (
                combined_score > 0.7
                or (individual_score > 0.8 and peer_score > 0.5)
                or (individual_score > 0.5 and peer_score > 0.8)
            )
            detection_method = 'individual_and_peer'
        else:
            combined_score   = individual_score
            is_anomaly       = individual_anomaly
            detection_method = 'individual_only'

        if is_anomaly:
            self.dfp_stats['peer_anomalies_detected'] += 1

        details = {
            'method'              : detection_method,
            'individual_score'    : individual_score,
            'peer_score'          : peer_score,
            'combined_score'      : combined_score,
            'peer_group_id'       : peer_group_id,
            'peer_group_size'     : peer_group_size,
            'reconstruction_error': recon_err,
            'threshold'           : float(threshold),
        }

        return is_anomaly, combined_score, details

    # Morpheus _build_single
    def _build_single(self, builder, input_node):
        def dfp_detection(message: ControlMessage) -> ControlMessage:
            try:
                meta = message.payload()

                with meta.mutable_dataframe() as df:
                    data_dict = {}
                    for col in df.columns:
                        try:
                            data_dict[col] = df[col].to_arrow().to_pylist()
                        except Exception:
                            data_dict[col] = list(df[col])

                    num_rows = len(next(iter(data_dict.values()))) if data_dict else 0
                    if num_rows == 0:
                        return message

                dfp_results = []

                # DFP disabled fast-path 
                if not self.dfp_enabled:
                    for _ in range(num_rows):
                        dfp_results.append(self._empty_result(None, 'disabled'))
                    self._write_dfp_columns(data_dict, dfp_results)
                    message.payload(MessageMeta(cudf.DataFrame(data_dict)))
                    return message

                # Main processing loop 
                for i in range(num_rows):
                    self.dfp_stats['messages_processed'] += 1
                    self.messages_since_peer_update      += 1

                    log_data = {k: v[i] for k, v in data_dict.items()}

                    entity = (
                        log_data.get(self.entity_field) or
                        log_data.get(f'fortinet_{self.entity_field}')
                    )
                    if not entity:
                        dfp_results.append(self._empty_result(None, 'no_entity'))
                        continue

                    features = self._extract_features(log_data)
                    profile  = self._update_entity_profile(entity, features)

                    if profile is None:
                        dfp_results.append(self._empty_result(entity, 'skipped'))
                        continue

                    # Train model if ready (guard against duplicate training)
                    if (profile['model'] is None
                            and len(profile['history']) >= self.training_samples
                            and entity not in self.trained_entities):
                        self.trained_entities.add(entity)
                        self._train_entity_model(entity)

                    # Periodic peer group update
                    if (self.peer_grouping_enabled
                            and self.messages_since_peer_update >= self.peer_group_update_interval):
                        self.messages_since_peer_update = 0
                        self._update_peer_groups()

                    # Detect anomaly
                    if profile['model'] is not None:
                        is_anomaly, score, details = self._detect_anomaly(entity, features)
                        if is_anomaly:
                            self.dfp_stats['anomalies_detected'] += 1

                        dfp_results.append({
                            'dfp_is_anomaly'      : 1 if is_anomaly else 0,
                            'dfp_score'           : score,
                            'dfp_individual_score': details.get('individual_score', score),
                            'dfp_peer_score'      : details.get('peer_score', 0.0),
                            'dfp_entity'          : entity,
                            'dfp_status'          : 'trained',
                            'dfp_peer_group_id'   : details.get('peer_group_id'),
                            'dfp_peer_group_size' : details.get('peer_group_size', 0),
                            'dfp_detection_method': details.get('method', 'individual_only'),
                        })
                    else:
                        dfp_results.append(self._empty_result(entity, 'training'))

                # Write results back into the DataFrame
                self._write_dfp_columns(data_dict, dfp_results)
                self.dfp_stats['total_entities'] = len(self.entity_profiles)

                # Logging every 100 messages 
                if self.dfp_stats['messages_processed'] % 100 == 0:
                    logging.info(
                        f"DFP STATUS | "
                        f"Msgs={self.dfp_stats['messages_processed']} | "
                        f"Entities={len(self.entity_profiles)}/{self.max_entities} | "
                        f"Trained={self.dfp_stats['trained_models']} | "
                        f"Profiles={self.dfp_stats['profiles_created']} | "
                        f"Anomalies={self.dfp_stats['anomalies_detected']} | "
                        f"PeerGroups={self.dfp_stats['peer_groups_created']} | "
                        f"PeerAnomalies={self.dfp_stats['peer_anomalies_detected']} | "
                        f"GroupingRuns={self.dfp_stats['peer_grouping_runs']} | "
                        f"TrackedIPs={len(self.entity_message_counts)}"
                    )

                    if self.entity_message_counts:
                        top = sorted(
                            self.entity_message_counts.items(),
                            key=lambda x: x[1], reverse=True
                        )[:3]
                        logging.info("  Top entities by volume:")
                        for ent, cnt in top:
                            status = "profiled" if ent in self.entity_profiles else "tracking"
                            gid    = self.peer_group_assignments.get(ent, "ungrouped")
                            logging.info(f"    └─ {ent}: {cnt} msgs ({status}, group={gid})")

                if any(r['dfp_is_anomaly'] for r in dfp_results):
                    logging.warning(
                        f"DFP ANOMALY DETECTED | "
                        f"Total={self.dfp_stats['anomalies_detected']} | "
                        f"PeerAnomalies={self.dfp_stats['peer_anomalies_detected']}"
                    )

                message.payload(MessageMeta(cudf.DataFrame(data_dict)))

            except Exception as e:
                logging.error(f"DFP stage error: {e}", exc_info=True)

            return message

        node = builder.make_node(self.unique_name, mrc.core.operators.map(dfp_detection))
        builder.make_edge(input_node, node)
        return node

    # Helpers
    @staticmethod
    def _empty_result(entity, status: str) -> Dict:
        return {
            'dfp_is_anomaly'      : 0,
            'dfp_score'           : 0.0,
            'dfp_individual_score': 0.0,
            'dfp_peer_score'      : 0.0,
            'dfp_entity'          : entity,
            'dfp_status'          : status,
            'dfp_peer_group_id'   : None,
            'dfp_peer_group_size' : 0,
            'dfp_detection_method': 'none',
        }

    @staticmethod
    def _write_dfp_columns(data_dict: Dict, dfp_results: List[Dict]):
        """Write all DFP result fields back into data_dict for the cuDF DataFrame."""
        for key in (
            'dfp_is_anomaly', 'dfp_score', 'dfp_individual_score',
            'dfp_peer_score', 'dfp_entity', 'dfp_status',
            'dfp_peer_group_id', 'dfp_peer_group_size', 'dfp_detection_method',
        ):
            data_dict[key] = [r[key] for r in dfp_results]

# MORPHEUS HYBRID STAGE  (Regex + BERT + DFP + optional LLM)

class MorpheusHybridStage(PassThruTypeMixin, SinglePortStage):
    """
    Multi-stage threat detection:
    1. Regex  — fast known-signature matching
    2. BERT   — GPU ML classification
    3. DFP    — individual + peer behavioural anomaly (from previous stage)
    4. LLM    — DeepSeek-R1 reasoning (disabled in real-time for performance)
    """

    def __init__(self, c: Config):
        super().__init__(c)

        self.device  = torch.device('cuda:0')
        gpu_name     = torch.cuda.get_device_name(0)

        logging.info("=" * 70)
        logging.info("NVIDIA Morpheus Hybrid Pipeline with Peer-Group DFP")
        logging.info(f"GPU: {gpu_name}")
        logging.info("=" * 70)

        # Stage 1: Regex 
        self.regex = RegexDetector()

        # Stage 2: BERT
        logging.info("Loading BERT classifier on GPU...")
        model_path = "/workspace/models/bert_fortinet_trained"
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model path not found: {model_path}")

        safetensors_path = os.path.join(model_path, 'model.safetensors')
        if os.path.exists(safetensors_path):
            size_mb = os.path.getsize(safetensors_path) / (1024 * 1024)
            logging.info(f"Found model.safetensors ({size_mb:.2f} MB)")

        self.bert_tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.bert_model     = DistilBertForSequenceClassification.from_pretrained(
            model_path, use_safetensors=True
        )
        self.bert_model.eval()
        self.bert_model.to(self.device)

        metadata_path = os.path.join(model_path, 'training_metadata.json')
        if os.path.exists(metadata_path):
            with open(metadata_path) as f:
                meta = json.load(f)
                self.id_to_label = {int(k): v for k, v in meta['id2label'].items()}
                logging.info(f"Labels          : {self.id_to_label}")
                logging.info(f"Train accuracy  : {meta.get('eval_accuracy', 'N/A'):.4f}")
                logging.info(f"Train F1        : {meta.get('eval_f1', 'N/A'):.4f}")
        else:
            with open(os.path.join(model_path, 'config.json')) as f:
                cfg = json.load(f)
                self.id_to_label = {int(k): v for k, v in cfg['id2label'].items()}
        logging.info("BERT loaded on GPU")
        logging.info(f"Model classes   : {list(self.id_to_label.values())}")

        # Stage 3: DeepSeek LLM (disabled for real-time) 
        self.llm_enabled = False

        if self.llm_enabled:
            logging.info("Loading DeepSeek-R1-Distill-Qwen-1.5B ...")
            self.llm_tokenizer = AutoTokenizer.from_pretrained(
                "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
                trust_remote_code=True
            )
            self.llm_model = AutoModelForCausalLM.from_pretrained(
                "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
            )
            self.llm_model.eval()
            logging.info("DeepSeek-R1 loaded")
        else:
            logging.warning("LLM DISABLED — BERT + DFP only (real-time performance mode)")
            self.llm_tokenizer = None
            self.llm_model     = None

        # Detection thresholds 
        # dfp_score is now the *combined* individual+peer score, so 0.70 is appropriate
        self.dfp_anomaly_threshold    = 0.70
        self.bert_confidence_threshold = 0.40

        # Kafka producer 
        from confluent_kafka import Producer
        self.kafka_producer = Producer({
            'bootstrap.servers': '192.168.19.80:9092',
            'client.id'        : 'morpheus-hybrid-dfp-peer'
        })
        self.output_topic  = 'morpheus-final-realtime-dfp'
        self.wazuh_enabled = False
        logging.info(f"Kafka output: {self.output_topic}")

        # Statistics 
        self.stats = {
            'total'                 : 0,
            'regex_hits'            : 0,
            'bert_processed'        : 0,
            'llm_calls'             : 0,
            'dfp_individual_anomaly': 0,
            'dfp_peer_anomaly'      : 0,
            'dfp_both_anomaly'      : 0,
            'threats'               : 0,
        }

        logging.info("=" * 70)
        logging.info("ALL STAGES LOADED SUCCESSFULLY")
        logging.info(f"DFP combined-score threshold : {self.dfp_anomaly_threshold}")
        logging.info(f"BERT confidence threshold    : {self.bert_confidence_threshold}")
        logging.info("=" * 70)

    @property
    def name(self) -> str:
        return "morpheus-hybrid-dfp-peer"

    def accepted_types(self) -> typing.Tuple:
        return (ControlMessage,)

    def supports_cpp_node(self):
        return False

    # LLM analysis 
    def _llm_analyze(self, log_data, text, is_dfp_anomaly=False, dfp_score=0.0):
        """DeepSeek-R1 reasoning for complex / ambiguous cases."""
        try:
            srcip    = log_data.get('srcip',    'unknown')
            dstip    = log_data.get('dstip',    'unknown')
            srcport  = log_data.get('srcport',  'unknown')
            dstport  = log_data.get('dstport',  'unknown')
            proto    = log_data.get('proto',    'unknown')
            action   = log_data.get('action',   'unknown')
            sentbyte = log_data.get('sentbyte', 0)
            rcvdbyte = log_data.get('rcvdbyte', 0)

            if is_dfp_anomaly:
                alert_type = f"DFP BEHAVIOURAL ANOMALY (score: {dfp_score:.0%})"
                context    = "Entity behaviour differs significantly from baseline and/or peer group."
            else:
                alert_type = "LOW CONFIDENCE DETECTION"
                context    = "ML classifier uncertain about this traffic pattern."

            proto_names   = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name    = proto_names.get(proto, f"Protocol {proto}")
            service_ports = {
                80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                23: "Telnet", 25: "SMTP", 53: "DNS", 3389: "RDP",
                445: "SMB", 3306: "MySQL"
            }
            dst_service = service_ports.get(dstport, f"port {dstport}")

            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst. "
                        "Analyse network logs concisely. "
                        "Focus on: unusual ports, suspicious protocols, "
                        "data exfiltration patterns, known attack signatures."
                    )
                },
                {
                    "role": "user",
                    "content": (
                        f"ALERT: {alert_type}\n{context}\n\n"
                        f"NETWORK LOG:\n"
                        f"{srcip}:{srcport} → {dstip}:{dstport}\n"
                        f"Protocol: {proto_name}\nService: {dst_service}\n"
                        f"Action: {action}\n"
                        f"Data: {sentbyte}B sent, {rcvdbyte}B received\n\n"
                        f"TASK: Is this malicious traffic?\n"
                        f'Answer in JSON: {{"is_threat": true/false, "confidence": 0-100, "reason": "one sentence"}}'
                    )
                }
            ]

            if hasattr(self.llm_tokenizer, 'apply_chat_template'):
                prompt = self.llm_tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
            else:
                prompt = f"{messages[0]['content']}\n\n{messages[1]['content']}"

            inputs = self.llm_tokenizer(
                prompt, return_tensors='pt', truncation=True, max_length=512
            )
            inputs = {k: v.to(self.llm_model.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.llm_model.generate(
                    **inputs,
                    max_new_tokens=128,
                    temperature=0.4,
                    top_p=0.85,
                    do_sample=True,
                    pad_token_id=(
                        self.llm_tokenizer.eos_token_id
                        or self.llm_tokenizer.pad_token_id
                    )
                )

            response = self.llm_tokenizer.decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )

            is_threat = any(
                w in response.lower()
                for w in ('true', 'attack', 'suspicious', 'threat',
                          'malicious', 'exfiltration', 'scanning')
            )
            conf_match = re.search(r'"confidence":\s*(\d+)', response)
            confidence = int(conf_match.group(1)) if conf_match else (75 if is_threat else 50)

            return {
                'is_suspicious': is_threat,
                'confidence'   : confidence,
                'llm_response' : response,
                'llm_trigger'  : 'dfp_anomaly' if is_dfp_anomaly else 'low_bert_confidence'
            }

        except Exception as e:
            logging.error(f"LLM error: {e}")
            return {
                'is_suspicious': False,
                'confidence'   : 50,
                'llm_response' : f'error: {str(e)}',
                'llm_trigger'  : 'dfp_anomaly' if is_dfp_anomaly else 'low_bert_confidence'
            }

    # Morpheus _build_single 
    def _build_single(self, builder, input_node):
        def hybrid_detection(message: ControlMessage) -> ControlMessage:
            try:
                meta = message.payload()

                with meta.mutable_dataframe() as df:
                    data_dict = {}
                    for col in df.columns:
                        try:
                            data_dict[col] = df[col].to_arrow().to_pylist()
                        except Exception:
                            data_dict[col] = list(df[col])

                    num_rows = len(next(iter(data_dict.values()))) if data_dict else 0
                    if num_rows == 0:
                        return message

                for i in range(num_rows):
                    self.stats['total'] += 1
                    log_data = {k: v[i] for k, v in data_dict.items()}

                    text = (
                        f"Rule: {log_data.get('rule_id', '')} "
                        f"Level: {log_data.get('rule_level', 0)} "
                        f"Action: {log_data.get('fortinet_action', '')} "
                        f"Service: {log_data.get('fortinet_service', '')} "
                        f"Log: {str(log_data.get('full_log', ''))[:300]}"
                    )

                    stages_used = []

                    # Stage 1: Regex 
                    regex_result = self.regex.detect(text)
                    if regex_result['regex_match']:
                        self.stats['regex_hits'] += 1
                        self.stats['threats']    += 1
                        stages_used.append('regex')

                        result = {
                            **log_data,
                            'threat_class'    : regex_result['regex_category'],
                            'confidence'      : regex_result['regex_confidence'],
                            'is_threat'       : 1,
                            'stages_used'     : ' → '.join(stages_used),
                            'detection_method': 'regex_pattern',
                            'model_version'   : 'morpheus_hybrid_dfp_peer_v2',
                        }
                        self.kafka_producer.produce(
                            self.output_topic,
                            value=json.dumps(result)
                        )
                        self.kafka_producer.poll(0)
                        logging.warning(
                            f"REGEX THREAT: {regex_result['regex_category'].upper()}"
                        )
                        continue

                    # Stage 2: BERT 
                    self.stats['bert_processed'] += 1
                    stages_used.append('bert')

                    inputs = self.bert_tokenizer(
                        [text], return_tensors='pt',
                        truncation=True, max_length=256
                    )
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}

                    with torch.no_grad():
                        outputs         = self.bert_model(**inputs)
                        probs           = torch.nn.functional.softmax(outputs.logits, dim=1)
                        pred_class      = torch.argmax(probs, dim=1).item()
                        bert_confidence = torch.max(probs, dim=1).values.item()

                    threat_class      = self.id_to_label[pred_class]
                    final_confidence  = bert_confidence
                    llm_analysis      = None
                    llm_is_suspicious = False

                    # Stage 3: DFP results (written by DFPAnomalyStage)
                    stages_used.append('dfp')

                    dfp_is_anomaly       = int(log_data.get('dfp_is_anomaly', 0))
                    dfp_score            = float(log_data.get('dfp_score', 0.0))
                    dfp_individual_score = float(log_data.get('dfp_individual_score', 0.0))
                    dfp_peer_score       = float(log_data.get('dfp_peer_score', 0.0))
                    dfp_entity           = log_data.get('dfp_entity')
                    dfp_status           = log_data.get('dfp_status', 'unknown')
                    dfp_peer_group_id    = log_data.get('dfp_peer_group_id')
                    dfp_peer_group_size  = int(log_data.get('dfp_peer_group_size', 0))
                    dfp_detection_method = log_data.get('dfp_detection_method', 'none')

                    # Track breakdown of anomaly trigger source
                    if dfp_is_anomaly:
                        if dfp_detection_method == 'individual_and_peer':
                            self.stats['dfp_both_anomaly'] += 1
                        elif dfp_peer_score > dfp_individual_score:
                            self.stats['dfp_peer_anomaly'] += 1
                        else:
                            self.stats['dfp_individual_anomaly'] += 1

                    # Stage 4: LLM (disabled in real-time mode) 
                    llm_analysis      = None
                    llm_is_suspicious = False

                    # Threat determination
                    bert_threat = threat_class is not None and threat_class != 'normal'
                    dfp_threat  = dfp_is_anomaly == 1 and dfp_score > self.dfp_anomaly_threshold
                    is_threat   = bert_threat or dfp_threat

                    if is_threat:
                        self.stats['threats'] += 1

                    # Build and publish result 
                    result = {
                        **log_data,
                        'full_log'            : log_data.get('full_log', ''),
                        '@timestamp'          : log_data.get('@timestamp') or log_data.get('timestamp'),
                        'threat_class'        : threat_class if threat_class else 'unknown',
                        'confidence'          : float(final_confidence),

                        # DFP fields — full breakdown
                        'dfp_is_anomaly'      : dfp_is_anomaly,
                        'dfp_score'           : dfp_score,
                        'dfp_individual_score': dfp_individual_score,
                        'dfp_peer_score'      : dfp_peer_score,
                        'dfp_entity'          : dfp_entity,
                        'dfp_status'          : dfp_status,
                        'dfp_peer_group_id'   : dfp_peer_group_id,
                        'dfp_peer_group_size' : dfp_peer_group_size,
                        'dfp_detection_method': dfp_detection_method,

                        'is_threat'           : int(is_threat),
                        'stages_used'         : ' → '.join(stages_used),
                        'model_version'       : 'morpheus_hybrid_dfp_peer_v2',
                    }

                    if llm_analysis:
                        result['llm_analysis']      = llm_analysis['llm_response']
                        result['llm_is_suspicious'] = int(llm_is_suspicious)
                        result['llm_trigger']       = llm_analysis.get('llm_trigger', 'unknown')

                    try:
                        self.kafka_producer.produce(
                            self.output_topic,
                            value=json.dumps(result, ensure_ascii=False)
                        )
                        self.kafka_producer.poll(0)
                    except Exception as e:
                        logging.error(f"Kafka produce failed: {e}")

                    if is_threat:
                        reasons = []
                        if bert_threat:
                            reasons.append(f"BERT:{threat_class}")
                        if dfp_threat:
                            reasons.append(
                                f"DFP:{dfp_score:.2f}"
                                f"(ind={dfp_individual_score:.2f},"
                                f"peer={dfp_peer_score:.2f},"
                                f"group={dfp_peer_group_id})"
                            )
                        logging.warning(
                            f"THREAT: {' | '.join(reasons)} | "
                            f"method={dfp_detection_method} | "
                            f"conf={final_confidence:.1%}"
                        )

                self.kafka_producer.flush()

                if self.stats['total'] % 100 == 0 and self.stats['total'] > 0:
                    total      = self.stats['total']
                    threat_pct = self.stats['threats'] / total * 100
                    logging.info(
                        f"STATS | Total={total} | "
                        f"Threats={self.stats['threats']} ({threat_pct:.1f}%) | "
                        f"Regex={self.stats['regex_hits']} | "
                        f"BERT={self.stats['bert_processed']} | "
                        f"DFP_ind={self.stats['dfp_individual_anomaly']} | "
                        f"DFP_peer={self.stats['dfp_peer_anomaly']} | "
                        f"DFP_both={self.stats['dfp_both_anomaly']}"
                    )

            except Exception as e:
                logging.error(f"Hybrid stage error: {e}", exc_info=True)

            return message

        node = builder.make_node(self.unique_name, mrc.core.operators.map(hybrid_detection))
        builder.make_edge(input_node, node)
        return node

# PIPELINE BUILDER

def build_pipeline():
    config = Config()
    config.mode                 = "OTHER"
    config.num_threads          = 32
    config.pipeline_batch_size  = 256
    config.model_max_batch_size = 128
    config.edge_buffer_size     = 128

    pipeline = LinearPipeline(config)

    pipeline.set_source(KafkaSourceStage(
        config,
        bootstrap_servers="192.168.19.80:9092",
        input_topic=["sys_logs"],
        group_id="morpheus-hybrid-dfp-peer-production",
        poll_interval="1millis",
        auto_offset_reset="latest"
    ))

    pipeline.add_stage(DeserializeStage(config))
    pipeline.add_stage(DFPAnomalyStage(config))
    pipeline.add_stage(MorpheusHybridStage(config))
    pipeline.add_stage(MonitorStage(config, description="Final Monitoring"))

    return pipeline

# MAIN

if __name__ == "__main__":
    try:
        pipeline = build_pipeline()
        logging.info("\n" + "=" * 70)
        logging.info("Starting Morpheus DFP Peer-Group Pipeline ...")
        logging.info("=" * 70)
        pipeline.run()
    except KeyboardInterrupt:
        logging.info("\nPipeline interrupted by user")
    except Exception as e:
        logging.error(f"Pipeline error: {e}", exc_info=True)
        raise