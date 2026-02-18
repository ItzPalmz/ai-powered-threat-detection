# Monitoring Guide - Morpheus DFP Peer Group Anomaly Detection

## Overview

This guide covers monitoring, observability, and operational best practices for the Morpheus pipeline.

---

## Table of Contents

- [Key Metrics to Monitor](#key-metrics-to-monitor)
- [Pipeline Health Checks](#pipeline-health-checks)
- [Performance Monitoring](#performance-monitoring)
- [Kafka Consumer Monitoring](#kafka-consumer-monitoring)
- [DFP Model Monitoring](#dfp-model-monitoring)
- [Peer Group Health](#peer-group-health)
- [Alerting Rules](#alerting-rules)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Dashboard Examples](#dashboard-examples)

---

## Key Metrics to Monitor

### 1. Pipeline Throughput

**Messages Processed Per Second**
```python
# Logged every 100 messages in pipeline
# Look for: "Stats: Total=X, Threats=Y"

Target: 50-100 messages/second
Warning: < 20 messages/second
Critical: < 5 messages/second or stopped
```

**Example Query (if using Prometheus):**
```promql
rate(morpheus_messages_processed_total[1m])
```

### 2. Detection Statistics

**Threat Detection Rate**
```python
# Calculate from logs:
threat_rate = threats_detected / total_messages * 100

Normal: 0.5-5% (depending on network)
Warning: > 10% (possible false positives)
Critical: 0% (detection not working)
```

**Stage-wise Breakdown**
```
Regex hits:     Fast pattern matching
BERT processed: ML classification
DFP anomalies:  Behavioral detection
  - Individual: Entity vs own history
  - Peer:       Entity vs peer group
LLM calls:      Deep reasoning (if enabled)
```

### 3. Latency Metrics

**End-to-End Latency**
```
Firewall → Kafka: < 1 second
Kafka → Morpheus: < 100ms
Morpheus Processing: 50-200ms per message
Morpheus → Kafka Output: < 50ms
Output → Wazuh: 1-30 seconds (OpenSearch refresh)
Output → Discord: < 500ms
```

**Critical Path:**
```
Total: Firewall event → Discord alert = 1-3 seconds
Total: Firewall event → Wazuh indexed = 5-30 seconds
```

---

## Pipeline Health Checks

### Manual Health Check Script

```bash
#!/bin/bash
# pipeline_health_check.sh

echo "=== Morpheus Pipeline Health Check ==="
echo ""

# 1. Check Kafka topics exist
echo "1. Kafka Topics:"
docker exec kafka /usr/bin/kafka-topics \
  --bootstrap-server 192.168.19.80:9092 \
  --list | grep -E "sys_logs|morpheus-final-realtime-dfp"
echo ""

# 2. Check consumer groups
echo "2. Consumer Groups:"
docker exec kafka /usr/bin/kafka-consumer-groups \
  --bootstrap-server 192.168.19.80:9092 \
  --list | grep morpheus
echo ""

# 3. Check consumer lag
echo "3. Consumer Lag:"
docker exec kafka /usr/bin/kafka-consumer-groups \
  --bootstrap-server 192.168.19.80:9092 \
  --group morpheus-hybrid-dfp-production \
  --describe 2>/dev/null | grep -E "TOPIC|sys_logs"
echo ""

# 4. Check GPU utilization
echo "4. GPU Status:"
nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total \
  --format=csv,noheader
echo ""

# 5. Check Morpheus process
echo "5. Morpheus Process:"
ps aux | grep morpheus_hybrid_pipeline | grep -v grep | \
  awk '{print "PID:", $2, "CPU:", $3"%", "MEM:", $4"%"}'
echo ""

# 6. Check recent output
echo "6. Recent Output Messages:"
timeout 3 docker exec kafka /usr/bin/kafka-console-consumer \
  --bootstrap-server 192.168.19.80:9092 \
  --topic morpheus-final-realtime-dfp \
  --from-beginning --max-messages 1 2>/dev/null | \
  jq -r '{timestamp: .["@timestamp"], threat: .is_threat, class: .threat_class}'
echo ""

echo "=== Health Check Complete ==="
```

### Automated Health Monitoring

```python
#!/usr/bin/env python3
# health_monitor.py - Run continuously to monitor pipeline health

import time
import subprocess
import json
import requests
from datetime import datetime

class PipelineHealthMonitor:
    def __init__(self):
        self.kafka_server = "192.168.19.80:9092"
        self.alert_webhook = "YOUR_DISCORD_WEBHOOK_URL"
        
    def check_consumer_lag(self):
        """Check Kafka consumer lag"""
        cmd = [
            "docker", "exec", "kafka",
            "/usr/bin/kafka-consumer-groups",
            "--bootstrap-server", self.kafka_server,
            "--group", "morpheus-hybrid-dfp-production",
            "--describe"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if 'sys_logs' in line:
                parts = line.split()
                if len(parts) >= 6:
                    lag = int(parts[5])
                    return lag
        return None
    
    def check_gpu_health(self):
        """Check GPU temperature and utilization"""
        cmd = [
            "nvidia-smi",
            "--query-gpu=temperature.gpu,utilization.gpu,memory.used",
            "--format=csv,noheader,nounits"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        temp, util, mem = result.stdout.strip().split(', ')
        
        return {
            'temperature': int(temp),
            'utilization': int(util),
            'memory_mb': int(mem)
        }
    
    def check_message_flow(self):
        """Check if messages are flowing"""
        cmd = [
            "timeout", "5",
            "docker", "exec", "kafka",
            "/usr/bin/kafka-console-consumer",
            "--bootstrap-server", self.kafka_server,
            "--topic", "morpheus-final-realtime-dfp",
            "--from-beginning", "--max-messages", "1"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                return True, data.get('@timestamp')
            except:
                return False, None
        return False, None
    
    def send_alert(self, message, severity="warning"):
        """Send alert to Discord"""
        color = {"critical": 0xFF0000, "warning": 0xFFA500, "info": 0x0099FF}
        
        payload = {
            "embeds": [{
                "title": f"🚨 Pipeline Alert ({severity.upper()})",
                "description": message,
                "color": color.get(severity, 0xFFA500),
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        try:
            requests.post(self.alert_webhook, json=payload)
        except Exception as e:
            print(f"Failed to send alert: {e}")
    
    def run(self):
        """Main monitoring loop"""
        print("Starting Pipeline Health Monitor...")
        
        last_alert_time = {}
        alert_cooldown = 300  # 5 minutes between same alerts
        
        while True:
            try:
                # Check consumer lag
                lag = self.check_consumer_lag()
                if lag is not None:
                    if lag > 1000:
                        if time.time() - last_alert_time.get('lag', 0) > alert_cooldown:
                            self.send_alert(
                                f"High consumer lag detected: {lag} messages behind",
                                "critical"
                            )
                            last_alert_time['lag'] = time.time()
                    print(f"[{datetime.now()}] Consumer lag: {lag}")
                
                # Check GPU health
                gpu = self.check_gpu_health()
                if gpu['temperature'] > 85:
                    if time.time() - last_alert_time.get('gpu_temp', 0) > alert_cooldown:
                        self.send_alert(
                            f"High GPU temperature: {gpu['temperature']}°C",
                            "warning"
                        )
                        last_alert_time['gpu_temp'] = time.time()
                print(f"[{datetime.now()}] GPU: {gpu['temperature']}°C, {gpu['utilization']}% util")
                
                # Check message flow
                flowing, last_msg_time = self.check_message_flow()
                if not flowing:
                    if time.time() - last_alert_time.get('flow', 0) > alert_cooldown:
                        self.send_alert(
                            "No messages flowing in output topic!",
                            "critical"
                        )
                        last_alert_time['flow'] = time.time()
                else:
                    print(f"[{datetime.now()}] Messages flowing ✓ (last: {last_msg_time})")
                
                time.sleep(60)  # Check every minute
                
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(10)

if __name__ == "__main__":
    monitor = PipelineHealthMonitor()
    monitor.run()
```

---

## Performance Monitoring

### GPU Monitoring

**NVIDIA-SMI Watch**
```bash
# Real-time GPU monitoring
watch -n 1 nvidia-smi

# Key metrics:
# - Temperature: Should stay < 85°C
# - GPU Util: 50-80% during active processing
# - Memory: Track for memory leaks
```

**GPU Memory Profiling**
```python
# Add to pipeline for memory tracking
import torch

def log_gpu_memory():
    if torch.cuda.is_available():
        allocated = torch.cuda.memory_allocated() / 1024**3
        cached = torch.cuda.memory_reserved() / 1024**3
        logging.info(f"GPU Memory: {allocated:.2f}GB allocated, {cached:.2f}GB cached")

# Call every 1000 messages
if self.stats['total'] % 1000 == 0:
    log_gpu_memory()
```

### Pipeline Processing Rate

**Track Messages/Second**
```python
# Add to your pipeline
import time

class PerformanceTracker:
    def __init__(self):
        self.start_time = time.time()
        self.message_count = 0
        self.checkpoint_time = time.time()
        self.checkpoint_count = 0
    
    def record_message(self):
        self.message_count += 1
        
        # Report every 100 messages
        if self.message_count % 100 == 0:
            now = time.time()
            elapsed = now - self.checkpoint_time
            interval_msgs = self.message_count - self.checkpoint_count
            
            rate = interval_msgs / elapsed if elapsed > 0 else 0
            avg_rate = self.message_count / (now - self.start_time)
            
            logging.info(
                f"Performance: {rate:.1f} msg/s (current), "
                f"{avg_rate:.1f} msg/s (average)"
            )
            
            self.checkpoint_time = now
            self.checkpoint_count = self.message_count
```

---

## Kafka Consumer Monitoring

### Consumer Lag Monitoring

**Continuous Lag Monitoring Script**
```bash
#!/bin/bash
# monitor_consumer_lag.sh

while true; do
    clear
    echo "=== Kafka Consumer Lag Monitor ==="
    echo "Time: $(date)"
    echo ""
    
    docker exec kafka /usr/bin/kafka-consumer-groups \
      --bootstrap-server 192.168.19.80:9092 \
      --group morpheus-hybrid-dfp-production \
      --describe | grep -E "GROUP|sys_logs|morpheus-final"
    
    echo ""
    echo "Press Ctrl+C to stop"
    sleep 5
done
```

### Consumer Group Health Metrics

```bash
# Export to Prometheus format
cat > /var/lib/node_exporter/textfile_collector/kafka_lag.prom << EOF
# HELP kafka_consumer_lag Kafka consumer group lag
# TYPE kafka_consumer_lag gauge
kafka_consumer_lag{group="morpheus-hybrid-dfp-production",topic="sys_logs"} $(GET_LAG_VALUE)
EOF
```

---

## DFP Model Monitoring

### DFP Statistics Dashboard

**Key Metrics from Pipeline Logs**
```python
# Logged every 100 messages:
DFP STATUS: 
  Messages_Processed=10000
  Entities=450/1000           # Entity profiles created
  Trained=425                 # Models trained
  Anomalies=127              # Total anomalies detected
  PeerGroups=35              # Active peer groups
  PeerGroupRuns=45           # Times peer grouping ran
  PeerAnomalies=89           # Anomalies detected via peer comparison
```

### Model Performance Tracking

```python
# Add to DFPAnomalyStage
class DFPMetrics:
    def __init__(self):
        self.training_times = []
        self.detection_times = []
        self.reconstruction_errors = []
    
    def record_training(self, duration_seconds):
        self.training_times.append(duration_seconds)
        
        if len(self.training_times) % 10 == 0:
            avg = sum(self.training_times[-10:]) / 10
            logging.info(f"DFP Training: avg {avg:.3f}s per model (last 10)")
    
    def record_detection(self, duration_ms, reconstruction_error):
        self.detection_times.append(duration_ms)
        self.reconstruction_errors.append(reconstruction_error)
        
        if len(self.detection_times) % 1000 == 0:
            avg_time = sum(self.detection_times[-1000:]) / 1000
            avg_error = sum(self.reconstruction_errors[-1000:]) / 1000
            logging.info(
                f"DFP Detection: avg {avg_time:.2f}ms per message, "
                f"avg reconstruction error: {avg_error:.4f}"
            )
```

---

## Peer Group Health

### Peer Group Metrics

**Monitor Peer Group Quality**
```python
# Add to peer group update logging
def log_peer_group_quality(self):
    """Log peer group health metrics"""
    
    group_sizes = [len(g.entity_ids) for g in self.peer_groups.values()]
    
    metrics = {
        'total_groups': len(self.peer_groups),
        'avg_group_size': np.mean(group_sizes) if group_sizes else 0,
        'min_group_size': min(group_sizes) if group_sizes else 0,
        'max_group_size': max(group_sizes) if group_sizes else 0,
        'singleton_groups': sum(1 for s in group_sizes if s == 1),
        'healthy_groups': sum(1 for s in group_sizes if s >= self.min_peer_group_size)
    }
    
    logging.info(f"Peer Group Health: {json.dumps(metrics)}")
    
    # Alert if too many singleton groups (poor clustering)
    if metrics['singleton_groups'] > metrics['total_groups'] * 0.3:
        logging.warning(
            f"High singleton ratio: {metrics['singleton_groups']}/{metrics['total_groups']} "
            f"- consider adjusting clustering parameters"
        )
```

### Peer Score Distribution

```python
# Track peer scores to detect drift
class PeerScoreTracker:
    def __init__(self):
        self.scores = deque(maxlen=10000)
    
    def record(self, score):
        self.scores.append(score)
        
        if len(self.scores) % 1000 == 0:
            scores_array = np.array(self.scores)
            logging.info(
                f"Peer Scores: "
                f"mean={np.mean(scores_array):.3f}, "
                f"std={np.std(scores_array):.3f}, "
                f"p95={np.percentile(scores_array, 95):.3f}"
            )
```

---

## Alerting Rules

### Critical Alerts

```yaml
# Example Prometheus alerting rules
groups:
  - name: morpheus_pipeline_critical
    interval: 30s
    rules:
      - alert: PipelineDown
        expr: up{job="morpheus-pipeline"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Morpheus pipeline is down"
          description: "Pipeline has been down for 2 minutes"
      
      - alert: HighConsumerLag
        expr: kafka_consumer_lag{group="morpheus-hybrid-dfp-production"} > 1000
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High Kafka consumer lag"
          description: "Consumer lag is {{ $value }} messages"
      
      - alert: GPUOverheating
        expr: nvidia_gpu_temperature_celsius > 85
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "GPU overheating"
          description: "GPU temperature is {{ $value }}°C"
      
      - alert: NoMessagesProcessed
        expr: rate(morpheus_messages_processed_total[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No messages being processed"
          description: "Pipeline has not processed any messages in 5 minutes"
```

### Warning Alerts

```yaml
  - name: morpheus_pipeline_warning
    interval: 60s
    rules:
      - alert: HighDFPAnomalyRate
        expr: rate(morpheus_dfp_anomalies_total[10m]) / rate(morpheus_messages_total[10m]) > 0.15
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High DFP anomaly rate"
          description: "{{ $value | humanizePercentage }} of messages flagged as anomalies"
      
      - alert: SlowProcessing
        expr: rate(morpheus_messages_processed_total[5m]) < 20
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Slow message processing"
          description: "Processing rate is {{ $value }} msg/s"
      
      - alert: PeerGroupingFailing
        expr: morpheus_peer_groups_created == 0
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Peer grouping not working"
          description: "No peer groups have been created in 30 minutes"
```

---

## Troubleshooting Guide

### Common Issues & Solutions

#### Issue 1: Pipeline Stopped Processing

**Symptoms:**
- No log output
- Consumer lag growing
- No threats in Discord/Wazuh

**Diagnosis:**
```bash
# Check if process is running
ps aux | grep morpheus_hybrid_pipeline

# Check last log entries
tail -100 morpheus_pipeline.log

# Check for Python errors
grep -i "error\|exception\|traceback" morpheus_pipeline.log | tail -20
```

**Solution:**
```bash
# Restart pipeline
screen -r morpheus
# Ctrl+C, then:
python3 morpheus_hybrid_pipeline.py
```

#### Issue 2: High Consumer Lag

**Symptoms:**
- LAG > 1000
- Discord alerts delayed
- Wazuh logs very delayed

**Diagnosis:**
```bash
# Check current lag
./check_consumer_lag.sh

# Check GPU utilization
nvidia-smi

# Check system resources
top
```

**Solutions:**
1. Scale consumer (add more instances)
2. Optimize OpenSearch indexing
3. Increase batch sizes
4. Check for bottlenecks (GPU, CPU, network)

#### Issue 3: DFP Models Not Training

**Symptoms:**
- `dfp_status` always "training"
- `Trained_Models=0` in logs
- No anomalies detected

**Diagnosis:**
```bash
# Check logs for training messages
grep "DFP TRAINING" morpheus_pipeline.log | tail -20

# Check entity count
grep "DFP STATUS" morpheus_pipeline.log | tail -1
```

**Solutions:**
- Wait for entities to accumulate 15+ messages
- Check `training_samples` parameter (default: 15)
- Verify GPU is available: `nvidia-smi`
- Check for CUDA errors in logs

#### Issue 4: Peer Groups Not Creating

**Symptoms:**
- `PeerGroups=0` in logs
- `dfp_peer_score` always 0
- `dfp_detection_method` always "individual_only"

**Diagnosis:**
```bash
# Check peer grouping runs
grep "Peer groups updated" morpheus_pipeline.log | tail -5

# Check entity count
grep "eligible entities" morpheus_pipeline.log | tail -1
```

**Solutions:**
- Wait for at least 3 entities with trained models
- Check `min_peer_group_size` parameter (default: 3)
- Increase `peer_group_update_interval` if too frequent
- Verify scikit-learn is installed

---

## Summary

### Daily Monitoring Checklist

-  Check consumer lag (`< 100`)
-  Verify GPU temperature (`< 80°C`)
-  Review threat detection rate (`0.5-5%`)
-  Check peer group count (`> 0`)
-  Verify messages flowing in all topics
-  Review error logs

### Weekly Maintenance

-  Analyze DFP model performance trends
-  Review peer group quality metrics
-  Check disk space (Kafka logs, pipeline logs)
-  Update detection thresholds if needed
-  Review false positive/negative rates
-  Backup Kafka topic configurations

### Monthly Review

-  Evaluate overall system performance
-  Optimize consumer group settings
-  Review and update alerting rules
-  Plan for capacity scaling
-  Update documentation
-  Review security incidents detected

---
