# LLM Enrichment Setup Guide

This guide covers setting up the LLM enrichment pipeline using Mistral-7B for contextual threat analysis with smart cooldown logic and multi-log attack detection.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Smart Cooldown Logic](#smart-cooldown-logic)
- [Configuration](#configuration)
- [Running the Service](#running-the-service)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Overview

The LLM enrichment pipeline provides:
- **Contextual threat analysis** using Mistral-7B-Instruct
- **Smart cooldown logic** to prevent redundant analysis
- **Multi-log attack detection** for brute force and port scans
- **Confidence scoring** (0-100%) for threat likelihood
- **Reasoning explanation** ("Why is this a threat?")

### When LLM Analysis is Triggered

1. **DFP Anomaly**: High behavioral anomaly score (>0.70)
2. **Multi-log Pattern**: 3+ events from same IP in 2 minutes
3. **New Behavior**: Different connection pattern for same entity

### When LLM Analysis is Skipped

1. **Same Behavior**: Same entity + same behavior within 10 minutes
2. **Low Threshold**: DFP score < 0.70 AND not multi-log pattern
3. **Skipped Threshold**: Already analyzed by BERT with high confidence

## Prerequisites

### Hardware
- **NVIDIA GPU**: 8GB+ VRAM (RTX 3060 or better)
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 20GB for model files

### Software
- Python 3.10+
- CUDA 12.x
- Conda environment
- Kafka running

## Installation

### Step 1: Activate Morpheus Environment
```bash
conda activate morpheus
```

### Step 2: Install LLM Dependencies
```bash
pip install \
    transformers \
    bitsandbytes \
    accelerate \
    sentencepiece \
    protobuf
```

### Step 3: Download Mistral Model

The model downloads automatically on first run (~13GB):
```python
from transformers import AutoTokenizer, AutoModelForCausalLM

# Downloads to ~/.cache/huggingface/
tokenizer = AutoTokenizer.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
```

### Step 4: Copy LLM Enrichment Script
```bash
# Copy script to project
cp scripts/llm/llm_enrichment.py ~/morpheus-threat-detection/scripts/llm/

# Make executable
chmod +x ~/morpheus-threat-detection/scripts/llm/llm_enrichment.py
```

## Smart Cooldown Logic

### How It Works

The smart cooldown prevents redundant LLM calls while still catching multi-log attacks:
```python
# Behavior Signature
signature = f"{srcip}:{dstip}:{dstport}:{action}:{app}"

# Cooldown Per Behavior
if same_signature_within_600_seconds:
    skip_analysis()  # Already analyzed this pattern

# Multi-log Detection Overrides Cooldown
if 3_or_more_events_in_120_seconds:
    analyze_immediately()  # Possible attack pattern
```

### Examples

**Example 1: Normal Repeated Traffic**
```
10:00 - 192.168.1.100 → 8.8.8.8:443 (HTTPS)
  → LLM analyzes

10:05 - 192.168.1.100 → 8.8.8.8:443 (HTTPS)
  → Skipped (same behavior, cooldown)

10:15 - 192.168.1.100 → 8.8.8.8:443 (HTTPS)
  → Analyzed (cooldown expired)
```

**Example 2: Port Scan**
```
10:00 - 192.168.1.100 → target:80
  → LLM analyzes

10:01 - 192.168.1.100 → target:443
  → LLM analyzes (different port = different behavior)

10:02 - 192.168.1.100 → target:22
  → LLM analyzes (3 events = multi-log pattern detected)
  → Context: "Multiple ports from same source"
```

**Example 3: Brute Force**
```
10:00 - 192.168.1.100 → SSH login fail
  → LLM analyzes

10:00:05 - 192.168.1.100 → SSH login fail
  → LLM analyzes (multi-log pattern: 2 events)

10:00:10 - 192.168.1.100 → SSH login fail
  → LLM analyzes (multi-log pattern: 3 events)
  → Context: "Multiple failed attempts"
```

## Configuration

### Edit LLM Enrichment Script
```bash
nano ~/morpheus-threat-detection/scripts/llm/llm_enrichment.py
```

Key configuration options:
```python
# Kafka Configuration
KAFKA_BROKER = "192.168.19.80:9092"
INPUT_TOPIC = "morpheus-final-realtime-dfp"
OUTPUT_TOPIC = "morpheus-llm-enrichment"

# LLM Thresholds
DFP_ANOMALY_THRESHOLD = 0.70        # Analyze if DFP score > 70%
BERT_CONFIDENCE_THRESHOLD = 0.40    # Analyze if BERT confidence < 40%

# Smart Cooldown
COOLDOWN_SECONDS = 600              # 10 minutes same-behavior cooldown
MULTI_LOG_WINDOW = 120              # 2 minutes for multi-log detection

# Model Configuration
MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.2"
QUANTIZATION = "4bit"               # INT4 for memory efficiency
MAX_NEW_TOKENS = 200                # Response length
TEMPERATURE = 0.1                   # Low for consistent analysis
```

### Model Quantization

4-bit quantization reduces memory from 14GB to 4GB:
```python
quantization_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)
```

### Prompt Engineering

The LLM uses this prompt structure:
```python
messages = [
    {
        "role": "user",
        "content": f"""You are a cybersecurity analyst. Analyze this network log and determine if it's a security threat.

{context_note}  # Added for multi-log patterns

Respond ONLY with valid JSON:
{{"is_threat": true/false, "confidence": 0-100, "reason": "Brief explanation"}}

ALERT TYPE: {alert_type}

LOG DATA:
- Source IP: {srcip}
- Destination IP: {dstip}
- Port: {dstport}
- Protocol: {protocol}
- Bytes: {sentbyte}/{rcvdbyte}
"""
    }
]
```

## Running the Service

### Run Manually (Testing)
```bash
# Activate environment
conda activate morpheus

# Run script
cd ~/morpheus-threat-detection/scripts/llm
python llm_enrichment.py
```

Monitor output:
```
Loading Mistral-7B-Instruct-v0.2 with 4-bit quantization...
Mistral-7B loaded with INT4 quantization on GPU
Consuming from: morpheus-final-realtime-dfp
Producing to: morpheus-llm-enrichment
SMART COOLDOWN: Same-behavior = 600s
MULTI-LOG WINDOW: 120s for attack patterns
```

### Create Systemd Service
```bash
sudo nano /etc/systemd/system/morpheus-llm-enricher.service
```
```ini
[Unit]
Description=Morpheus LLM Enrichment Service
After=network.target kafka-docker.service morpheus-pipeline.service

[Service]
Type=simple
User=intern_soc
WorkingDirectory=/home/intern_soc/morpheus-threat-detection/scripts/llm
Environment="PATH=/home/intern_soc/miniconda3/envs/morpheus/bin:/usr/local/cuda/bin"
ExecStart=/home/intern_soc/miniconda3/envs/morpheus/bin/python llm_enrichment.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
MemoryMax=16G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable morpheus-llm-enricher
sudo systemctl start morpheus-llm-enricher

# Monitor
sudo journalctl -u morpheus-llm-enricher -f
```

## Monitoring

### Check Service Status
```bash
# Service status
sudo systemctl status morpheus-llm-enricher

# View logs
sudo journalctl -u morpheus-llm-enricher -f

# Look for:
# "LLM ANALYZED: 192.168.x.x -> Context: multi_log_pattern"
# "STATS | LLM Calls: 45 (2.3%) | Multi-Log: 12 | Threats: 8"
```

### Monitor GPU Usage
```bash
# Watch GPU memory (should be ~4-6GB for Mistral-7B INT4)
watch -n 1 nvidia-smi
```

### Monitor Output to Kafka
```bash
# View enriched logs
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-llm-enrichment \
  | jq 'select(.llm_status == "analyzed")'
```

### Statistics

Pipeline logs stats every 100 messages:
```
STATS | Total: 10000
      | LLM Calls: 234 (2.34%)
      | Multi-Log Patterns: 45
      | Skipped(Cooldown): 8766
      | Threats: 23
```

**Expected LLM call rate**: 1-3% of total logs (smart filtering working)

### Performance Metrics
```bash
# Average time per LLM analysis
sudo journalctl -u morpheus-llm-enricher | grep "LLM ANALYZED" | tail -100

# Typical: 0.5-2 seconds per analysis
```

## Output Format

### Analyzed Log Example
```json
{
  "@timestamp": "2026-02-16T10:30:00.000Z",
  "srcip": "192.168.1.100",
  "dstip": "8.8.8.8",
  "dfp_is_anomaly": 1,
  "dfp_score": 0.85,
  "original_threat_class": "normal",
  
  "llm_status": "analyzed",
  "llm_is_suspicious": 1,
  "llm_confidence": 85,
  "llm_response": "Large amount of data transfer between internal and external IP addresses over SSH protocol which could indicate a potential brute force attack or data exfiltration attempt.",
  "llm_trigger": "dfp_anomaly",
  "llm_context": "multi_log_pattern",
  "enrichment_timestamp": "2026-02-16T10:30:02.123+07:00"
}
```

### Skipped Log Example
```json
{
  "@timestamp": "2026-02-16T10:30:00.000Z",
  "srcip": "192.168.1.100",
  "dstip": "8.8.8.8",
  "dfp_is_anomaly": 0,
  "dfp_score": 0.45,
  
  "llm_status": "skipped_threshold",
  "llm_is_suspicious": 0,
  "enrichment_timestamp": "2026-02-16T10:30:00.456+07:00"
}
```

## Testing

### Test 1: Force LLM Analysis
```bash
# Send high-anomaly test log
TEST_LOG='{"srcip": "192.168.1.100", "dstip": "8.8.8.8", "dfp_is_anomaly": 1, "dfp_score": 0.95, "original_threat_class": "normal"}'

echo $TEST_LOG | docker exec -i kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-final-realtime-dfp

# Wait 5 seconds
sleep 5

# Check output
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-llm-enrichment \
  --max-messages 1 \
  | jq .
```

Should show `llm_status: "analyzed"`

### Test 2: Multi-log Pattern Detection
```bash
# Send 3 logs in quick succession
for i in {1..3}; do
  TEST_LOG='{"srcip": "192.168.1.100", "dstip": "8.8.8.8", "dstport": '$((443+i))', "dfp_is_anomaly": 1, "dfp_score": 0.75}'
  echo $TEST_LOG | docker exec -i kafka kafka-console-producer \
    --bootstrap-server localhost:9092 \
    --topic morpheus-final-realtime-dfp
  sleep 1
done

# Check logs
sudo journalctl -u morpheus-llm-enricher | grep "multi_log_pattern"
```

Should see: `Context: multi_log_pattern`

### Test 3: Cooldown Behavior
```bash
# Send same log twice with 5 second gap
TEST_LOG='{"srcip": "192.168.1.100", "dstip": "8.8.8.8", "dstport": 443, "dfp_is_anomaly": 1, "dfp_score": 0.75}'

# First
echo $TEST_LOG | docker exec -i kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-final-realtime-dfp

sleep 5

# Second (should be skipped)
echo $TEST_LOG | docker exec -i kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-final-realtime-dfp

# Check logs
sudo journalctl -u morpheus-llm-enricher | grep "cooldown"
```

Should see: `Cooldown: cooldown_same_behavior`

## Troubleshooting

### Issue: Out of GPU Memory

**Symptoms**: CUDA out of memory

**Solutions**:
```bash
# 1. Verify 4-bit quantization is enabled
grep "load_in_4bit" llm_enrichment.py

# 2. Reduce max_new_tokens
MAX_NEW_TOKENS = 100  # From 200

# 3. Check other GPU processes
nvidia-smi
sudo kill -9 <other_process_pid>

# 4. Restart service
sudo systemctl restart morpheus-llm-enricher
```

### Issue: Slow LLM Response

**Symptoms**: >5 seconds per analysis

**Solutions**:
```python
# Reduce token length
MAX_NEW_TOKENS = 100

# Increase temperature slightly (faster generation)
TEMPERATURE = 0.2

# Check GPU utilization
watch -n 1 nvidia-smi
```

### Issue: Too Many LLM Calls

**Symptoms**: >10% of logs analyzed

**Solutions**:
```python
# Increase thresholds
DFP_ANOMALY_THRESHOLD = 0.80  # More strict

# Increase cooldown
COOLDOWN_SECONDS = 900  # 15 minutes

# Increase multi-log window
MULTI_LOG_WINDOW = 180  # 3 minutes
```

### Issue: Missing Attack Detection

**Symptoms**: Port scans not detected

**Solutions**:
```python
# Decrease multi-log threshold
# In is_multi_log_attack_pattern():
if event_count >= 2:  # From 3

# Lower cooldown
COOLDOWN_SECONDS = 300  # 5 minutes
```

### Issue: Model Download Fails

**Symptoms**: Connection timeout or 404

**Solutions**:
```bash
# Manually download model
python << EOF
from transformers import AutoTokenizer, AutoModelForCausalLM
tokenizer = AutoTokenizer.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")
print("Model downloaded successfully")
EOF

# Check cache
ls -lh ~/.cache/huggingface/hub/
```

## Optimization

### For Higher Accuracy
```python
# Lower temperature
TEMPERATURE = 0.05  # More deterministic

# Increase max tokens
MAX_NEW_TOKENS = 300  # More detailed analysis

# Lower thresholds
DFP_ANOMALY_THRESHOLD = 0.60  # Analyze more logs
```

### For Higher Throughput
```python
# Increase thresholds
DFP_ANOMALY_THRESHOLD = 0.85  # Fewer analyses

# Reduce max tokens
MAX_NEW_TOKENS = 100  # Faster generation

# Increase cooldown
COOLDOWN_SECONDS = 900  # Less frequent
```

### For Better Attack Detection
```python
# Aggressive multi-log detection
if event_count >= 2:  # Lower threshold

# Shorter window
MULTI_LOG_WINDOW = 60  # 1 minute

# Always analyze high DFP
DFP_ANOMALY_THRESHOLD = 0.50  # Catch more
```

## Best Practices

1. **Monitor GPU**: Keep utilization 40-80% for optimal performance
2. **Tune Thresholds**: Adjust based on false positive/negative rate
3. **Cooldown Balance**: Too short = redundant calls, too long = missed attacks
4. **Multi-log Window**: 2 minutes is ideal for most attack patterns
5. **Model Updates**: Newer models may have better reasoning
6. **Prompt Engineering**: Refine prompts for better threat analysis
7. **Logging**: Keep detailed logs for debugging
8. **Statistics**: Monitor LLM call rate (should be 1-5%)

## Advanced Configuration

### Custom Prompts

Edit the prompt in `llm_analyze()` function:
```python
content = f"""You are a senior SOC analyst with 10 years experience.

CONTEXT: {context_note}
SEVERITY: {"HIGH" if dfp_score > 0.8 else "MEDIUM"}

Analyze if this is a security incident requiring investigation.
Focus on: data exfiltration, lateral movement, reconnaissance.

[... rest of prompt ...]
"""
```

### Multi-Model Setup

Run different models for different threat types:
```python
# Fast model for simple threats
if dfp_score < 0.80:
    model = "mistralai/Mistral-7B-Instruct-v0.2"

# Powerful model for complex threats
else:
    model = "mistralai/Mixtral-8x7B-Instruct-v0.1"
```

### Confidence Calibration

Adjust confidence based on DFP + LLM agreement:
```python
if dfp_is_anomaly and llm_is_suspicious:
    confidence = min(100, llm_confidence * 1.2)  # Boost
elif not dfp_is_anomaly and llm_is_suspicious:
    confidence = llm_confidence * 0.8  # Reduce
```

## Next Steps

- [Wazuh Integration](wazuh-integration.md) - Send enriched logs to SIEM
- [Monitoring Guide](monitoring.md) - Set up dashboards
- [Troubleshooting](troubleshooting.md) - Common issues

## References

- [Mistral AI Documentation](https://docs.mistral.ai/)
- [Transformers Documentation](https://huggingface.co/docs/transformers/)
- [BitsAndBytes Quantization](https://github.com/TimDettmers/bitsandbytes)
