# Morpheus Pipeline Setup Guide

This guide covers setting up the NVIDIA Morpheus threat detection pipeline with GPU acceleration, DFP behavioral analysis, and multi-stage detection.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Pipeline Components](#pipeline-components)
- [Configuration](#configuration)
- [Running the Pipeline](#running-the-pipeline)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Hardware Requirements
- **NVIDIA GPU**: RTX 3060 or better (minimum 8GB VRAM)
- **CPU**: 16+ cores recommended
- **RAM**: 32GB minimum, 64GB recommended
- **Storage**: 100GB+ SSD for models and logs

### Software Requirements
- Ubuntu 24.04 LTS
- NVIDIA Driver 550+
- CUDA 12.x
- Docker (for Kafka)
- Conda/Miniconda

### Check GPU
```bash
# Verify GPU is detected
nvidia-smi

# Should show your GPU model and CUDA version
```

## Installation

### Step 1: Install CUDA and cuDNN
```bash
# Install CUDA toolkit
wget https://developer.download.nvidia.com/compute/cuda/12.3.0/local_installers/cuda_12.3.0_545.23.06_linux.run
sudo sh cuda_12.3.0_545.23.06_linux.run

# Add to PATH
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Verify
nvcc --version
```

### Step 2: Install Conda
```bash
# Download Miniconda
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh

# Install
bash Miniconda3-latest-Linux-x86_64.sh

# Activate
source ~/.bashrc
```

### Step 3: Create Morpheus Environment
```bash
# Create conda environment
conda create -n morpheus python=3.10 -y
conda activate morpheus

# Install PyTorch with CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Install Morpheus dependencies
pip install \
    cudf-cu12 \
    cuml-cu12 \
    cupy-cuda12x \
    transformers \
    bitsandbytes \
    confluent-kafka \
    pandas \
    numpy \
    scikit-learn
```

### Step 4: Install NVIDIA Morpheus
```bash
# Clone Morpheus repository
git clone https://github.com/nv-morpheus/Morpheus.git
cd Morpheus

# Install Morpheus
pip install -e .

# Verify installation
python -c "import morpheus; print(morpheus.__version__)"
```

### Step 5: Download Models
```bash
# Create model directory
mkdir -p ~/models

# Download DistilBERT model (already trained)
# Copy your trained model to ~/models/bert_fortinet_trained

# Mistral model will download automatically on first run
```

## Pipeline Components

### 1. Regex Detector
Fast pattern matching for known attack signatures:
- SQL Injection
- XSS Attacks
- Command Injection
- Brute Force patterns
- Malware signatures
- Port Scan indicators

### 2. DistilBERT Classifier
ML-based threat classification:
- Pre-trained on FortiGate logs
- Multi-class threat detection
- GPU-accelerated inference
- Confidence scoring

### 3. DFP (Digital Fingerprinting)
Behavioral anomaly detection:
- Per-entity (srcip) autoencoder models
- Learns normal traffic patterns
- Detects behavioral deviations
- Port scan detection via entropy
- GPU-accelerated training

### 4. Document ID Generation
Ensures no duplicates in Wazuh:
- MD5 hash of (srcip + dstip + timestamp + srcport)
- Same log = same ID = update, not duplicate
- Enables LLM enrichment without duplication

## Configuration

### Pipeline Configuration

Edit `morpheus_pipeline.py`:
```python
# Kafka Configuration
KAFKA_BROKER = "192.168.19.80:9092"
INPUT_TOPIC = "sys_logs"
OUTPUT_TOPIC = "morpheus-final-realtime-dfp"

# DFP Configuration
DFP_ENABLED = True
DFP_ANOMALY_THRESHOLD = 0.70  # 70th percentile
TRAINING_SAMPLES = 5           # Faster training
MAX_ENTITIES = 1000            # Limit memory usage

# Model Paths
BERT_MODEL_PATH = "/home/intern_soc/models/bert_fortinet_trained"

# Performance
PIPELINE_BATCH_SIZE = 256
MODEL_MAX_BATCH_SIZE = 128
NUM_THREADS = 32
```

### DFP Features

The pipeline extracts these features for behavioral analysis:

**Traffic Metrics**:
- Bytes sent/received
- Packets sent/received
- Duration
- Bytes per packet
- Traffic ratios

**Port Features**:
- Source/destination ports
- Port entropy (scan detection)
- Common vs suspicious ports

**Protocol Features**:
- TCP/UDP/ICMP indicators
- Application IDs

**Temporal Features**:
- Hour of day
- Day of week
- Business hours indicator
- Night traffic indicator

**Network Topology**:
- Internal vs external traffic
- Source/destination classification

### Detection Thresholds
```python
# DFP Thresholds
DFP_ANOMALY_THRESHOLD = 0.70        # Anomaly score threshold
TRAINING_SAMPLES = 5                # Min samples before training
ANOMALY_PERCENTILE = 0.70          # Reconstruction error percentile

# Port Scan Detection
PORT_ENTROPY_THRESHOLD = 4          # Unique ports = likely scan
PORT_SCAN_WINDOW = 20              # Last N connections

# Entity Management
MAX_ENTITIES = 1000                 # Prevent memory exhaustion
MIN_MESSAGES_FOR_TRAINING = 5      # Min msgs before profiling
```

## Running the Pipeline

### Start Pipeline
```bash
# Activate environment
conda activate morpheus

# Navigate to pipeline directory
cd ~/morpheus-threat-detection/scripts/morpheus

# Run pipeline
python morpheus_pipeline.py
```

### Run as Background Service

Create systemd service:
```bash
sudo nano /etc/systemd/system/morpheus-pipeline.service
```
```ini
[Unit]
Description=Morpheus Threat Detection Pipeline
After=network.target kafka-docker.service

[Service]
Type=simple
User=intern_soc
WorkingDirectory=/home/intern_soc/morpheus-threat-detection/scripts/morpheus
Environment="PATH=/home/intern_soc/miniconda3/envs/morpheus/bin:/usr/local/cuda/bin"
ExecStart=/home/intern_soc/miniconda3/envs/morpheus/bin/python morpheus_pipeline.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable morpheus-pipeline
sudo systemctl start morpheus-pipeline

# Monitor logs
sudo journalctl -u morpheus-pipeline -f
```

## Monitoring

### Check Pipeline Status
```bash
# View logs
sudo journalctl -u morpheus-pipeline -f

# Look for:
# "Starting Morpheus Pipeline..."
# "DFP Anomaly Detection Initialized"
# "BERT loaded on GPU"
# "Pipeline started"
```

### Monitor GPU Usage
```bash
# Watch GPU utilization
watch -n 1 nvidia-smi

# Should show:
# - GPU memory usage (~4-6GB)
# - GPU utilization (40-80%)
```

### Monitor Output to Kafka
```bash
# Watch output messages
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-final-realtime-dfp

# Check message count
docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic morpheus-final-realtime-dfp
```

### DFP Statistics

Pipeline logs DFP stats every 100 messages:
```
DFP STATUS: 
  Messages_Processed=1000
  Total_Entities=45/1000
  Trained_Models=23
  Anomalies_Detected=8
```

### Performance Metrics
```bash
# Check pipeline throughput
# Look in logs for:
# "Stats: Total=10000, Threats=150 (1.5%), DFP_Anomaly=45"
```

Expected performance:
- **Throughput**: 1,000-5,000 logs/second
- **Latency**: 100-500ms per log
- **GPU Memory**: 4-6GB
- **CPU Usage**: 40-60%

## Testing

### Test 1: Send Test Log
```bash
# Create test log
TEST_LOG='{"srcip": "192.168.1.100", "dstip": "8.8.8.8", "srcport": 12345, "dstport": 443, "proto": 6, "action": "accept", "sentbyte": 5000, "rcvdbyte": 3000, "duration": 10}'

# Send to Kafka input topic
echo $TEST_LOG | docker exec -i kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs

# Wait 2 seconds
sleep 2

# Check output
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic morpheus-final-realtime-dfp \
  --max-messages 1
```

### Test 2: Simulate Port Scan
```bash
# Run nmap from another machine
nmap -A -T4 192.168.19.80

# Monitor DFP detection
sudo journalctl -u morpheus-pipeline -f | grep -i "PORT SCAN\|ANOMALY"
```

Should see: `PORT SCAN DETECTED: 192.168.x.x`

### Test 3: Verify DFP Training
```bash
# Generate traffic from single IP
for i in {1..10}; do
  curl -s http://192.168.19.80 > /dev/null
  sleep 1
done

# Check logs for training
sudo journalctl -u morpheus-pipeline | grep "DFP TRAINING"

# Should show:
# "⏱️  DFP TRAINING: Entity=192.168.x.x, Samples=10, Time=0.234s"
```

## Optimization

### For High Volume
```python
# Increase batch sizes
PIPELINE_BATCH_SIZE = 512
MODEL_MAX_BATCH_SIZE = 256

# Increase workers
NUM_THREADS = 64

# Reduce DFP overhead
TRAINING_SAMPLES = 10  # Train less frequently
MAX_ENTITIES = 500      # Limit entities
```

### For Low Latency
```python
# Reduce batch sizes
PIPELINE_BATCH_SIZE = 64
MODEL_MAX_BATCH_SIZE = 32

# Increase DFP sensitivity
DFP_ANOMALY_THRESHOLD = 0.60  # Catch more anomalies
TRAINING_SAMPLES = 3           # Train faster
```

### GPU Memory Optimization
```python
# Use smaller batch sizes
MODEL_MAX_BATCH_SIZE = 64

# Disable gradient computation (already done)
torch.no_grad()

# Clear GPU cache periodically
torch.cuda.empty_cache()
```

## Troubleshooting

### Issue: GPU Out of Memory

**Symptoms**: CUDA out of memory error

**Solution**:
```bash
# Reduce batch size in config
MODEL_MAX_BATCH_SIZE = 32

# Check GPU memory
nvidia-smi

# Kill other GPU processes
sudo kill -9 <PID>
```

### Issue: Pipeline Not Starting

**Check**:
```bash
# View full error
sudo journalctl -u morpheus-pipeline -n 100 --no-pager

# Common causes:
# 1. Kafka not running
# 2. CUDA not available
# 3. Model files missing
```

**Solutions**:
```bash
# Start Kafka
~/kafka-setup/kafka-manager.sh start

# Verify CUDA
python -c "import torch; print(torch.cuda.is_available())"

# Check model path
ls -la ~/models/bert_fortinet_trained/
```

### Issue: No Output to Kafka

**Check**:
```bash
# 1. Is pipeline consuming input?
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe \
  --group morpheus-hybrid-dfp-peer-production

# 2. Check for errors
sudo journalctl -u morpheus-pipeline | grep -i error

# 3. Verify output topic exists
docker exec kafka kafka-topics --list --bootstrap-server localhost:9092
```

### Issue: DFP Not Training

**Symptoms**: All logs show `dfp_status: training`

**Check**:
```bash
# View DFP logs
sudo journalctl -u morpheus-pipeline | grep "DFP"

# Look for:
# - "Created profile for entity X"
# - "DFP TRAINING: Entity=X"
```

**Common cause**: Not enough samples yet (need 5 per entity)

### Issue: High False Positives

**Solution**:
```python
# Increase DFP threshold
DFP_ANOMALY_THRESHOLD = 0.80  # More strict

# Increase training samples
TRAINING_SAMPLES = 10  # Better baseline
```

### Issue: Missing Detections

**Solution**:
```python
# Lower DFP threshold
DFP_ANOMALY_THRESHOLD = 0.60  # More sensitive

# Lower port scan threshold
PORT_SCAN_UNIQUE_PORTS = 3  # Detect smaller scans
```

## Performance Tuning

### CPU Optimization
```bash
# Check CPU usage
top -u intern_soc

# Adjust workers
NUM_THREADS = $(nproc)  # Match CPU cores
```

### Kafka Optimization
```python
# Increase consumer performance
KAFKA_FETCH_MIN_BYTES = 1024
KAFKA_FETCH_WAIT_MAX_MS = 100
```

### Memory Management
```python
# Limit entity cache size
MAX_ENTITIES = 500

# Clear old profiles periodically
if len(entity_profiles) > MAX_ENTITIES:
    # Evict least active entities
    evict_least_active_entities()
```

## Best Practices

1. **GPU Monitoring**: Always monitor GPU memory and utilization
2. **DFP Tuning**: Adjust thresholds based on your network baseline
3. **Batch Sizes**: Balance throughput vs latency
4. **Entity Limits**: Prevent memory exhaustion in large networks
5. **Model Updates**: Retrain DistilBERT periodically with new attack samples
6. **Logging**: Keep detailed logs for debugging
7. **Backup**: Version control pipeline configuration
8. **Testing**: Test with known attack patterns before production

## Model Training (Optional)

### Retrain DistilBERT
```bash
# Prepare training data
python scripts/prepare_training_data.py

# Train model
python scripts/train_bert_model.py \
  --train_data data/training.csv \
  --epochs 10 \
  --batch_size 32 \
  --output models/bert_fortinet_updated

# Replace model
mv models/bert_fortinet_trained models/bert_fortinet_backup
mv models/bert_fortinet_updated models/bert_fortinet_trained

# Restart pipeline
sudo systemctl restart morpheus-pipeline
```

## References

- [NVIDIA Morpheus Documentation](https://docs.nvidia.com/morpheus/)
- [PyTorch CUDA Guide](https://pytorch.org/docs/stable/cuda.html)
- [Transformers Documentation](https://huggingface.co/docs/transformers/)