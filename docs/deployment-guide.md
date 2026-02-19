# Deployment Guide
# Deployment Guide

Complete step-by-step guide for deploying the Morpheus AI Threat Detection System from scratch.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Phase 1: System Preparation](#phase-1-system-preparation)
- [Phase 2: Infrastructure Setup](#phase-2-infrastructure-setup)
- [Phase 3: Pipeline Deployment](#phase-3-pipeline-deployment)
- [Phase 4: Integration & Testing](#phase-4-integration--testing)
- [Phase 5: Production Cutover](#phase-5-production-cutover)
- [Post-Deployment](#post-deployment)
- [Rollback Procedures](#rollback-procedures)

## Overview

This guide walks you through a complete production deployment of the Morpheus threat detection system. Estimated time: 4-6 hours for experienced administrators.

### Deployment Phases
```
Phase 1: System Preparation (30 min)
  └─ OS install, updates, drivers

Phase 2: Infrastructure Setup (60 min)
  └─ Kafka, Logstash, Wazuh

Phase 3: Pipeline Deployment (90 min)
  └─ Morpheus, LLM, Indexers

Phase 4: Integration & Testing (60 min)
  └─ FortiGate, Discord, Testing

Phase 5: Production Cutover (30 min)
  └─ Enable auto-start, monitoring

Total: 4.5 hours minimum
```

## Prerequisites

### Hardware Requirements

**Minimum (Development/Testing)**:
- CPU: 16 cores
- RAM: 32GB
- GPU: NVIDIA RTX 3060 (8GB VRAM)
- Storage: 250GB SSD
- Network: 1Gbps

**Recommended (Production)**:
- CPU: 32+ cores
- RAM: 64GB+
- GPU: NVIDIA RTX 4090 (24GB VRAM)
- Storage: 500GB NVMe SSD
- Network: 10Gbps

**Storage Breakdown**:
```
OS & System:          50GB
Docker Volumes:       100GB
Kafka Data:           50GB
OpenSearch Data:      150GB
Models & Logs:        50GB
Reserved:             100GB
─────────────────────────
Total:                500GB
```

### Software Requirements

- Ubuntu 24.04 LTS (fresh install)
- NVIDIA Driver 550+
- CUDA Toolkit 12.3+
- Docker 24.0+
- Docker Compose 2.0+
- Python 3.10+
- Git

### Network Requirements

- Static IP address
- Firewall access to FortiGate
- Outbound HTTPS (for Discord, model downloads)
- Internal network access (Kafka, OpenSearch)

### Access Requirements

- Root/sudo access
- GitHub account (for code repository)
- Discord webhook URL (for alerts)
- FortiGate admin access
- Email server details (optional)

## Pre-Deployment Checklist

### Planning

- [ ] Hardware procured and racked
- [ ] Network configuration planned
- [ ] IP address allocated: `192.168.19.80`
- [ ] DNS entry created (optional)
- [ ] Firewall rules documented
- [ ] Backup strategy defined
- [ ] Monitoring plan created
- [ ] Team trained on system

### Information Gathering
```bash
# Record this information before starting

# Network
SERVER_IP="192.168.19.80"
FORTIGATE_IP="192.168.x.x"
GATEWAY="192.168.x.1"
NETMASK="255.255.255.0"

# Credentials
WAZUH_ADMIN_PASSWORD="<generate-strong-password>"
OPENSEARCH_PASSWORD="<generate-strong-password>"
DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Email (optional)
SMTP_SERVER="smtp.gmail.com"
SMTP_PORT="587"
EMAIL_FROM="security@company.com"
EMAIL_TO="soc-team@company.com"
```


## Phase 1: Infrastructure Setup

### Step 1.1: Install Wazuh
```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Update
sudo apt update

# Install Wazuh indexer (OpenSearch)
sudo apt install -y wazuh-indexer

# Configure OpenSearch
sudo nano /etc/wazuh-indexer/opensearch.yml

# Update:
# network.host: 0.0.0.0
# node.name: node-1
# cluster.initial_master_nodes: ["node-1"]

# Start indexer
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer

# Wait for startup
sleep 30

# Initialize security
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh

# Install Wazuh Manager
sudo apt install -y wazuh-manager

# Start manager
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Install Wazuh Dashboard
sudo apt install -y wazuh-dashboard

# Configure dashboard
sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml

# Update:
# server.host: 0.0.0.0
# opensearch.hosts: ["https://localhost:9200"]

# Start dashboard
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard

# Get admin password
sudo tar -xvf wazuh-install-files.tar
cat wazuh-install-files/wazuh-passwords.txt | grep "admin"

# Save password for later
WAZUH_ADMIN_PASSWORD="<password-from-above>"
```

### Step 1.2: Deploy Kafka
```bash
# Create Kafka directory
mkdir -p ~/kafka-setup
cd ~/kafka-setup

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    container_name: zookeeper
    hostname: zookeeper
    ports:
      - "2181:2181"
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
      ZOOKEEPER_SYNC_LIMIT: 2
    volumes:
      - zookeeper-data:/var/lib/zookeeper/data
      - zookeeper-logs:/var/lib/zookeeper/log
    restart: unless-stopped
    networks:
      - kafka-network

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    container_name: kafka
    hostname: kafka
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://192.168.19.80:9092
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
      KAFKA_LOG_RETENTION_HOURS: 168
      KAFKA_LOG_SEGMENT_BYTES: 1073741824
      KAFKA_NUM_PARTITIONS: 3
    volumes:
      - kafka-data:/var/lib/kafka/data
    restart: unless-stopped
    networks:
      - kafka-network

volumes:
  zookeeper-data:
  zookeeper-logs:
  kafka-data:

networks:
  kafka-network:
    driver: bridge
EOF

# Update IP address if different
# sed -i 's/192.168.19.80/<YOUR_SERVER_IP>/g' docker-compose.yml

# Start Kafka
docker-compose up -d

# Wait for startup
sleep 30

# Verify
docker ps
docker logs kafka | tail -20

# Create topics
docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 20 \
  --topic sys_logs

docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 10 \
  --topic morpheus-final-realtime-dfp

docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 5 \
  --topic morpheus-llm-enrichment

# List topics
docker exec kafka kafka-topics --list --bootstrap-server localhost:9092

# Create systemd service for auto-start
cat << 'EOF' | sudo tee /etc/systemd/system/kafka-docker.service
[Unit]
Description=Kafka Docker Compose Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/intern_soc/kafka-setup
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Enable
sudo systemctl daemon-reload
sudo systemctl enable kafka-docker
```

### Step 1.3: Install Logstash
```bash
# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install
sudo apt update
sudo apt install -y logstash

# Configure JVM
sudo nano /etc/logstash/jvm.options

# Set heap size (adjust based on RAM):
# -Xms2g
# -Xmx2g

# Create pipeline config
cat << 'EOF' | sudo tee /etc/logstash/conf.d/syslog-to-kafka.conf
input {
  udp {
    port => 5514
    host => "0.0.0.0"
    buffer_size => 26214400 
    workers => 4            
    queue_size => 4000
    type => "syslog"
  }
}

filter {
  mutate {
    add_field => {
      "ingest"        => "udp5514"
      "ingest_type"   => "syslog"
      "ingest_vendor" => "fortinet"
      "ingest_proto"  => "udp"
    }
  }

  dissect {
    mapping => { "message" => "<%{syslog_pri}>%{payload}" }
  }

  syslog_pri {
    syslog_pri_field_name => "syslog_pri"
  }

  if [payload] {
    kv {
      source => "payload"
      field_split => " "
      value_split => "="
      trim_value => "\""
      remove_char_key => "\""
      allow_duplicate_values => false 
    }
  }

  if [date] and [time] {
    mutate {
      add_field => { "fg_timestamp" => "%{date} %{time}" }
    }
    date {
      match => [ "fg_timestamp", "yyyy-MM-dd HH:mm:ss" ]
      timezone => "Asia/Bangkok"
      target => "@timestamp"
    }
  }

  mutate {
    convert => {
      "srcport"   => "integer"
      "dstport"   => "integer"
      "proto"     => "integer"
      "policyid"  => "integer"
      "sessionid" => "integer"
      "appid"     => "integer"
      "eventtime" => "integer"
    }
    remove_field => ["payload", "fg_timestamp", "message"]
  }
}

output {
  kafka {
    bootstrap_servers => "192.168.19.80:9092"
    topic_id => "sys_logs"
    codec => json
    acks => "1"
    retries => 2147483647
    batch_size => 16384 
  }
}
EOF

# Update IP in config if different
# sudo sed -i 's/192.168.19.80/<YOUR_SERVER_IP>/g' /etc/logstash/conf.d/syslog-to-kafka.conf

# Test config
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/syslog-to-kafka.conf

# Start Logstash
sudo systemctl enable logstash
sudo systemctl start logstash

# Monitor logs
sudo journalctl -u logstash -f
# Wait for: "Pipeline started" and "UDP listener started"
# Press Ctrl+C to exit
```

## Phase 2: Pipeline Deployment

### Step 2.1: Clone Repository
```bash
# Clone project (if using Git)
cd ~
git clone https://github.com/ItzPalmz/morpheus-threat-detection.git
cd morpheus-threat-detection

# Or create from scratch
mkdir -p ~/morpheus-threat-detection
cd ~/morpheus-threat-detection
mkdir -p scripts/{morpheus,llm,wazuh}
mkdir -p configs/{logstash,wazuh,kafka}
mkdir -p docs
```

### Step 2.2: Setup Morpheus Environment
```bash
# Create Conda environment
conda create -n morpheus python=3.10 -y
conda activate morpheus

# Install PyTorch with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Install dependencies
pip install \
    cudf-cu12 \
    cuml-cu12 \
    cupy-cuda12x \
    transformers \
    bitsandbytes \
    accelerate \
    sentencepiece \
    protobuf \
    confluent-kafka \
    opensearch-py \
    pandas \
    numpy \
    scikit-learn

# Verify GPU access
python -c "import torch; print(torch.cuda.is_available())"
# Should print: True
```

### Step 2.3: Deploy Morpheus Pipeline
```bash
# Place your morpheus_pipeline.py in:
# ~/morpheus-threat-detection/scripts/morpheus/morpheus_pipeline.py

# Create systemd service
cat << 'EOF' | sudo tee /etc/systemd/system/morpheus-pipeline.service
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
EOF

# Enable service (don't start yet)
sudo systemctl daemon-reload
sudo systemctl enable morpheus-pipeline
```

### Step 2.4: Deploy LLM Enrichment
```bash
# Place your llm_enrichment.py in:
# ~/morpheus-threat-detection/scripts/llm/llm_enrichment.py

# Create systemd service
cat << 'EOF' | sudo tee /etc/systemd/system/morpheus-llm-enricher.service
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
MemoryMax=16G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
EOF

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable morpheus-llm-enricher
```

### Step 2.5: Deploy Indexers
```bash
# Place your morpheus_to_wazuh.py in:
# ~/morpheus-threat-detection/scripts/wazuh/morpheus_to_wazuh.py

# Create systemd service for base indexer
cat << 'EOF' | sudo tee /etc/systemd/system/morpheus-base-indexer.service
[Unit]
Description=Morpheus Base Indexer to Wazuh
After=network.target kafka-docker.service

[Service]
Type=simple
User=intern_soc
WorkingDirectory=/home/intern_soc/morpheus-threat-detection/scripts/wazuh
Environment="PATH=/home/intern_soc/miniconda3/envs/morpheus/bin"
ExecStart=/home/intern_soc/miniconda3/envs/morpheus/bin/python morpheus_to_wazuh.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Place your llm_to_wazuh.py in:
# ~/morpheus-threat-detection/scripts/wazuh/llm_to_wazuh.py

# Create systemd service for LLM indexer
cat << 'EOF' | sudo tee /etc/systemd/system/morpheus-llm-indexer.service
[Unit]
Description=Morpheus LLM Indexer to Wazuh
After=network.target kafka-docker.service morpheus-llm-enricher.service

[Service]
Type=simple
User=intern_soc
WorkingDirectory=/home/intern_soc/morpheus-threat-detection/scripts/wazuh
Environment="PATH=/home/intern_soc/miniconda3/envs/morpheus/bin"
ExecStart=/home/intern_soc/miniconda3/envs/morpheus/bin/python llm_to_wazuh.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable morpheus-base-indexer
sudo systemctl enable morpheus-llm-indexer
```

### Step 2.6: Create OpenSearch Index
```bash
# Set your Wazuh admin password
WAZUH_ADMIN_PASSWORD="your-password-here"

# Create index with proper settings
curl -k -u admin:${WAZUH_ADMIN_PASSWORD} \
  -X PUT https://localhost:9200/morpheus-final-realtime-dfp-2 \
  -H 'Content-Type: application/json' \
  -d '{
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "lifecycle.name": null
      }
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "srcip": {"type": "ip"},
        "dstip": {"type": "ip"},
        "srcport": {"type": "integer"},
        "dstport": {"type": "integer"},
        "dfp_score": {"type": "float"},
        "llm_confidence": {"type": "integer"},
        "srcname": {"type": "keyword"},
        "dstname": {"type": "keyword"},
        "policyname": {"type": "keyword"},
        "service": {"type": "keyword"},
        "app": {"type": "keyword"}
      }
    }
  }'

# Verify
curl -k -u admin:${WAZUH_ADMIN_PASSWORD} \
  https://localhost:9200/_cat/indices/morpheus*
```

## Phase 3: Integration & Testing

### Step 3.1: Configure Wazuh Rules
```bash
# Create custom rules
cat << 'EOF' | sudo tee /var/ossec/etc/rules/local_rules.xml
<group name="morpheus,threat_detection,">
  
  <rule id="100200" level="12">
    <field name="llm_status">analyzed</field>
    <field name="llm_is_suspicious">1</field>
    <description>Morpheus AI: LLM-confirmed security threat detected</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100201" level="8">
    <field name="llm_status">analyzed</field>
    <field name="llm_is_suspicious">0</field>
    <description>Morpheus AI: Event analyzed by LLM (non-threatening)</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100202" level="10">
    <field name="dfp_is_anomaly">1</field>
    <match>dfp_score</match>
    <description>Morpheus AI: Behavioral anomaly detected by DFP</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100203" level="11">
    <field name="threat_class">PortScan</field>
    <description>Morpheus AI: Port scan activity detected</description>
    <options>no_full_log</options>
  </rule>

  <rule id="100206" level="14">
    <field name="dfp_is_anomaly">1</field>
    <field name="llm_is_suspicious">1</field>
    <description>Morpheus AI: CRITICAL - DFP and LLM both confirm threat</description>
    <options>no_full_log</options>
  </rule>

</group>
EOF

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

### Step 3.2: Configure Discord Integration
```bash
# Set your Discord webhook URL
DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"

# Create Discord integration script (place custom-discord script here)
# sudo nano /var/ossec/integrations/custom-discord
# (Use the script from wazuh-integration.md)

# Make executable
sudo chmod +x /var/ossec/integrations/custom-discord
sudo chown root:wazuh /var/ossec/integrations/custom-discord

# Configure in ossec.conf
sudo bash -c "cat >> /var/ossec/etc/ossec.conf" << EOF

<integration>
  <name>custom-discord</name>
  <hook_url>${DISCORD_WEBHOOK}</hook_url>
  <level>10</level>
  <rule_id>100200,100203,100206</rule_id>
  <alert_format>json</alert_format>
</integration>
EOF

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

### Step 3.3: Configure FortiGate
```bash
# On FortiGate CLI, run:
# config log syslogd setting
#     set status enable
#     set server "192.168.19.80"
#     set port 5514
#     set mode udp
#     set facility local7
# end
#
# config log syslogd filter
#     set traffic enable
#     set forward-traffic enable
# end

# Verify from FortiGate:
# get log syslogd setting
# diagnose test application syslogd 1
```

### Step 3.4: Start All Services
```bash
# Start services in order
sudo systemctl start morpheus-pipeline
sleep 30

sudo systemctl start morpheus-llm-enricher
sleep 10

sudo systemctl start morpheus-base-indexer
sleep 10

sudo systemctl start morpheus-llm-indexer

# Check all services
sudo systemctl status morpheus-pipeline
sudo systemctl status morpheus-llm-enricher
sudo systemctl status morpheus-base-indexer
sudo systemctl status morpheus-llm-indexer
```

### Step 3.5: Verify Data Flow
```bash
# Test data flow
cat > ~/test_data_flow.sh << 'EOF'
#!/bin/bash

echo "=== Testing Complete Data Flow ==="
echo

echo "1. Sending test log to Logstash..."
echo '<189>date=2026-02-16 time=10:00:00 devname="Test" srcip=1.1.1.1 dstip=8.8.8.8 srcport=12345 dstport=443 proto=6 action=accept' \
  | nc -u localhost 5514

sleep 5

echo "2. Checking Kafka sys_logs..."
COUNT1=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic sys_logs 2>/dev/null | awk -F: '{sum+=$NF} END {print sum}')
echo "   Messages: $COUNT1"

echo "3. Checking Kafka morpheus-final-realtime-dfp..."
COUNT2=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic morpheus-final-realtime-dfp 2>/dev/null | awk -F: '{sum+=$NF} END {print sum}')
echo "   Messages: $COUNT2"

echo "4. Checking Wazuh index..."
COUNT3=$(curl -sk -u admin:${WAZUH_ADMIN_PASSWORD} \
  https://localhost:9200/morpheus-final-realtime-dfp-2/_count | jq .count)
echo "   Documents: $COUNT3"

echo
echo "=== Results ==="
echo "Logstash → Kafka: $([ $COUNT1 -gt 0 ] && echo '✅' || echo '❌')"
echo "Morpheus → Kafka: $([ $COUNT2 -gt 0 ] && echo '✅' || echo '❌')"
echo "Indexer → Wazuh: $([ $COUNT3 -gt 0 ] && echo '✅' || echo '❌')"
EOF

chmod +x ~/test_data_flow.sh
./test_data_flow.sh
```

### Step 3.6: Generate Test Traffic
```bash
# Wait for FortiGate logs (5-10 minutes)
echo "Waiting for FortiGate logs..."
sleep 300

# Check Kafka is receiving
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --max-messages 5

# Check for threats in Wazuh
curl -k -u admin:${WAZUH_ADMIN_PASSWORD} \
  https://localhost:9200/morpheus-final-realtime-dfp-2/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {"term": {"is_threat": 1}},
    "size": 5,
    "sort": [{"@timestamp": "desc"}]
  }' | jq '.hits.hits[] | {srcip: ._source.srcip, threat: ._source.threat_class}'
```

## Phase 4: Production Cutover

### Step 4.1: Enable Monitoring
```bash
# Create monitoring script
cat > ~/monitor_morpheus.sh << 'EOF'
#!/bin/bash

while true; do
    clear
    echo "=== Morpheus System Monitor ==="
    date
    echo
    
    echo "Services:"
    systemctl is-active morpheus-pipeline && echo "  ✅ Pipeline" || echo "  ❌ Pipeline"
    systemctl is-active morpheus-llm-enricher && echo "  ✅ LLM" || echo "  ❌ LLM"
    systemctl is-active morpheus-base-indexer && echo "  ✅ Base Indexer" || echo "  ❌ Base"
    systemctl is-active morpheus-llm-indexer && echo "  ✅ LLM Indexer" || echo "  ❌ LLM Index"
    
    echo
    echo "GPU:"
    nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader
    
    echo
    echo "Kafka Messages:"
    docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
      --broker-list localhost:9092 \
      --topic sys_logs 2>/dev/null | awk -F: '{sum+=$NF} END {print "  sys_logs: " sum}'
    
    sleep 10
done
EOF

chmod +x ~/monitor_morpheus.sh

# Run in tmux
sudo apt install -y tmux
# tmux new -s monitor
# ./monitor_morpheus.sh
# Detach: Ctrl+B, D
```

### Step 4.2: Configure Automated Backups
```bash
# Create backup directory
sudo mkdir -p /backup/morpheus

# Create backup script
cat > ~/backup_morpheus.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/morpheus"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${BACKUP_DIR}

# Backup configs
tar czf ${BACKUP_DIR}/configs_${DATE}.tar.gz \
  /etc/logstash/conf.d/ \
  /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/ossec.conf \
  /home/intern_soc/kafka-setup/docker-compose.yml \
  /home/intern_soc/morpheus-threat-detection/ 2>/dev/null

# Cleanup old backups (keep 30 days)
find ${BACKUP_DIR} -name "configs_*.tar.gz" -mtime +30 -delete

echo "Backup completed: ${BACKUP_DIR}/configs_${DATE}.tar.gz"
EOF

chmod +x ~/backup_morpheus.sh

# Add to crontab (daily at 2 AM)
(crontab -l 2>/dev/null; echo "0 2 * * * /home/intern_soc/backup_morpheus.sh >> /var/log/morpheus-backup.log 2>&1") | crontab -
```

### Step 4.3: Final Health Check
```bash
# Run comprehensive health check
cat > ~/health_check.sh << 'EOF'
#!/bin/bash

echo "=== COMPREHENSIVE HEALTH CHECK ==="
echo

PASS=0
FAIL=0

# Check services
for service in kafka-docker logstash morpheus-pipeline morpheus-llm-enricher morpheus-base-indexer morpheus-llm-indexer wazuh-manager; do
    if systemctl is-active --quiet $service; then
        echo "✅ $service"
        ((PASS++))
    else
        echo "❌ $service"
        ((FAIL++))
    fi
done

# Check GPU
if nvidia-smi > /dev/null 2>&1; then
    echo "✅ GPU Available"
    ((PASS++))
else
    echo "❌ GPU Not Available"
    ((FAIL++))
fi

# Check Kafka topics
TOPICS=$(docker exec kafka kafka-topics --list --bootstrap-server localhost:9092 2>/dev/null | wc -l)
if [ $TOPICS -ge 3 ]; then
    echo "✅ Kafka Topics ($TOPICS)"
    ((PASS++))
else
    echo "❌ Kafka Topics ($TOPICS)"
    ((FAIL++))
fi

# Check data flow
MSGS=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 --topic sys_logs 2>/dev/null | awk -F: '{sum+=$NF} END {print sum}')
if [ $MSGS -gt 0 ]; then
    echo "✅ Data Flowing ($MSGS messages)"
    ((PASS++))
else
    echo "❌ No Data Flow"
    ((FAIL++))
fi

echo
echo "=== RESULTS ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"

if [ $FAIL -eq 0 ]; then
    echo "✅ SYSTEM HEALTHY - READY FOR PRODUCTION"
    exit 0
else
    echo "❌ SYSTEM HAS ISSUES - CHECK FAILED COMPONENTS"
    exit 1
fi
EOF

chmod +x ~/health_check.sh
./health_check.sh
```

## Post-Deployment

### Week 1: Tuning Phase

**Day 1-3: Baseline Collection**
- Monitor for false positives
- No tuning yet, just observe
- Run `./health_check.sh` daily
- Review Discord alerts
- Document any issues

**Day 4-7: Initial Tuning**
```bash
# If too many LLM calls (>5%)
# Edit: ~/morpheus-threat-detection/scripts/llm/llm_enrichment.py
# Increase: DFP_ANOMALY_THRESHOLD = 0.80

# If missing threats
# Edit: ~/morpheus-threat-detection/scripts/morpheus/morpheus_pipeline.py
# Decrease: DFP_ANOMALY_THRESHOLD = 0.60

# Restart affected services
sudo systemctl restart morpheus-llm-enricher
sudo systemctl restart morpheus-pipeline
```

### Monthly Tasks
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Update Conda packages
conda activate morpheus
conda update --all

# Check disk usage
df -h

# Review threat statistics
# Generate monthly report from Wazuh Dashboard
```

## Rollback Procedures

### Emergency Rollback
```bash
# Stop all Morpheus services
sudo systemctl stop morpheus-pipeline
sudo systemctl stop morpheus-llm-enricher
sudo systemctl stop morpheus-base-indexer
sudo systemctl stop morpheus-llm-indexer

# Kafka stays running

# Restore from backup if needed
cd /backup/morpheus/
tar xzf configs_LATEST.tar.gz
# Copy configs back to original locations
```

### Partial Rollback
```bash
# Disable LLM (keep Morpheus + DFP)
sudo systemctl stop morpheus-llm-enricher
sudo systemctl stop morpheus-llm-indexer
sudo systemctl disable morpheus-llm-enricher
sudo systemctl disable morpheus-llm-indexer
```

## Troubleshooting Quick Reference
```bash
# Service won't start
sudo journalctl -u <service-name> -n 100

# No logs in Kafka
sudo tcpdump -i any port 5514 -c 10

# GPU issues
nvidia-smi
sudo systemctl restart morpheus-pipeline

# Wazuh index issues
curl -k -u admin:${WAZUH_ADMIN_PASSWORD} \
  https://localhost:9200/_cluster/health?pretty

# Full system diagnostic
./health_check.sh
```

## Conclusion

Your Morpheus AI Threat Detection System is now deployed and operational.

**Success Criteria**:
- All services running
- Data flowing end-to-end
- Threats detected and alerted
- Dashboard accessible
- Backups configured
