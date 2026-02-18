# Troubleshooting Guide

Comprehensive troubleshooting guide for the Morpheus AI Threat Detection System.

## Table of Contents
- [Quick Diagnostic](#quick-diagnostic)
- [Kafka Issues](#kafka-issues)
- [Logstash Issues](#logstash-issues)
- [Morpheus Pipeline Issues](#morpheus-pipeline-issues)
- [LLM Enrichment Issues](#llm-enrichment-issues)
- [Wazuh Integration Issues](#wazuh-integration-issues)
- [Performance Issues](#performance-issues)
- [Data Flow Issues](#data-flow-issues)

## Quick Diagnostic

### Check All Services
```bash
#!/bin/bash
echo "=== Morpheus System Health Check ==="
echo

# Kafka
echo "1. Kafka:"
docker ps | grep -E "kafka|zookeeper" 

# Logstash
echo "2. Logstash:"
sudo systemctl is-active logstash 

# Morpheus Pipeline
echo "3. Morpheus Pipeline:"
sudo systemctl is-active morpheus-pipeline 

# LLM Enrichment
echo "4. LLM Enrichment:"
sudo systemctl is-active morpheus-llm-enricher 

# Base Indexer
echo "5. Base Indexer:"
sudo systemctl is-active morpheus-base-indexer 

# LLM Indexer
echo "6. LLM Indexer:"
sudo systemctl is-active morpheus-llm-indexer 

# Wazuh
echo "7. Wazuh Manager:"
sudo systemctl is-active wazuh-manager 

echo
echo "=== Data Flow Check ==="

# Check Kafka topics
echo "Kafka Topics:"
docker exec kafka kafka-topics --list --bootstrap-server localhost:9092 | grep morpheus

# Check message counts
echo
echo "Message Counts:"
for topic in sys_logs morpheus-final-realtime-dfp morpheus-llm-enrichment; do
  count=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 \
    --topic $topic 2>/dev/null | awk -F: '{sum+=$NF} END {print sum}')
  echo "  $topic: $count"
done

echo
echo "Wazuh Index Count:"
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_count | jq .count
```

Save as `health_check.sh` and run:
```bash
chmod +x health_check.sh
./health_check.sh
```

---

## Kafka Issues

### Issue: Kafka Won't Start

**Symptoms:**
- Container exits immediately
- Port 9092 not listening

**Diagnosis:**
```bash
# Check logs
docker logs kafka

# Check ZooKeeper
docker logs zookeeper

# Check ports
sudo netstat -tulpn | grep -E "2181|9092"
```

**Solutions:**

**1. ZooKeeper not ready:**
```bash
docker-compose restart zookeeper
sleep 15
docker-compose restart kafka
```

**2. Port already in use:**
```bash
# Find process using port
sudo lsof -i :9092

# Kill it
sudo kill -9 <PID>

# Restart Kafka
docker-compose restart kafka
```

**3. Stale ZooKeeper state:**
```bash
docker-compose down
docker volume rm kafka-setup_zookeeper-data
docker-compose up -d
```

### Issue: Can't Connect to Kafka

**Symptoms:**
- "Connection refused" errors
- "No resolvable bootstrap urls"

**Diagnosis:**
```bash
# Test connection
telnet 192.168.19.80 9092

# Check advertised listeners
docker exec kafka env | grep ADVERTISED
```

**Solutions:**

**1. Wrong advertised listener:**
```bash
# Edit docker-compose.yml
nano ~/kafka-setup/docker-compose.yml

# Ensure:
KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092
KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://192.168.19.80:9092

# Restart
docker-compose down
docker-compose up -d
```

**2. Firewall blocking:**
```bash
# Allow port
sudo iptables -A INPUT -p tcp --dport 9092 -j ACCEPT
sudo iptables-save
```

### Issue: Messages Not Appearing in Kafka

**Diagnosis:**
```bash
# Check producer
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --max-messages 1

# Check consumer groups
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --list
```

**Solutions:**

**1. Producer not connected:**
```bash
# Check Logstash logs
sudo journalctl -u logstash | grep -i kafka

# Should see "Cluster ID: ..."
```

**2. Topic doesn't exist:**
```bash
# Create topic
docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 20 \
  --topic sys_logs
```

---

## Logstash Issues

### Issue: Logstash Won't Start

**Symptoms:**
- Service fails immediately
- Port 5514 not listening

**Diagnosis:**
```bash
# Check status
sudo systemctl status logstash

# View logs
sudo journalctl -u logstash -n 100

# Test config
sudo /usr/share/logstash/bin/logstash --config.test_and_exit \
  -f /etc/logstash/conf.d/syslog-to-kafka.conf
```

**Solutions:**

**1. Configuration syntax error:**
```bash
# Test and fix config
sudo /usr/share/logstash/bin/logstash --config.test_and_exit \
  -f /etc/logstash/conf.d/syslog-to-kafka.conf

# Common issues:
# - Missing closing }
# - Wrong quotes
# - Invalid field names
```

**2. Port already in use:**
```bash
# Check what's using 5514
sudo lsof -i :5514

# Kill it
sudo kill -9 <PID>

# Restart Logstash
sudo systemctl restart logstash
```

**3. Java heap too large:**
```bash
# Reduce heap
sudo nano /etc/logstash/jvm.options

# Change to:
-Xms512m
-Xmx512m

# Restart
sudo systemctl restart logstash
```

### Issue: Logs Not Reaching Kafka

**Diagnosis:**
```bash
# Check if receiving UDP
sudo tcpdump -i any -n port 5514 -c 10

# Check Logstash processing
sudo tail -f /var/log/logstash/logstash-plain.log

# Check Kafka connection
sudo journalctl -u logstash | grep -i "cluster id"
```

**Solutions:**

**1. FortiGate not sending:**
```bash
# On FortiGate
diagnose test application syslogd 1

# Or reconfigure syslog
config log syslogd setting
  set status enable
  set server "192.168.19.80"
  set port 5514
end
```

**2. Firewall blocking UDP:**
```bash
# Allow UDP 5514
sudo iptables -A INPUT -p udp --dport 5514 -j ACCEPT

# Check
sudo iptables -L INPUT | grep 5514
```

**3. Logstash not connected to Kafka:**
```bash
# Check bootstrap_servers in config
sudo nano /etc/logstash/conf.d/syslog-to-kafka.conf

# Should be:
bootstrap_servers => "192.168.19.80:9092"

# Restart
sudo systemctl restart logstash
```

---

## Morpheus Pipeline Issues

### Issue: Pipeline Won't Start

**Symptoms:**
- Service exits immediately
- CUDA errors

**Diagnosis:**
```bash
# Check logs
sudo journalctl -u morpheus-pipeline -n 100

# Check GPU
nvidia-smi

# Check Python environment
conda activate morpheus
python -c "import torch; print(torch.cuda.is_available())"
```

**Solutions:**

**1. CUDA not available:**
```bash
# Check NVIDIA driver
nvidia-smi

# Reinstall CUDA
sudo apt-get install cuda-toolkit-12-3

# Update PATH
export PATH=/usr/local/cuda/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH
```

**2. Missing dependencies:**
```bash
conda activate morpheus
pip install torch torchvision cupy-cuda12x transformers
```

**3. Model files missing:**
```bash
# Check model exists
ls -la ~/models/bert_fortinet_trained/

# If missing, copy from backup or retrain
```

### Issue: GPU Out of Memory

**Symptoms:**
- "CUDA out of memory" error
- Pipeline crashes randomly

**Solutions:**

**1. Reduce batch size:**
```python
# In morpheus_pipeline.py
PIPELINE_BATCH_SIZE = 128  # From 256
MODEL_MAX_BATCH_SIZE = 64   # From 128
```

**2. Kill other GPU processes:**
```bash
# Check GPU usage
nvidia-smi

# Kill process
sudo kill -9 <PID>
```

**3. Clear GPU cache:**
```python
# Add to pipeline periodically
import torch
torch.cuda.empty_cache()
```

### Issue: No Output to Kafka

**Diagnosis:**
```bash
# Check if consuming input
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe \
  --group morpheus-hybrid-dfp-peer-production

# Check for errors
sudo journalctl -u morpheus-pipeline | grep -i error
```

**Solutions:**

**1. Not consuming from input topic:**
```bash
# Check Kafka broker address in script
# Should be: "192.168.19.80:9092"

# Restart pipeline
sudo systemctl restart morpheus-pipeline
```

**2. DFP blocking:**
```python
# Lower thresholds in morpheus_pipeline.py
DFP_ANOMALY_THRESHOLD = 0.50  # More sensitive
TRAINING_SAMPLES = 3           # Faster training
```

---

## LLM Enrichment Issues

### Issue: LLM Out of Memory

**Symptoms:**
- "CUDA out of memory"
- Service crashes

**Solutions:**

**1. Verify 4-bit quantization:**
```python
# In llm_enrichment.py
quantization_config = BitsAndBytesConfig(
    load_in_4bit=True,  # Must be True
    # ...
)
```

**2. Reduce token length:**
```python
MAX_NEW_TOKENS = 100  # From 200
```

**3. Kill other GPU processes:**
```bash
nvidia-smi
sudo kill -9 <PID>
```

### Issue: LLM Too Slow

**Symptoms:**
- >5 seconds per analysis
- Building backlog

**Solutions:**

**1. Increase temperature:**
```python
TEMPERATURE = 0.2  # From 0.1 (faster generation)
```

**2. Reduce max tokens:**
```python
MAX_NEW_TOKENS = 100  # From 200
```

**3. Increase thresholds (analyze less):**
```python
DFP_ANOMALY_THRESHOLD = 0.85  # From 0.70
```

### Issue: Too Many LLM Calls

**Symptoms:**
- >10% of logs analyzed
- High GPU usage

**Solutions:**

**1. Increase thresholds:**
```python
DFP_ANOMALY_THRESHOLD = 0.80  # More strict
COOLDOWN_SECONDS = 900         # Longer cooldown
```

**2. Disable multi-log for testing:**
```python
# Comment out multi-log bypass
# if is_multi_log:
#     return True
```

---

## Wazuh Integration Issues

### Issue: No Logs in Wazuh

**Diagnosis:**
```bash
# Check indexers
sudo systemctl status morpheus-base-indexer
sudo systemctl status morpheus-llm-indexer

# Check index
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_count
```

**Solutions:**

**1. Indexers not running:**
```bash
sudo systemctl start morpheus-base-indexer
sudo systemctl start morpheus-llm-indexer
```

**2. Wrong index name:**
```bash
# Check index exists
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/_cat/indices | grep morpheus
```

**3. OpenSearch connection failed:**
```bash
# Test connection
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/

# Check credentials in scripts
```

### Issue: Logs Disappearing

**Diagnosis:**
```bash
# Check for ILM policy
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_settings \
  | jq '.[].settings.index.lifecycle'
```

**Solutions:**

**1. Remove ILM policy:**
```bash
curl -k -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  -X PUT https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_settings \
  -H 'Content-Type: application/json' \
  -d '{"index": {"lifecycle.name": null}}'
```

**2. Check ISM policies:**
```bash
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/_plugins/_ism/explain/morpheus-final-realtime-dfp-2
```

### Issue: Duplicate Logs

**Diagnosis:**
```bash
# Check for duplicates
curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {"term": {"srcip.keyword": "192.168.1.100"}},
    "size": 10
  }' | jq '.hits.hits[] | ._id' | sort | uniq -d
```

**Solutions:**

**1. Different consumer groups:**
```bash
# Check consumer groups are different
grep "GROUP_ID" /home/intern_soc/wazuh-ai-threat-detection/scripts/*.py

# Should see:
# morpheus_to_wazuh.py: morpheus-wazuh-base-indexer
# llm_to_wazuh.py: morpheus-llm-wazuh-updater
```

**2. Ensure UPDATE not INDEX:**
```python
# In llm_to_wazuh.py
"_op_type": "update",  # Not "index"
```

### Issue: Discord Not Working

**Diagnosis:**
```bash
# Test manually
sudo /var/ossec/integrations/custom-discord \
  /var/ossec/logs/alerts/alerts.json \
  "" \
  "YOUR_WEBHOOK_URL"

# Check integration logs
sudo tail -f /var/ossec/logs/integrations.log
```

**Solutions:**

**1. Wrong webhook URL:**
```bash
# Check URL in ossec.conf
sudo grep "hook_url" /var/ossec/etc/ossec.conf
```

**2. Python dependencies missing:**
```bash
sudo pip3 install requests
```

**3. Wrong permissions:**
```bash
sudo chmod +x /var/ossec/integrations/custom-discord
sudo chown root:wazuh /var/ossec/integrations/custom-discord
```

---

## Performance Issues

### Issue: High CPU Usage

**Diagnosis:**
```bash
# Check CPU usage
top -u intern_soc

# Check which service
ps aux | grep -E "morpheus|logstash|kafka" | sort -k3 -r
```

**Solutions:**

**1. Reduce workers:**
```python
# Morpheus pipeline
NUM_THREADS = 16  # From 32

# Logstash
# In /etc/logstash/conf.d/
workers => 2  # From 4
```

**2. Reduce batch sizes:**
```python
PIPELINE_BATCH_SIZE = 128  # From 256
```

### Issue: High Memory Usage

**Diagnosis:**
```bash
# Check memory
free -h

# Check which service
ps aux | sort -k4 -r | head -10
```

**Solutions:**

**1. Limit DFP entities:**
```python
MAX_ENTITIES = 500  # From 1000
```

**2. Reduce Java heap:**
```bash
# Logstash
sudo nano /etc/logstash/jvm.options
-Xms512m
-Xmx512m
```

### Issue: High Latency

**Symptoms:**
- Logs delayed >10 seconds
- Dashboard updates slow

**Solutions:**

**1. Increase Kafka partitions:**
```bash
docker exec kafka kafka-topics --alter \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --partitions 30
```

**2. Reduce batch delay:**
```python
# In indexer scripts
MAX_FLUSH_INTERVAL = 1.0  # From 2.0
```

**3. Use SSD for data:**
```bash
# Move Kafka data to SSD
# Edit docker-compose.yml volumes
```

---

## Data Flow Issues

### Complete Data Flow Test
```bash
#!/bin/bash
echo "=== Testing Complete Data Flow ==="

# 1. Send test to Logstash
echo "Sending test log to Logstash..."
echo '<189>date=2026-02-16 time=10:00:00 devname="Test" srcip=1.1.1.1 dstip=8.8.8.8 srcport=12345 dstport=443' \
  | nc -u 192.168.19.80 5514

sleep 2

# 2. Check Kafka sys_logs
echo "Checking Kafka sys_logs..."
COUNT1=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic sys_logs 2>/dev/null \
  | awk -F: '{sum+=$NF} END {print sum}')
echo "  Messages: $COUNT1"

# 3. Check Kafka morpheus-final-realtime-dfp
echo "Checking Morpheus output..."
COUNT2=$(docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 --topic morpheus-final-realtime-dfp 2>/dev/null \
  | awk -F: '{sum+=$NF} END {print sum}')
echo "  Messages: $COUNT2"

# 4. Check Wazuh index
echo "Checking Wazuh index..."
COUNT3=$(curl -sk -u admin:HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC \
  https://192.168.19.80:9200/morpheus-final-realtime-dfp-2/_count | jq .count)
echo "  Documents: $COUNT3"

echo
echo "=== Data Flow Status ==="
echo "FortiGate → Logstash: ✅"
echo "Logstash → Kafka (sys_logs): $([ $COUNT1 -gt 0 ] && echo '✅' || echo '❌')"
echo "Morpheus → Kafka (dfp): $([ $COUNT2 -gt 0 ] && echo '✅' || echo '❌')"
echo "Indexer → Wazuh: $([ $COUNT3 -gt 0 ] && echo '✅' || echo '❌')"
```

---

## References

- [Kafka Troubleshooting](https://kafka.apache.org/documentation/#troubleshooting)
- [Logstash Troubleshooting](https://www.elastic.co/guide/en/logstash/current/troubleshooting.html)
- [CUDA Troubleshooting](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html#troubleshooting)
- [Wazuh Troubleshooting](https://documentation.wazuh.com/current/user-manual/manager/troubleshooting.html)
