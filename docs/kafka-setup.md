# Kafka Setup Guide

This guide covers setting up Apache Kafka using Docker for the Morpheus threat detection pipeline.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Topic Management](#topic-management)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Ubuntu 24.04 LTS (or similar)
- Docker installed
- Docker Compose installed
- At least 4GB RAM available
- 20GB disk space

## Installation

### Step 1: Install Docker
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt-get update
sudo apt-get install docker-compose-plugin
```

### Step 2: Create Kafka Directory
```bash
mkdir -p ~/kafka-setup
cd ~/kafka-setup
```

### Step 3: Create Docker Compose Configuration

Create `docker-compose.yml`:
```yaml
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
```

**Important**: Replace `192.168.19.80` with your server's IP address.

### Step 4: Start Kafka
```bash
# Start services
docker-compose up -d

# Wait 30 seconds for startup
sleep 30

# Verify containers are running
docker ps
```

Expected output:
```
CONTAINER ID   IMAGE                              STATUS
abc123...      confluentinc/cp-kafka:7.5.0        Up 30 seconds
def456...      confluentinc/cp-zookeeper:7.5.0    Up 30 seconds
```

## Configuration

### Network Configuration

**KAFKA_LISTENERS**: Defines which network interfaces Kafka listens on
- `PLAINTEXT://0.0.0.0:9092` - Listen on all interfaces

**KAFKA_ADVERTISED_LISTENERS**: Address that clients use to connect
- Use your server's IP address: `PLAINTEXT://192.168.19.80:9092`
- For localhost-only: `PLAINTEXT://localhost:9092`

### Performance Tuning

For high-volume environments, adjust these settings:
```yaml
environment:
  # Increase memory
  KAFKA_HEAP_OPTS: "-Xmx2G -Xms2G"
  
  # Increase batch size
  KAFKA_BATCH_SIZE: 32768
  
  # Increase retention
  KAFKA_LOG_RETENTION_HOURS: 336  # 2 weeks
```

## Topic Management

### Create Topics
```bash
# Create sys_logs topic (high-volume)
docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 20 \
  --topic sys_logs

# Create morpheus-final-realtime-dfp topic
docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 10 \
  --topic morpheus-final-realtime-dfp

# Create morpheus-llm-enrichment topic
docker exec kafka kafka-topics --create \
  --bootstrap-server localhost:9092 \
  --replication-factor 1 \
  --partitions 5 \
  --topic morpheus-llm-enrichment
```

### List Topics
```bash
docker exec kafka kafka-topics --list \
  --bootstrap-server localhost:9092
```

### Describe Topic
```bash
docker exec kafka kafka-topics --describe \
  --bootstrap-server localhost:9092 \
  --topic sys_logs
```

### Modify Partitions
```bash
# Increase partitions (can only increase, not decrease)
docker exec kafka kafka-topics --alter \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --partitions 30
```

### Delete Topic
```bash
docker exec kafka kafka-topics --delete \
  --bootstrap-server localhost:9092 \
  --topic old_topic
```

## Monitoring

### Check Message Count
```bash
# Get offset (message count)
docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
  --broker-list localhost:9092 \
  --topic sys_logs
```

### View Messages
```bash
# View recent messages
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --max-messages 10

# View from beginning
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --from-beginning \
  --max-messages 10
```

### Monitor in Real-Time
```bash
# Watch messages as they arrive
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs
```

Press `Ctrl+C` to stop.

### Check Consumer Groups
```bash
# List consumer groups
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --list

# Describe group (shows lag)
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --group morpheus-hybrid-dfp-peer-production \
  --describe
```

### View Logs
```bash
# Kafka logs
docker logs kafka --tail 100

# ZooKeeper logs
docker logs zookeeper --tail 100

# Follow logs in real-time
docker logs kafka -f
```

## Management Scripts

Create a management script for convenience:
```bash
nano ~/kafka-setup/kafka-manager.sh
```
```bash
#!/bin/bash

case "$1" in
  start)
    echo "Starting Kafka stack..."
    cd ~/kafka-setup
    docker-compose up -d
    sleep 30
    docker ps | grep -E "kafka|zookeeper"
    ;;
  stop)
    echo "Stopping Kafka stack..."
    cd ~/kafka-setup
    docker-compose down
    ;;
  restart)
    echo "Restarting Kafka stack..."
    cd ~/kafka-setup
    docker-compose restart
    ;;
  logs)
    cd ~/kafka-setup
    docker-compose logs -f
    ;;
  status)
    docker ps | grep -E "kafka|zookeeper"
    echo ""
    docker exec kafka kafka-topics --list --bootstrap-server localhost:9092
    ;;
  topics)
    docker exec kafka kafka-topics --list --bootstrap-server localhost:9092
    ;;
  offsets)
    for topic in $(docker exec kafka kafka-topics --list --bootstrap-server localhost:9092); do
      echo "Topic: $topic"
      docker exec kafka kafka-run-class kafka.tools.GetOffsetShell \
        --broker-list localhost:9092 \
        --topic $topic 2>/dev/null
      echo ""
    done
    ;;
  clean)
    echo "⚠️  This will DELETE all Kafka data!"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
      cd ~/kafka-setup
      docker-compose down -v
      echo "Kafka data deleted."
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|logs|status|topics|offsets|clean}"
    exit 1
    ;;
esac
```

Make it executable:
```bash
chmod +x ~/kafka-setup/kafka-manager.sh
```

Usage:
```bash
~/kafka-setup/kafka-manager.sh status
~/kafka-setup/kafka-manager.sh logs
~/kafka-setup/kafka-manager.sh topics
```

## Systemd Service (Auto-start on Boot)

Create systemd service:
```bash
sudo nano /etc/systemd/system/kafka-docker.service
```
```ini
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
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable kafka-docker
sudo systemctl start kafka-docker
```

## Troubleshooting

### Issue: Kafka Won't Start

**Symptoms**: Container exits immediately

**Solution**:
```bash
# Check logs
docker logs kafka

# Common fix: ZooKeeper not ready
docker-compose restart zookeeper
sleep 15
docker-compose restart kafka
```

### Issue: Can't Connect to Kafka

**Symptoms**: Connection refused or timeout

**Check**:
```bash
# Verify port is listening
sudo netstat -tulpn | grep 9092

# Test connection
telnet 192.168.19.80 9092
```

**Solution**:
```bash
# Check KAFKA_ADVERTISED_LISTENERS matches your IP
docker exec kafka env | grep KAFKA_ADVERTISED

# Update docker-compose.yml if needed
nano docker-compose.yml
# Change KAFKA_ADVERTISED_LISTENERS to your correct IP
docker-compose down
docker-compose up -d
```

### Issue: Messages Not Appearing

**Check**:
```bash
# Producer side - check if messages are being sent
docker logs kafka | grep -i error

# Consumer side - verify consumer group is active
docker exec kafka kafka-consumer-groups \
  --bootstrap-server localhost:9092 \
  --describe --group YOUR_GROUP_ID
```

### Issue: Disk Full

**Solution**:
```bash
# Check disk usage
df -h

# Reduce retention
docker exec kafka kafka-configs \
  --bootstrap-server localhost:9092 \
  --entity-type topics \
  --entity-name sys_logs \
  --alter \
  --add-config retention.ms=86400000  # 1 day
```

### Issue: High Memory Usage

**Solution**:
```bash
# Stop Kafka
docker-compose down

# Edit docker-compose.yml
nano docker-compose.yml

# Add under kafka environment:
KAFKA_HEAP_OPTS: "-Xmx1G -Xms1G"  # Reduce from default 2G

# Restart
docker-compose up -d
```

### Issue: ZooKeeper Connection Lost

**Symptoms**: `NodeExistsException` or connection errors

**Solution**:
```bash
# Clean restart
docker-compose down
docker volume rm kafka-setup_zookeeper-data
docker-compose up -d
```

## Performance Optimization

### For High-Volume Environments
```yaml
environment:
  # Memory
  KAFKA_HEAP_OPTS: "-Xmx4G -Xms4G"
  
  # Throughput
  KAFKA_NUM_NETWORK_THREADS: 8
  KAFKA_NUM_IO_THREADS: 16
  KAFKA_SOCKET_SEND_BUFFER_BYTES: 102400
  KAFKA_SOCKET_RECEIVE_BUFFER_BYTES: 102400
  
  # Compression
  KAFKA_COMPRESSION_TYPE: lz4
  
  # Batching
  KAFKA_BATCH_SIZE: 32768
  KAFKA_LINGER_MS: 10
```

### Partition Strategy

**Rule of thumb**: 
- Partitions = (Target throughput / Producer throughput per partition)
- High volume: 20-30 partitions
- Medium volume: 10 partitions
- Low volume: 3-5 partitions

## Security (Optional)

### Enable SSL

1. Generate certificates
2. Update docker-compose.yml:
```yaml
environment:
  KAFKA_LISTENERS: SSL://0.0.0.0:9093
  KAFKA_ADVERTISED_LISTENERS: SSL://192.168.19.80:9093
  KAFKA_SSL_KEYSTORE_FILENAME: kafka.keystore.jks
  KAFKA_SSL_KEYSTORE_CREDENTIALS: keystore_creds
  KAFKA_SSL_KEY_CREDENTIALS: key_creds
```

### Enable SASL Authentication
```yaml
environment:
  KAFKA_SASL_ENABLED_MECHANISMS: PLAIN
  KAFKA_SASL_MECHANISM_INTER_BROKER_PROTOCOL: PLAIN
```

## Backup and Recovery

### Backup Topics
```bash
# Export topic data
docker exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs \
  --from-beginning \
  --max-messages 100000 > backup.json
```

### Restore Topics
```bash
# Import data
cat backup.json | docker exec -i kafka kafka-console-producer \
  --bootstrap-server localhost:9092 \
  --topic sys_logs
```

## Best Practices

1. **Partitions**: Start with 10-20 for high-volume topics
2. **Retention**: Set based on disk space (default: 7 days)
3. **Replication**: Use replication-factor=3 for production multi-node clusters
4. **Monitoring**: Set up consumer group lag monitoring
5. **Backups**: Regularly backup topic configurations
6. **Updates**: Keep Kafka version updated for security patches

## References

- [Confluent Documentation](https://docs.confluent.io/)
- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
