#!/bin/bash
# Morpheus AI Threat Detection - Setup Script
# Automatically sets up the entire deployment from GitHub repository

set -e

# ==================== COLORS ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${YELLOW}===================================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}===================================================${NC}"
    echo ""
}

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }

# ==================== REPO ROOT ====================
# setup.sh must live in repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "${BLUE}Repository root: $REPO_ROOT${NC}"

# ==================== FIXED PATHS ====================
SCRIPTS_DIR="$REPO_ROOT/scripts"
MODELS_DIR="$REPO_ROOT/models"
CACHE_DIR="$MODELS_DIR/dfp_cache"
CONFIGS_DIR="$REPO_ROOT/configs"

# STRICT BERT PATH (NO OVERRIDES)
BERT_MODEL_PATH="$MODELS_DIR/bert_fortinet_trained"

# Optional LLM (disabled by default)
LLM_MODELS_PATH="$MODELS_DIR/llm"

# Docker/Kafka defaults
KAFKA_HOST="${KAFKA_HOST:-192.168.19.80}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
IMAGE_NAME="${IMAGE_NAME:-morpheus-rtx5090:latest}"
NETWORK_NAME="${NETWORK_NAME:-morpheus-network}"

# ==================== PREREQUISITES ====================
print_header "Step 1: Checking Prerequisites"

command -v docker >/dev/null || { print_error "Docker not installed"; exit 1; }

if command -v docker-compose >/dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

docker info >/dev/null || { print_error "Docker daemon not running"; exit 1; }
print_success "Docker is ready"

# ==================== VALIDATE REPO STRUCTURE ====================
print_header "Step 2: Validating Repository Structure"

[ -d "$SCRIPTS_DIR" ] || { print_error "Missing scripts directory"; exit 1; }
[ -d "$MODELS_DIR" ] || { print_error "Missing models directory"; exit 1; }

mkdir -p "$CACHE_DIR"
chmod 777 "$CACHE_DIR"

# ==================== STRICT BERT CHECK ====================
print_header "Step 3: Validating BERT Model"

if [ ! -d "$BERT_MODEL_PATH" ]; then
    print_error "BERT model directory missing:"
    echo "Expected: $BERT_MODEL_PATH"
    exit 1
fi

if [ ! -f "$BERT_MODEL_PATH/config.json" ]; then
    print_error "config.json missing inside bert_fortinet_trained"
    exit 1
fi

print_success "BERT model validated"

# ==================== BUILD IMAGE ====================
print_header "Step 4: Building Docker Image"

cd "$REPO_ROOT"
docker build -t "$IMAGE_NAME" .
print_success "Image built"

# ==================== NETWORK ====================
print_header "Step 5: Docker Network"

docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || \
docker network create "$NETWORK_NAME"

print_success "Network ready"

# ==================== KAFKA ====================
print_header "Step 6: Starting Kafka"

docker ps | grep -q zookeeper || docker run -d \
  --name zookeeper \
  --network "$NETWORK_NAME" \
  -p 2181:2181 \
  confluentinc/cp-zookeeper:7.5.0

sleep 5

docker ps | grep -q kafka || docker run -d \
  --name kafka \
  --network "$NETWORK_NAME" \
  -p "$KAFKA_PORT:9092" \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:29092 \
  confluentinc/cp-kafka:7.5.0

sleep 10

docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
  --create --topic sys_logs --if-not-exists

docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
  --create --topic morpheus-final-realtime-dfp --if-not-exists

print_success "Kafka ready"

# ==================== DEPLOY ====================
print_header "Step 7: Starting Morpheus"

CONTAINER_NAME="morpheus-production-1"
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --network "$NETWORK_NAME" \
  --gpus all \
  -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 \
  -e KAFKA_INPUT_TOPIC=sys_logs \
  -e KAFKA_OUTPUT_TOPIC=morpheus-final-realtime-dfp \
  -v "$SCRIPTS_DIR:/workspace/scripts:ro" \
  -v "$CACHE_DIR:/workspace/models/dfp_cache:rw" \
  -v "$BERT_MODEL_PATH:/models/bert:ro" \
  --restart unless-stopped \
  "$IMAGE_NAME" \
  python /workspace/scripts/morpheus/morpheus_pipeline.py

print_success "Morpheus container started"

# ==================== SUMMARY ====================
print_header "Deployment Complete"

docker ps --format "table {{.Names}}\t{{.Status}}"
echo ""
echo "View logs:"
echo "docker logs -f morpheus-production-1"