#!/bin/bash
# Morpheus AI Threat Detection - Setup Script
# Automatically sets up the entire deployment from GitHub repository

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Script directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo ""
echo "=========================================="
echo "Morpheus AI Threat Detection - Setup"
echo "=========================================="
echo ""
echo -e "${BLUE}Repository root: $REPO_ROOT${NC}"
echo ""

# ==================== CONFIGURATION ====================

# Default values (can be overridden with environment variables)
KAFKA_HOST="${KAFKA_HOST:-192.168.19.80}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
IMAGE_NAME="${IMAGE_NAME:-morpheus-rtx5090:latest}"
NETWORK_NAME="${NETWORK_NAME:-morpheus-network}"

# Paths relative to repository root
SCRIPTS_DIR="$REPO_ROOT/ai-powered-threat-detection//scripts"
MODELS_DIR="$REPO_ROOT/ai-powered-threat-detection//models"
CACHE_DIR="$REPO_ROOT/ai-powered-threat-detection//models/dfp_cache"
CONFIGS_DIR="$REPO_ROOT/ai-powered-threat-detection//configs"

# User-provided paths (will prompt if not set)
BERT_MODEL_PATH="${BERT_MODEL_PATH:-}"
LLM_MODELS_PATH="${LLM_MODELS_PATH:-}"

# ==================== FUNCTIONS ====================

print_header() {
    echo ""
    echo -e "${YELLOW}===================================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}===================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_error "$1 is not installed"
        return 1
    fi
}

# ==================== PREREQUISITE CHECKS ====================

print_header "Step 1: Checking Prerequisites"

# Check Docker
if ! check_command docker; then
    print_error "Docker is required but not installed"
    echo ""
    echo "Install Docker:"
    echo "  curl -fsSL https://get.docker.com -o get-docker.sh"
    echo "  sudo sh get-docker.sh"
    exit 1
fi

# Check Docker Compose
if ! check_command docker-compose; then
    print_warning "docker-compose not found, will use 'docker compose' instead"
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
    print_success "docker-compose is installed"
fi

# Check if Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker daemon is not running"
    echo "Start Docker: sudo systemctl start docker"
    exit 1
fi
print_success "Docker daemon is running"

# Check for NVIDIA GPU
if command -v nvidia-smi &> /dev/null; then
    print_success "NVIDIA GPU detected"
    nvidia-smi --query-gpu=name --format=csv,noheader | head -1
else
    print_warning "nvidia-smi not found - GPU may not be available"
fi

# Check NVIDIA Container Toolkit
if docker run --rm --gpus all nvidia/cuda:12.0-base-ubuntu22.04 nvidia-smi &> /dev/null; then
    print_success "NVIDIA Container Toolkit is working"
else
    print_warning "NVIDIA Container Toolkit may not be configured properly"
    echo "Install: sudo apt-get install -y nvidia-container-toolkit"
fi

# ==================== DIRECTORY STRUCTURE ====================

print_header "Step 2: Verifying Repository Structure"

# Check required directories exist
REQUIRED_DIRS=(
    "$SCRIPTS_DIR"
    "$SCRIPTS_DIR/morpheus"
    "$MODELS_DIR"
    "$CONFIGS_DIR"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        print_success "Found: $dir"
    else
        print_warning "Creating: $dir"
        mkdir -p "$dir"
    fi
done

# Check for Python scripts
if [ -f "$SCRIPTS_DIR/morpheus/morpheus_pipeline.py" ] || \
   [ -f "$SCRIPTS_DIR/morpheus/morpheus_pipeline_official_dfp.py" ]; then
    print_success "Morpheus pipeline scripts found"
else
    print_warning "Morpheus pipeline scripts not found in $SCRIPTS_DIR/morpheus/"
    echo "Expected: morpheus_pipeline.py or morpheus_pipeline_official_dfp.py"
fi

# Create cache directory
if [ ! -d "$CACHE_DIR" ]; then
    print_info "Creating DFP cache directory..."
    mkdir -p "$CACHE_DIR"
    chmod 777 "$CACHE_DIR"
fi
print_success "Cache directory: $CACHE_DIR"

# ==================== EXTERNAL MODEL PATHS ====================

print_header "Step 3: Configuring Model Paths"

# BERT Model Path
if [ -z "$BERT_MODEL_PATH" ]; then
    echo ""
    echo -e "${BLUE}Enter path to BERT model directory:${NC}"
    echo "  This is required for ML-based threat classification"
    echo "  Example: /home/user/bert_fortinet_trained"
    echo ""
    echo "  The directory should contain:"
    echo "    - config.json"
    echo "    - model.safetensors (or pytorch_model.bin)"
    echo "    - tokenizer files"
    echo ""
    echo -e "${BLUE}Path (or Enter to skip if testing without BERT):${NC}"
    read -r BERT_MODEL_PATH
fi

if [ -n "$BERT_MODEL_PATH" ] && [ -d "$BERT_MODEL_PATH" ]; then
    if [ -f "$BERT_MODEL_PATH/config.json" ]; then
        print_success "BERT model found: $BERT_MODEL_PATH"
    else
        print_warning "BERT config.json not found in $BERT_MODEL_PATH"
    fi
elif [ -n "$BERT_MODEL_PATH" ]; then
    print_error "BERT model path does not exist: $BERT_MODEL_PATH"
    BERT_MODEL_PATH=""
fi

# LLM Model Path
if [ -z "$LLM_MODELS_PATH" ]; then
    echo ""
    echo -e "${BLUE}Enter path to LLM models directory (OPTIONAL):${NC}"
    echo "  ${YELLOW}Note: LLM is disabled by default in the pipeline${NC}"
    echo "  If you enable it later, models will auto-download from HuggingFace"
    echo ""
    echo "  Options:"
    echo "    1) Press Enter to skip (models download automatically when needed)"
    echo "    2) Enter local path if you pre-downloaded models"
    echo "       Example: /home/user/llm-models/mistral-7b"
    echo ""
    echo -e "${BLUE}Path (or Enter to skip):${NC}"
    read -r LLM_MODELS_PATH
    
    if [ -z "$LLM_MODELS_PATH" ]; then
        print_info "LLM models will auto-download from HuggingFace when enabled"
    fi
fi

if [ -n "$LLM_MODELS_PATH" ] && [ -d "$LLM_MODELS_PATH" ]; then
    print_success "LLM models path: $LLM_MODELS_PATH"
elif [ -n "$LLM_MODELS_PATH" ]; then
    print_warning "LLM models path does not exist: $LLM_MODELS_PATH"
    LLM_MODELS_PATH=""
fi

# ==================== DOCKER IMAGE ====================

print_header "Step 4: Building Docker Image"

# Check if Dockerfile exists
if [ ! -f "$REPO_ROOT/Dockerfile" ]; then
    print_error "Dockerfile not found in $REPO_ROOT"
    echo ""
    echo "The Dockerfile is required to build the container image."
    echo "Please ensure Dockerfile exists in the repository root."
    exit 1
fi
print_success "Dockerfile found"

if docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    print_info "Image $IMAGE_NAME already exists"
    echo ""
    read -p "Rebuild image? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REBUILD_IMAGE=true
    else
        REBUILD_IMAGE=false
    fi
else
    print_warning "Image $IMAGE_NAME not found - building new image"
    REBUILD_IMAGE=true
fi

if [ "$REBUILD_IMAGE" = true ]; then
    print_info "Building Docker image (this may take 10-15 minutes)..."
    print_info "Installing all Python dependencies from requirements.txt..."
    cd "$REPO_ROOT"
    
    # Build with output
    if docker build -t "$IMAGE_NAME" . ; then
        print_success "Image built successfully: $IMAGE_NAME"
    else
        print_error "Failed to build Docker image"
        echo ""
        echo "Common issues:"
        echo "  1. Check Dockerfile syntax"
        echo "  2. Ensure requirements.txt exists"
        echo "  3. Check internet connectivity"
        echo "  4. Run: docker build -t $IMAGE_NAME . --no-cache"
        exit 1
    fi
else
    print_success "Using existing image: $IMAGE_NAME"
fi

# ==================== DOCKER NETWORK ====================

print_header "Step 5: Setting Up Docker Network"

if docker network inspect "$NETWORK_NAME" > /dev/null 2>&1; then
    print_success "Network $NETWORK_NAME already exists"
else
    print_info "Creating network: $NETWORK_NAME"
    docker network create "$NETWORK_NAME"
    print_success "Network created: $NETWORK_NAME"
fi

# ==================== KAFKA INFRASTRUCTURE ====================

print_header "Step 6: Starting Kafka Infrastructure"

# Zookeeper
if docker ps | grep -q "zookeeper"; then
    print_success "Zookeeper is already running"
else
    print_info "Starting Zookeeper..."
    docker run -d \
        --name zookeeper \
        --network "$NETWORK_NAME" \
        -p 2181:2181 \
        -e ZOOKEEPER_CLIENT_PORT=2181 \
        -e ZOOKEEPER_TICK_TIME=2000 \
        --restart unless-stopped \
        confluentinc/cp-zookeeper:7.5.0
    
    print_info "Waiting for Zookeeper to start (10s)..."
    sleep 10
    print_success "Zookeeper started"
fi

# Kafka
if docker ps | grep -q "kafka"; then
    print_success "Kafka is already running"
else
    print_info "Starting Kafka..."
    docker run -d \
        --name kafka \
        --network "$NETWORK_NAME" \
        -p "$KAFKA_PORT:9092" \
        -e KAFKA_BROKER_ID=1 \
        -e KAFKA_ZOOKEEPER_CONNECT='zookeeper:2181' \
        -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT \
        -e "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:29092,PLAINTEXT_HOST://${KAFKA_HOST}:${KAFKA_PORT}" \
        -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
        -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
        -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
        -e KAFKA_AUTO_CREATE_TOPICS_ENABLE='true' \
        -e KAFKA_NUM_PARTITIONS=3 \
        --restart unless-stopped \
        confluentinc/cp-kafka:7.5.0
    
    print_info "Waiting for Kafka to start (15s)..."
    sleep 15
    print_success "Kafka started"
fi

# Create Kafka topics
print_info "Creating Kafka topics..."
docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
    --create --topic sys_logs \
    --partitions 3 --replication-factor 1 --if-not-exists

docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
    --create --topic morpheus-final-realtime-dfp \
    --partitions 3 --replication-factor 1 --if-not-exists

docker exec kafka kafka-topics --bootstrap-server localhost:9092 \
    --create --topic morpheus-llm-enrichment \
    --partitions 1 --replication-factor 1 --if-not-exists

print_success "Kafka topics created"

# List topics
echo ""
print_info "Available Kafka topics:"
docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list

# ==================== DEPLOYMENT MODE ====================

print_header "Step 7: Deployment Configuration"

echo ""
echo "Choose deployment mode:"
echo "  1) Full deployment (4 Morpheus + 2 LLM + 1 Writer)"
echo "  2) Minimal (1 Morpheus + 1 Writer)"
echo "  3) Docker Compose (use docker-compose.yml)"
echo "  4) Custom"
echo ""
read -p "Enter choice [1-4]: " DEPLOY_MODE

case $DEPLOY_MODE in
    1)
        MORPHEUS_REPLICAS=4
        LLM_REPLICAS=2
        WRITER_ENABLED=true
        ;;
    2)
        MORPHEUS_REPLICAS=1
        LLM_REPLICAS=0
        WRITER_ENABLED=true
        ;;
    3)
        # Use docker-compose
        print_info "Using docker-compose deployment..."
        
        if [ ! -f "$REPO_ROOT/docker-compose.yml" ]; then
            print_error "docker-compose.yml not found in $REPO_ROOT"
            exit 1
        fi
        
        cd "$REPO_ROOT"
        $DOCKER_COMPOSE up -d
        
        print_success "Deployment started via docker-compose"
        echo ""
        echo "View logs: $DOCKER_COMPOSE logs -f"
        echo "Check status: $DOCKER_COMPOSE ps"
        exit 0
        ;;
    4)
        read -p "Number of Morpheus pipeline instances [1-8]: " MORPHEUS_REPLICAS
        read -p "Number of LLM enrichment instances [0-2]: " LLM_REPLICAS
        read -p "Enable Wazuh writer? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            WRITER_ENABLED=true
        else
            WRITER_ENABLED=false
        fi
        ;;
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

# ==================== START CONTAINERS ====================

print_header "Step 8: Starting Morpheus Containers"

# Start Morpheus Pipeline instances
for i in $(seq 1 "$MORPHEUS_REPLICAS"); do
    CONTAINER_NAME="morpheus-production-$i"
    
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        print_warning "Removing existing container: $CONTAINER_NAME"
        docker rm -f "$CONTAINER_NAME"
    fi
    
    print_info "Starting $CONTAINER_NAME..."
    
    VOLUME_ARGS="-v $SCRIPTS_DIR:/workspace/scripts:ro"
    VOLUME_ARGS="$VOLUME_ARGS -v $CACHE_DIR:/workspace/models/dfp_cache:rw"
    
    if [ -n "$BERT_MODEL_PATH" ]; then
        VOLUME_ARGS="$VOLUME_ARGS -v $BERT_MODEL_PATH:/models/bert:ro"
    fi
    
    docker run -d \
        --name "$CONTAINER_NAME" \
        --network "$NETWORK_NAME" \
        --gpus all \
        -e CUDA_VISIBLE_DEVICES=0 \
        -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 \
        -e KAFKA_INPUT_TOPIC=sys_logs \
        -e KAFKA_OUTPUT_TOPIC=morpheus-final-realtime-dfp \
        -e MORPHEUS_LOG_LEVEL=INFO \
        $VOLUME_ARGS \
        --restart unless-stopped \
        "$IMAGE_NAME" \
        python /workspace/scripts/morpheus/morpheus_pipeline.py
    
    sleep 3
    print_success "$CONTAINER_NAME started"
done

# Start LLM Enrichment instances
if [ "$LLM_REPLICAS" -gt 0 ]; then
    print_header "Starting LLM Enrichment Containers"
    
    for i in $(seq 1 "$LLM_REPLICAS"); do
        if [ "$i" -eq 1 ]; then
            CONTAINER_NAME="morpheus-llm-enrichment"
        else
            CONTAINER_NAME="morpheus-llm-enrichment-$i"
        fi
        
        if docker ps -a | grep -q "$CONTAINER_NAME"; then
            print_warning "Removing existing container: $CONTAINER_NAME"
            docker rm -f "$CONTAINER_NAME"
        fi
        
        print_info "Starting $CONTAINER_NAME..."
        
        VOLUME_ARGS="-v $SCRIPTS_DIR:/workspace/scripts:ro"
        
        if [ -n "$LLM_MODELS_PATH" ]; then
            VOLUME_ARGS="$VOLUME_ARGS -v $LLM_MODELS_PATH:/workspace/models:ro"
        fi
        
        docker run -d \
            --name "$CONTAINER_NAME" \
            --network "$NETWORK_NAME" \
            --gpus all \
            -e CUDA_VISIBLE_DEVICES=0 \
            -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 \
            -e COOLDOWN_SECONDS=600 \
            -e MULTI_LOG_WINDOW=120 \
            $VOLUME_ARGS \
            --restart unless-stopped \
            "$IMAGE_NAME" \
            python /workspace/scripts/llm/llm_enrichment.py
        
        sleep 2
        print_success "$CONTAINER_NAME started"
    done
fi

# Start Wazuh Writer
if [ "$WRITER_ENABLED" = true ]; then
    print_header "Starting Wazuh Writer"
    
    CONTAINER_NAME="morpheus-writer"
    
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        print_warning "Removing existing container: $CONTAINER_NAME"
        docker rm -f "$CONTAINER_NAME"
    fi
    
    print_info "Starting $CONTAINER_NAME..."
    
    docker run -d \
        --name "$CONTAINER_NAME" \
        --network "$NETWORK_NAME" \
        -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092 \
        -e WAZUH_INDEXER_HOST="${WAZUH_INDEXER_HOST:-192.168.19.80}" \
        -e WAZUH_INDEXER_PORT="${WAZUH_INDEXER_PORT:-9200}" \
        -e WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}" \
        -e WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD}" \
        -v "$SCRIPTS_DIR:/workspace/scripts:ro" \
        --restart unless-stopped \
        "$IMAGE_NAME" \
        python /workspace/scripts/wazuh/llm_to_wazuh.py
    
    print_success "$CONTAINER_NAME started"
fi

# ==================== VERIFICATION ====================

print_header "Step 9: Deployment Summary"

echo ""
print_success "Setup completed successfully!"
echo ""

print_info "Running containers:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "morpheus|kafka|zookeeper"

echo ""
print_info "Kafka topics:"
docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list

echo ""
print_info "GPU status:"
nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used --format=csv,noheader 2>/dev/null || echo "nvidia-smi not available"

# ==================== NEXT STEPS ====================

print_header "Next Steps"

echo ""
echo "1. Check container logs:"
echo "   docker logs -f morpheus-production-1"
echo ""
echo "2. Monitor Kafka messages:"
echo "   docker exec kafka kafka-console-consumer \\"
echo "     --bootstrap-server localhost:9092 \\"
echo "     --topic morpheus-final-realtime-dfp \\"
echo "     --from-beginning --max-messages 5"
echo ""
echo "3. View all logs:"
echo "   docker logs morpheus-production-1 2>&1 | tail -50"
echo ""
echo "4. Check GPU usage:"
echo "   watch -n 1 nvidia-smi"
echo ""
echo "5. Stop all containers:"
echo "   docker stop \$(docker ps --filter name=morpheus -q)"
echo ""
echo "6. Restart containers:"
echo "   docker restart \$(docker ps --filter name=morpheus -q)"
echo ""

# Save configuration
CONFIG_FILE="$REPO_ROOT/.morpheus-setup.conf"
cat > "$CONFIG_FILE" << EOF
# Morpheus Setup Configuration
# Generated: $(date)

KAFKA_HOST=$KAFKA_HOST
KAFKA_PORT=$KAFKA_PORT
IMAGE_NAME=$IMAGE_NAME
NETWORK_NAME=$NETWORK_NAME
BERT_MODEL_PATH=$BERT_MODEL_PATH
LLM_MODELS_PATH=$LLM_MODELS_PATH
MORPHEUS_REPLICAS=$MORPHEUS_REPLICAS
LLM_REPLICAS=$LLM_REPLICAS
WRITER_ENABLED=$WRITER_ENABLED
EOF

print_success "Configuration saved to: $CONFIG_FILE"

echo ""
echo "=========================================="
echo "Setup Complete! 🎉"
echo "=========================================="
echo ""