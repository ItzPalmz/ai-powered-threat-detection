# Morpheus AI Threat Detection - Production Dockerfile
FROM nvcr.io/nvidia/morpheus/morpheus:v24.06.03-runtime

LABEL maintainer="Teetuch Thawinphrai"
LABEL description="AI-Powered Threat Detection with NVIDIA Morpheus"
LABEL version="1.0"

# Set working directory
WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    vim \
    htop \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files first (for better Docker layer caching)
COPY requirements*.txt /workspace/

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt || echo "Some packages may have failed"

# Install critical packages explicitly (in case requirements.txt is incomplete)
RUN pip install --no-cache-dir \
    transformers>=4.30.0 \
    torch>=2.0.0 \
    scikit-learn>=1.3.0 \
    confluent-kafka>=2.3.0 \
    pandas>=2.0.0 \
    numpy>=1.24.0 \
    cudf-cu12>=23.10.0 \
    cupy-cuda12x>=12.0.0 || echo "GPU packages may need manual install"

# Create necessary directories
RUN mkdir -p \
    /workspace/scripts \
    /workspace/models \
    /workspace/models/dfp_cache \
    /workspace/configs \
    /workspace/logs \
    /workspace/data

# Set permissions
RUN chmod -R 777 /workspace/models/dfp_cache /workspace/logs /workspace/data

# Copy application files (these will be overridden by volume mounts in production)
COPY scripts/ /workspace/scripts/
COPY models/ /workspace/models/
COPY configs/ /workspace/configs/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV CUDA_VISIBLE_DEVICES=0
ENV MORPHEUS_LOG_LEVEL=INFO
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092
ENV HF_HOME=/workspace/.cache/huggingface

# Expose ports
EXPOSE 8080

# Health check - verify CUDA is available
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD python3 -c "import sys; import torch; sys.exit(0 if torch.cuda.is_available() else 1)" || exit 1

# Default command
CMD ["python3", "/workspace/scripts/morpheus/morpheus_pipeline.py"]