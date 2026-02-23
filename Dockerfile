# Morpheus AI Threat Detection - Production Dockerfile
FROM nvcr.io/nvidia/morpheus/morpheus:v24.06.03-runtime

LABEL maintainer="Teetuch Thawinphrai"
LABEL description="AI-Powered Threat Detection with NVIDIA Morpheus"
LABEL version="1.0"

# ------------------------------------------------------------------
# Environment Setup
# ------------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MORPHEUS_LOG_LEVEL=INFO \
    HF_HOME=/workspace/.cache/huggingface \
    TRANSFORMERS_CACHE=/workspace/.cache/huggingface \
    XDG_CACHE_HOME=/workspace/.cache

WORKDIR /workspace

# ------------------------------------------------------------------
# Install ONLY basic utilities (DO NOT touch CUDA / RAPIDS)
# ------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        vim \
        htop \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# Copy dependency file first (better layer caching)
# ------------------------------------------------------------------
COPY requirements.txt .

# Use Morpheus Python (already GPU-aligned)
RUN /opt/conda/bin/pip install --upgrade pip setuptools wheel

# Install ONLY pure-python deps
# (No torch / cudf / cupy here — already provided by base image)
RUN /opt/conda/bin/pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------
# Create runtime directories
# ------------------------------------------------------------------
RUN mkdir -p \
    /workspace/scripts \
    /workspace/models \
    /workspace/models/dfp_cache \
    /workspace/configs \
    /workspace/logs \
    /workspace/data \
    /workspace/.cache

# Give non-root write access (safer than 777)
RUN chmod -R 775 /workspace

# ------------------------------------------------------------------
# Copy application code
# These can still be overridden by docker-compose volumes
# ------------------------------------------------------------------
COPY scripts/ /workspace/scripts/
COPY models/ /workspace/models/
COPY configs/ /workspace/configs/

# ------------------------------------------------------------------
# Runtime Variables (DON'T hardcode GPU index)
# Let Docker/NVIDIA runtime decide
# ------------------------------------------------------------------
ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092

# ------------------------------------------------------------------
# Default command
# ------------------------------------------------------------------
CMD ["python3", "/workspace/scripts/morpheus/morpheus_pipeline.py"]