# ------------------------------------------------------------
# RTX 5090 Production Image (PyTorch First Architecture)
# ------------------------------------------------------------
FROM nvcr.io/nvidia/pytorch:25.06-py3

LABEL maintainer="Teetuch Thawinphrai"
LABEL description="AI-Powered Threat Detection - RTX 5090 Optimized"
LABEL version="2.0"

# ------------------------------------------------------------
# Environment
# ------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/workspace/.cache/huggingface \
    TRANSFORMERS_CACHE=/workspace/.cache/huggingface \
    XDG_CACHE_HOME=/workspace/.cache

WORKDIR /workspace

# ------------------------------------------------------------
# System utilities
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        vim \
        htop \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Upgrade pip
# ------------------------------------------------------------
RUN python -m pip install --upgrade pip setuptools wheel

# ------------------------------------------------------------
# Install ML + Streaming Dependencies
# ------------------------------------------------------------
RUN pip install --no-cache-dir \
    transformers \
    accelerate \
    scikit-learn \
    scipy \
    pandas \
    confluent-kafka \
    python-dateutil

# ------------------------------------------------------------
# Optional: If RTX 5090 requires nightly torch
# (Uncomment only if needed)
# ------------------------------------------------------------
# RUN pip uninstall -y torch torchvision torchaudio
# RUN pip install --pre torch torchvision torchaudio \
#     --index-url https://download.pytorch.org/whl/nightly/cu124

# ------------------------------------------------------------
# Runtime directories
# ------------------------------------------------------------
RUN mkdir -p \
    /workspace/scripts \
    /workspace/models \
    /workspace/configs \
    /workspace/logs \
    /workspace/data \
    /workspace/.cache

# ------------------------------------------------------------
# Copy application
# ------------------------------------------------------------
COPY scripts/ /workspace/scripts/
COPY models/ /workspace/models/
COPY configs/ /workspace/configs/

ENV KAFKA_BOOTSTRAP_SERVERS=kafka:29092

# ------------------------------------------------------------
# Default command
# ------------------------------------------------------------
CMD ["python", "/workspace/scripts/morpheus/morpheus_pipeline.py"]