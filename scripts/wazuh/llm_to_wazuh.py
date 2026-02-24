#!/usr/bin/env python3
"""
Kafka LLM Enrichment to Wazuh OpenSearch Consumer
Consumes from morpheus-llm-enrichment and indexes to Wazuh
"""
from confluent_kafka import Consumer
from opensearchpy import OpenSearch, helpers
import json
import logging
from datetime import datetime
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================================
# CONFIGURATION
# ============================================================================
KAFKA_BROKER = "192.168.19.80:9092"
KAFKA_TOPIC = "morpheus-llm-enrichment"  
GROUP_ID = "morpheus-llm-wazuh-indexer"

INDEXER_HOST = "192.168.19.80"
INDEXER_PORT = 9200
INDEXER_USER = "admin"
INDEXER_PASS = "HsU4+m88zRiiJ*yI7gbWlBaloHmycLDC"
INDEX_NAME = "morpheus-llm-alerts"  

# ============================================================================
# TUNING PARAMETERS 
# ============================================================================
MAX_BULK_SIZE = 50         # Smaller batches for lower latency
MAX_FLUSH_INTERVAL = 1.0   # Flush every 1 second max
POLL_TIMEOUT = 0.1         # Seconds

# Kafka Consumer Performance Tuning
KAFKA_FETCH_MIN_BYTES = 1  # Process immediately
KAFKA_FETCH_WAIT_MAX_MS = 100    

# ============================================================================
# OPENSEARCH CLIENT
# ============================================================================
client = OpenSearch(
    hosts=[{'host': INDEXER_HOST, 'port': INDEXER_PORT}],
    http_auth=(INDEXER_USER, INDEXER_PASS),
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False,
    timeout=30,
    max_retries=3,
    retry_on_timeout=True
)

try:
    info = client.info()
    logging.info(f"Connected to OpenSearch: {info['version']['number']}")
except Exception as e:
    logging.error(f"Failed to connect to OpenSearch: {e}")
    sys.exit(1)

# ============================================================================
# KAFKA CONSUMER
# ============================================================================
conf = {
    "bootstrap.servers": KAFKA_BROKER,
    "group.id": GROUP_ID,
    "auto.offset.reset": "latest",
    "enable.auto.commit": True,
    "auto.commit.interval.ms": 1000,
    "fetch.min.bytes": KAFKA_FETCH_MIN_BYTES,
    "fetch.wait.max.ms": KAFKA_FETCH_WAIT_MAX_MS,
    "session.timeout.ms": 45000,
    "max.poll.interval.ms": 600000, 
    "heartbeat.interval.ms": 3000,
}

consumer = Consumer(conf)
consumer.subscribe([KAFKA_TOPIC])

# ============================================================================
# BULK INDEXING LOGIC
# ============================================================================
buffer = []
last_flush_time = time.time()
total_indexed = 0
total_errors = 0
llm_analyzed = 0
llm_suspicious = 0

def flush_bulk(actions):
    global total_indexed, total_errors, last_flush_time
    if not actions:
        return
    
    try:
        start_time = time.time()
        success, errors = helpers.bulk(
            client, 
            actions,
            raise_on_error=False,
            raise_on_exception=False
        )
        
        elapsed = time.time() - start_time
        total_indexed += success
        
        if errors:
            total_errors += len(errors)
            logging.error(f"Bulk error: {errors[0]}")
        
        logging.info(
            f"Indexed {success} docs in {elapsed:.3f}s | "
            f"Total: {total_indexed} | LLM Analyzed: {llm_analyzed} | Suspicious: {llm_suspicious}"
        )
        last_flush_time = time.time()
        
    except Exception as e:
        logging.error(f"Fatal bulk indexing failure: {e}")
        total_errors += len(actions)

def should_flush(buffer_size):
    """Trigger flush based on batch size or time elapsed."""
    if buffer_size >= MAX_BULK_SIZE:
        return True
    if (time.time() - last_flush_time) >= MAX_FLUSH_INTERVAL and buffer_size > 0:
        return True
    return False

# ============================================================================
# MAIN CONSUMER LOOP
# ============================================================================
logging.info("="*70)
logging.info(f"LLM Enrichment -> Wazuh Indexer Started")
logging.info(f"   Topic: {KAFKA_TOPIC}")
logging.info(f"   Index: {INDEX_NAME}")
logging.info(f"   Max Latency: {MAX_FLUSH_INTERVAL}s")
logging.info("="*70)

try:
    while True:
        msg = consumer.poll(POLL_TIMEOUT)

        # 1. Handle Empty Poll / Time-based Flush
        if msg is None:
            if should_flush(len(buffer)):
                flush_bulk(buffer)
                buffer = []
            continue

        # 2. Handle Kafka Errors
        if msg.error():
            logging.error(f"Kafka error: {msg.error()}")
            continue

        # 3. Parse Message
        try:
            event = json.loads(msg.value().decode('utf-8'))
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode failure: {e}")
            continue
        
        # 4. Track LLM stats
        if event.get('llm_status') == 'analyzed':
            llm_analyzed += 1
            if event.get('llm_is_suspicious') == 1:
                llm_suspicious += 1
        
        # 5. Enforce @timestamp for Wazuh/OpenSearch
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
        
        # 6. Add event type marker for Wazuh rules
        event["event_type"] = "morpheus_llm_enrichment"
        
        # 7. Buffer for Bulk
        buffer.append({
            "_index": INDEX_NAME,
            "_source": event
        })

        # 8. Check for Size-based Flush
        if should_flush(len(buffer)):
            flush_bulk(buffer)
            buffer = []

except KeyboardInterrupt:
    logging.info("Shutting down consumer...")
finally:
    # Final flush before exit
    if buffer:
        logging.info(f"Final flush of {len(buffer)} documents...")
        flush_bulk(buffer)
    consumer.close()
    logging.info(f"Process ended. Success: {total_indexed}, Errors: {total_errors}")
    sys.exit(0)