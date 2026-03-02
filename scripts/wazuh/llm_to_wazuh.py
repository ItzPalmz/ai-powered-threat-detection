#!/usr/bin/env python3
"""
Debug Updater: Tries to find data with wider windows and relaxed field mappings.
"""
from opensearchpy import OpenSearch
from confluent_kafka import Consumer
import json
import logging
from datetime import datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# CONFIGURATION

KAFKA_BROKER = "192.168.19.80:9092"
KAFKA_TOPIC = "morpheus-llm-enrichment"
GROUP_ID = "morpheus-llm-updater-debug"

OPENSEARCH_HOST = "192.168.19.80"
OPENSEARCH_PORT = 9200
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "password"
MORPHEUS_INDEX = "morpheus-final-realtime-dfp-2"

# INCREASED TIME WINDOW for debugging (5 minutes)
TIME_WINDOW = 300 

# OPENSEARCH CLIENT

client = OpenSearch(
    hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
    http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False,
    timeout=30
)

consumer = Consumer({
    "bootstrap.servers": KAFKA_BROKER,
    "group.id": GROUP_ID,
    "auto.offset.reset": "latest",
    "enable.auto.commit": True,
})
consumer.subscribe([KAFKA_TOPIC])

logging.info(f"DEBUG MODE ACTIVE")
logging.info(f"Window increased to: {TIME_WINDOW}s (5 mins)")
logging.info(f"Query mode: Relaxing .keyword checks")

# MAIN LOOP

stats = {
    'total': 0, 'matched': 0, 'no_match': 0, 'errors': 0
}

try:
    while True:
        msg = consumer.poll(1.0)
        if msg is None: continue
        if msg.error(): continue
        
        try:
            llm_data = json.loads(msg.value().decode('utf-8'))
        except:
            continue
        
        stats['total'] += 1
        
        # Extract fields
        timestamp = llm_data.get('@timestamp')
        srcip = llm_data.get('srcip')
        dstip = llm_data.get('dstip')
        srcport = llm_data.get('srcport')
        dstport = llm_data.get('dstport')
        
        if not all([timestamp, srcip, dstip]):
            continue

        # Parse timestamp
        try:
            if timestamp.endswith('Z'):
                ts_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                ts_dt = datetime.fromisoformat(timestamp)
            
            # Create wide window
            t_start = (ts_dt - timedelta(seconds=TIME_WINDOW)).isoformat()
            t_end = (ts_dt + timedelta(seconds=TIME_WINDOW)).isoformat()
        except Exception as e:
            logging.error(f"Time Parse Error: {e}")
            continue
        
        # STRATEGY 1: Try Searching WITHOUT .keyword first
        # This assumes srcip/dstip are mapped as 'ip' or 'keyword' directly.
        # If your mapping has 'srcip.keyword', it usually also has 'srcip'.
        
        query_filters = [
            {"term": {"srcip": srcip}},   # Removed .keyword
            {"term": {"dstip": dstip}},   # Removed .keyword
            {"range": {"@timestamp": {"gte": t_start, "lte": t_end}}}
        ]
        
        if srcport is not None:
            query_filters.append({"term": {"srcport": int(srcport)}})
        if dstport is not None:
            query_filters.append({"term": {"dstport": int(dstport)}})
            
        query = {
            "query": {"bool": {"must": query_filters}},
            "size": 1,
            "sort": [{"@timestamp": "asc"}]
        }
        
        # DEBUG: Print the actual query being sent
        logging.info(f"DEBUG Query for {srcip} -> {dstip}:\n{json.dumps(query, indent=2)}")

        try:
            result = client.search(index=MORPHEUS_INDEX, body=query)
            hits = result['hits']['total']['value']
            
            if hits > 0:
                # Update logic
                doc = result['hits']['hits'][0]
                doc_id = doc['_id']
                update_body = {
                    "doc": {
                        "llm_is_suspicious": llm_data.get('llm_is_suspicious'),
                        "llm_confidence": llm_data.get('llm_confidence'),
                        "llm_response": llm_data.get('llm_response'),
                        "llm_trigger": llm_data.get('llm_trigger'),
                        "llm_matched": True
                    }
                }
                client.update(index=MORPHEUS_INDEX, id=doc_id, body=update_body)
                stats['matched'] += 1
                logging.info(f"MATCHED: Updated {doc_id}")
            else:

                # STRATEGY 2: If still no match, try WILD CARD searching
                # This helps if data is there but IPs have different formatting (e.g. spaces)
                # Only do this for the first 10 errors to avoid spam
                if stats['no_match'] < 10:
                    logging.warning(f"Exact match failed. Attempting wildcard search for {srcip}...")
                    
                    wildcard_query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"wildcard": {"srcip.keyword": f"*{srcip}*"}}, # Force keyword here
                                    {"wildcard": {"dstip.keyword": f"*{dstip}*"}},
                                    {"range": {"@timestamp": {"gte": t_start, "lte": t_end}}}
                                ]
                            }
                        },
                        "size": 1
                    }
                    
                    wc_result = client.search(index=MORPHEUS_INDEX, body=wildcard_query)
                    wc_hits = wc_result['hits']['total']['value']
                    logging.info(f"Wildcard Search Result: Found {wc_hits} hits")
                
                stats['no_match'] += 1
                
        except Exception as e:
            logging.error(f"Search error: {e}")
            stats['errors'] += 1

except KeyboardInterrupt:
    pass
finally:
    logging.info(f"Stats: {stats}")