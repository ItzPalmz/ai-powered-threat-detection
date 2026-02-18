#!/usr/bin/env python3
"""
Optimized LLM Follow-Up Enrichment Pipeline (Mistral 7B INT4)
Reads logs from Kafka, applies Entity Cooldown, analyzes with LLM, sends enrichment back.
"""
import os
import re
import json
import logging
import time
import torch
from datetime import datetime, timezone, timedelta
from confluent_kafka import Consumer, Producer
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ============================================================================
# CONFIGURATION
# ============================================================================
KAFKA_BROKER = "192.168.19.80:9092"
INPUT_TOPIC = "morpheus-final-realtime-dfp"
OUTPUT_TOPIC = "morpheus-llm-enrichment"
GROUP_ID = "morpheus-llm-enrichment-opt"

# LLM thresholds - STRICT
DFP_ANOMALY_THRESHOLD = 0.98
BERT_CONFIDENCE_THRESHOLD = 0.40

# OPTIMIZATION: Entity Cooldown
COOLDOWN_SECONDS = 600  # 10 Minutes

# ============================================================================
# LOAD MISTRAL MODEL (4-bit Quantized)
# ============================================================================
logging.info("Loading Mistral-7B-Instruct-v0.2 with 4-bit quantization...")
device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')

# 4-bit quantization configuration
quantization_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)

llm_tokenizer = AutoTokenizer.from_pretrained(
    "mistralai/Mistral-7B-Instruct-v0.2",
    trust_remote_code=True
)

llm_model = AutoModelForCausalLM.from_pretrained(
    "mistralai/Mistral-7B-Instruct-v0.2",
    quantization_config=quantization_config,
    device_map="auto",
    trust_remote_code=True
)
llm_model.eval()
logging.info("Mistral-7B loaded with INT4 quantization on GPU")

# ============================================================================
# STATE MANAGEMENT (IN-MEMORY COOLDOWN)
# ============================================================================
entity_cooldown_cache = {} 

# ============================================================================
# KAFKA
# ============================================================================
consumer = Consumer({
    "bootstrap.servers": KAFKA_BROKER,
    "group.id": GROUP_ID,
    "auto.offset.reset": "latest",
    "enable.auto.commit": True,
})
consumer.subscribe([INPUT_TOPIC])

producer = Producer({"bootstrap.servers": KAFKA_BROKER})

logging.info(f"Consuming from: {INPUT_TOPIC}")
logging.info(f"Producing to: {OUTPUT_TOPIC}")
logging.info(f"OPTIMIZATION: Entity Cooldown = {COOLDOWN_SECONDS}s")
logging.info(f"THRESHOLDS: DFP > {DFP_ANOMALY_THRESHOLD} OR BERT < {BERT_CONFIDENCE_THRESHOLD}")

# ============================================================================
# LLM ANALYSIS FUNCTION
# ============================================================================
def llm_analyze(log_data, is_dfp_anomaly=False, dfp_score=0.0):
    """Analyze log with Mistral LLM"""
    try:
        srcip = log_data.get('srcip', 'unknown')
        dstip = log_data.get('dstip', 'unknown')
        srcport = log_data.get('srcport', 'unknown')
        dstport = log_data.get('dstport', 'unknown')
        proto = log_data.get('proto', 'unknown')
        action = log_data.get('action', 'unknown')
        app = log_data.get('app', 'unknown')
        sentbyte = log_data.get('sentbyte', 0)
        rcvdbyte = log_data.get('rcvdbyte', 0)
        
        alert_type = f"DFP BEHAVIORAL ANOMALY (score: {dfp_score:.0%})" if is_dfp_anomaly else "LOW CONFIDENCE DETECTION"
        
        # Mistral chat template format
        messages = [
            {
                "role": "user", 
                "content": f"""You are a cybersecurity analyst. Analyze this network log and determine if it's a security threat.

Respond ONLY with valid JSON in this exact format:
{{"is_threat": true/false, "confidence": 0-100, "reason": "Brief explanation of the threat"}}

LOG DATA:
- Source IP: {srcip}
- Destination IP: {dstip}
- Source Port: {srcport}
- Destination Port: {dstport}
- Protocol: {proto}
- Action: {action}
- Application: {app}
- Bytes Sent: {sentbyte}
- Bytes Received: {rcvdbyte}

"""
            }
        ]
        
        # Apply Mistral chat template
        prompt = llm_tokenizer.apply_chat_template(
            messages, 
            tokenize=False, 
            add_generation_prompt=True
        )
        
        inputs = llm_tokenizer(
            prompt, 
            return_tensors='pt', 
            truncation=True, 
            max_length=1024
        ).to(device)
        
        with torch.no_grad():
            outputs = llm_model.generate(
                **inputs,
                max_new_tokens=200,
                temperature=0.1,  # Very low temp for consistent security analysis
                top_p=0.9,
                do_sample=True,
                pad_token_id=llm_tokenizer.eos_token_id if llm_tokenizer.eos_token_id else llm_tokenizer.pad_token_id
            )
        
        response = llm_tokenizer.decode(
            outputs[0][inputs['input_ids'].shape[1]:], 
            skip_special_tokens=True
        ).strip()
        
        logging.debug(f"LLM Raw Response: {response}")
        
        # Parse JSON response
        is_threat = False
        confidence = 50
        reason = "Unable to parse response"
        
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{[^}]*"is_threat"[^}]*\}', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group(0))
                is_threat = bool(parsed.get('is_threat', False))
                confidence = int(parsed.get('confidence', 50))
                reason = parsed.get('reason', 'No reason provided')
            else:
                # Fallback: keyword-based detection
                response_lower = response.lower()
                is_threat = any(keyword in response_lower for keyword in ['threat', 'malicious', 'attack', 'suspicious', 'anomaly'])
                confidence = 80 if is_threat else 20
                reason = response  # FULL RESPONSE
        except json.JSONDecodeError as e:
            logging.warning(f"JSON parse error: {e}. Response: {response[:100]}")
            # Fallback parsing
            is_threat = 'true' in response.lower()
            confidence = 70 if is_threat else 30
            reason = response  # FULL RESPONSE
        
        return {
            'is_suspicious': is_threat,
            'confidence': confidence,
            'llm_response': reason,
            'llm_trigger': 'dfp_anomaly' if is_dfp_anomaly else 'low_bert_conf',
            'full_log': log_data.get('log')
        }
        
    except Exception as e:
        logging.error(f"LLM error: {e}", exc_info=True)
        return {
            'is_suspicious': False, 
            'confidence': 0, 
            'llm_response': f'error: {str(e)}', 
            'llm_trigger': 'error'
        }

# ============================================================================
# MAIN LOOP
# ============================================================================
stats = {
    'total_consumed': 0,
    'llm_analyzed': 0,
    'skipped_cooldown': 0,
    'skipped_threshold': 0,
    'threats_found': 0
}

try:
    while True:
        msg = consumer.poll(1.0)
        
        if msg is None: 
            continue
        if msg.error():
            logging.error(f"Kafka error: {msg.error()}")
            continue
        
        try:
            log_data = json.loads(msg.value())
        except json.JSONDecodeError:
            continue
        
        stats['total_consumed'] += 1
        
        # Extract Fields
        entity = log_data.get('srcip', '')
        dfp_is_anomaly = log_data.get('dfp_is_anomaly', 0)
        dfp_score = float(log_data.get('dfp_score', 0.0))
        bert_confidence = float(log_data.get('confidence', 1.0))
        
        # Base Enrichment Object
        enrichment = {
            '@timestamp': log_data.get('@timestamp'),
            'srcip': log_data.get('srcip'),
            'dstip': log_data.get('dstip'),
            'original_threat_class': log_data.get('threat_class'),
            'dfp_is_anomaly': dfp_is_anomaly,
            'dfp_score': dfp_score,
            'enrichment_timestamp': datetime.now(timezone(timedelta(hours=7))).isoformat(),
        }

        # ============================================================
        # CHECK 1: THRESHOLD FILTERING
        # ============================================================
        meets_threshold = (
            (dfp_is_anomaly == 1 and dfp_score > DFP_ANOMALY_THRESHOLD) or
            (bert_confidence < BERT_CONFIDENCE_THRESHOLD)
        )
        
        if not meets_threshold:
            enrichment['llm_status'] = 'skipped_threshold'
            enrichment['llm_is_suspicious'] = 0
            stats['skipped_threshold'] += 1
             
            producer.produce(OUTPUT_TOPIC, value=json.dumps(enrichment))
            producer.poll(0)
            continue

        # ============================================================
        # CHECK 2: ENTITY COOLDOWN
        # ============================================================
        current_time = time.time()
        last_analysis_time = entity_cooldown_cache.get(entity, 0)
        
        if (current_time - last_analysis_time) < COOLDOWN_SECONDS:
            enrichment['llm_status'] = 'skipped_cooldown'
            enrichment['llm_is_suspicious'] = 1 
            enrichment['llm_reason'] = 'Duplicate IP within cooldown window'
            
            stats['skipped_cooldown'] += 1
            
            producer.produce(OUTPUT_TOPIC, value=json.dumps(enrichment))
            producer.poll(0)
            continue

        # ============================================================
        # EXECUTE LLM
        # ============================================================
        stats['llm_analyzed'] += 1
        entity_cooldown_cache[entity] = current_time
        
        # Cleanup cache occasionally
        if len(entity_cooldown_cache) > 10000:
            keys_to_remove = list(entity_cooldown_cache.keys())[:5000]
            for k in keys_to_remove: 
                del entity_cooldown_cache[k]

        # Run Analysis
        llm_result = llm_analyze(
            log_data,
            is_dfp_anomaly=(dfp_is_anomaly == 1),
            dfp_score=dfp_score
        )
        
        if llm_result['is_suspicious']:
            stats['threats_found'] += 1
        
        enrichment.update({
            'llm_status': 'analyzed',
            'llm_is_suspicious': int(bool(llm_result.get('is_suspicious', False))),
            'llm_confidence': llm_result.get('confidence', 0),
            'llm_response': llm_result.get('llm_response', ''),
            'llm_trigger': llm_result.get('llm_trigger', 'unknown')
        })
        
        producer.produce(OUTPUT_TOPIC, value=json.dumps(enrichment, ensure_ascii=False))
        producer.poll(0)
        
        logging.info(
            f"LLM ANALYZED: {entity} -> Trigger: {llm_result['llm_trigger']} | "
            f"Suspicious: {llm_result['is_suspicious']} | Confidence: {llm_result['confidence']}"
        )

        # Periodic Stats
        if stats['total_consumed'] % 100 == 0:
            analysis_rate = (stats['llm_analyzed'] / stats['total_consumed'] * 100) if stats['total_consumed'] > 0 else 0
            logging.info(
                f"STATS | Total: {stats['total_consumed']} | "
                f"LLM Calls: {stats['llm_analyzed']} ({analysis_rate:.2f}%) | "
                f"Skipped(Cooldown): {stats['skipped_cooldown']} | "
                f"Threats: {stats['threats_found']}"
            )

except KeyboardInterrupt:
    logging.info("Stopping consumer...")
finally:
    consumer.close()
    producer.flush()
    logging.info(f"Final Stats: {stats}")