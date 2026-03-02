#!/usr/bin/env python3
import time
import requests
from opensearchpy import OpenSearch
from datetime import datetime

# CONFIG

OPENSEARCH_HOST = "https://192.168.19.80:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASS = "password"
INDEX_NAME = "morpheus-final-realtime-dfp-2"

DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_URL"
POLL_INTERVAL = 15  # seconds

# OpenSearch Client

client = OpenSearch(
    hosts=[OPENSEARCH_HOST],
    http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
    use_ssl=True,
    verify_certs=False
)

seen_ids = set()

# Query: ONLY llm_is_suspicious AND llm_response exists

def poll_latest():
    q = {
        "size": 10,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    { "term": { "llm_is_suspicious": 1 } },
                    { "exists": { "field": "llm_response" } },
		    { "exists": { "field": "event.original" } }
                ]
            }
        }
    }

    r = client.search(index=INDEX_NAME, body=q)
    return r["hits"]["hits"]

# Discord Sender

def send_to_discord(src):
    if src.get("llm_is_suspicious") != 1 or not src.get("llm_response"):
        return

    # LLM 
    llm_response   = src.get("llm_response", "No LLM analysis")
    llm_confidence = int(src.get("llm_confidence", 0))
    llm_trigger    = src.get("llm_trigger", "unknown")
    llm_flag       = int(src.get("llm_is_suspicious", 0))

    # Network 
    srcip   = src.get("srcip", "N/A")
    dstip   = src.get("dstip", "N/A")
    srcport = src.get("srcport", "N/A")
    dstport = src.get("dstport", "N/A")
    proto   = src.get("proto", "N/A")
    app     = src.get("app", "N/A")
    action  = src.get("action", "N/A")

    # Traffic Stats 
    sent = int(src.get("sentbyte") or 0)
    recv = int(src.get("rcvdbyte") or 0)
    duration = src.get("duration", "N/A")

    # Firewall Policy 
    policy_id   = src.get("policyid", "N/A")
    policy_name = src.get("policyname", "N/A")
    srcintf     = src.get("srcintf", "N/A")
    dstintf     = src.get("dstintf", "N/A")

    # DFP 
    dfp_flag  = int(src.get("dfp_is_anomaly", 0))
    dfp_score = src.get("dfp_score", "N/A")
    threat_class = src.get("threat_class", "N/A")

    # Severity 
    severity = "LOW"
    color = 0xFFCC00
    emoji = "💡"

    if llm_confidence >= 90:
        severity = "CRITICAL"
        color = 0x8B0000
        emoji = "🚨"
    elif llm_confidence >= 70:
        severity = "HIGH"
        color = 0xFF0000
        emoji = "⚠️"
    elif llm_confidence >= 50:
        severity = "MEDIUM"
        color = 0xFF6600
        emoji = "⚡"

    embed = {
        "title": f"{emoji} Morpheus AI Alert — {severity}",
        "color": color,
        "description": f"**🤖 LLM Analysis:**\n{llm_response}",
        "fields": [
            {
                "name": "🔎 Detection Signals",
                "value": (
                    f"**LLM Suspicious:** `{llm_flag}`\n"
                    f"**LLM Confidence:** `{llm_confidence}%`\n"
                    f"**Trigger:** `{llm_trigger}`"
                ),
                "inline": False
            },
            {
                "name": "🌐 Network Traffic",
                "value": (
                    f"**Src:** `{srcip}:{srcport}`\n"
                    f"**Dst:** `{dstip}:{dstport}`\n"
                    f"**Proto:** `{proto}`\n"
                    f"**App:** `{app}`\n"
                    f"**Action:** `{action}`"
                ),
                "inline": False
            },
            {
                "name": "📊 Traffic Stats",
                "value": (
                    f"**Sent:** `{round(sent/1024,2)} KB`\n"
                    f"**Received:** `{round(recv/1024,2)} KB`\n"
                    f"**Duration:** `{duration}`"
                ),
                "inline": False
            },
            {
                "name": "🔍 Firewall Policy",
                "value": (
                    f"**Policy ID:** `{policy_id}`\n"
                    f"**Policy Name:** `{policy_name}`\n"
                    f"**Src Intf:** `{srcintf}`\n"
                    f"**Dst Intf:** `{dstintf}`"
                ),
                "inline": False
            },
            {
                "name": "🧬 DFP Analysis",
                "value": (
                    f"**Anomaly:** `{'YES ⚠️' if dfp_flag else 'NO'}`\n"
                    f"**DFP Score:** `{dfp_score}`\n"
                    f"**Original Class:** `{threat_class}`"
                ),
                "inline": False
            }
        ],
        "footer": {
            "text": "Morpheus Hybrid DFP + LLM via Wazuh"
        },

    }

    payload = {"embeds": [embed]}
    requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)

# Main Loop

def main():
    print("Polling OpenSearch index:", INDEX_NAME)
    while True:
        try:
            hits = poll_latest()
            for h in hits:
                doc_id = h["_id"]
                if doc_id in seen_ids:
                    continue

                seen_ids.add(doc_id)
                send_to_discord(h["_source"])

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print("Poll error:", e)
            time.sleep(10)

if __name__ == "__main__":
    main()
