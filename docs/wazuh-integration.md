# Wazuh Integration Guide

This guide covers integrating the Morpheus threat detection pipeline with Wazuh SIEM for centralized security monitoring, alerting, and incident response.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Installation](#installation)
- [Rules Configuration](#rules-configuration)
- [Discord Integration](#discord-integration)
- [Active Response](#active-response)
- [Dashboard Setup](#dashboard-setup)
- [Troubleshooting](#troubleshooting)

## Overview

The Wazuh integration provides:
- **Centralized logging** of all enriched threat data
- **Rule-based alerting** for LLM-confirmed threats
- **Active response** for automated threat mitigation
- **Dashboard visualization** of security events
- **Discord notifications** for real-time alerts
- **Incident management** and threat tracking

## Prerequisites

- Wazuh Server 4.x installed
- OpenSearch backend
- Wazuh Dashboard
- Morpheus pipeline running
- LLM enrichment active

## Architecture

### Data Flow
```
Morpheus Pipeline
    ↓ Kafka: morpheus-final-realtime-dfp
morpheus-base-indexer
    ↓ OpenSearch: morpheus-final-realtime-dfp-2
    
LLM Enrichment
    ↓ Kafka: morpheus-llm-enrichment
morpheus-llm-indexer (UPDATE)
    ↓ OpenSearch: morpheus-final-realtime-dfp-2 (same index)
    
Wazuh Manager
    ↓ Monitors index via API
Wazuh Rules Engine
    ↓ Triggers on llm_is_suspicious=1
custom-discord Integration
    ↓ Sends alerts to Discord
```

### Key Components

1. **morpheus-base-indexer**: Indexes full logs with all FortiGate fields
2. **morpheus-llm-indexer**: Updates logs with LLM enrichment (no duplicates)
3. **Wazuh Rules**: Trigger on threat detection
4. **Active Response**: Automated firewall blocking
5. **Discord Integration**: Real-time notifications

## Installation

### Step 1: Create Wazuh Index Pattern
```bash
# Login to Wazuh Dashboard
# Go to Management → Index Patterns

# Create pattern: morpheus-final-realtime-dfp-2
# Time field: @timestamp
```

Or via API:
```bash
curl -k -u admin:password \
  -X POST https://<wazuh-dashboard-ip:9200>/.kibana/_doc/index-pattern:morpheus-final-realtime-dfp-2 \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "index-pattern",
    "index-pattern": {
      "title": "morpheus-final-realtime-dfp-2",
      "timeFieldName": "@timestamp"
    }
  }'
```

### Step 2: Install Indexer Services

#### Base Indexer (Creates Documents)

Already installed in previous steps. Verify:
```bash
sudo systemctl status morpheus-base-indexer
```

#### LLM Indexer (Updates Documents)

Already installed. Verify:
```bash
sudo systemctl status morpheus-llm-indexer
```

### Step 3: Verify Index Settings
```bash
# Check index exists
curl -k -u admin:password \
  https://<wazuh-dashboard-ip:9200>/_cat/indices/morpheus*

# Check document count
curl -k -u admin:password \
  https://<wazuh-dashboard-ip:9200>/morpheus-final-realtime-dfp-2/_count

# Sample document
curl -k -u admin:password \
  https://<wazuh-dashboard-ip:9200>/<morpheus-final-realtime-dfp-2>/_search?size=1 \
  | jq '.hits.hits[0]._source'
```

## Rules Configuration

### Step 1: Create Custom Rules
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
```xml
<group name="morpheus,threat_detection,">
  
  <!-- Rule 100200: LLM-Confirmed Security Threat -->
  <rule id="100200" level="12">
    <field name="llm_status">analyzed</field>
    <field name="llm_is_suspicious">1</field>
    <description>Morpheus AI: LLM-confirmed security threat detected</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100201: LLM Analysis (Informational) -->
  <rule id="100201" level="8">
    <field name="llm_status">analyzed</field>
    <field name="llm_is_suspicious">0</field>
    <description>Morpheus AI: Event analyzed by LLM (non-threatening)</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100202: DFP Behavioral Anomaly -->
  <rule id="100202" level="10">
    <field name="dfp_is_anomaly">1</field>
    <match>dfp_score</match>
    <description>Morpheus AI: Behavioral anomaly detected by DFP</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100203: Port Scan Detected -->
  <rule id="100203" level="11">
    <field name="threat_class">PortScan</field>
    <description>Morpheus AI: Port scan activity detected</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100204: Multi-log Attack Pattern -->
  <rule id="100204" level="11">
    <field name="llm_context">multi_log_pattern</field>
    <description>Morpheus AI: Multi-log attack pattern (brute force/scan)</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100205: High Confidence Threat -->
  <rule id="100205" level="13">
    <field name="llm_is_suspicious">1</field>
    <field name="llm_confidence">^9|^8</field>
    <description>Morpheus AI: High confidence threat (80%+)</description>
    <options>no_full_log</options>
  </rule>

  <!-- Rule 100206: Critical Threat (DFP + LLM Agreement) -->
  <rule id="100206" level="14">
    <field name="dfp_is_anomaly">1</field>
    <field name="llm_is_suspicious">1</field>
    <description>Morpheus AI: CRITICAL - DFP and LLM both confirm threat</description>
    <options>no_full_log</options>
  </rule>

</group>
```

### Rule Levels Explained

- **Level 8**: Informational (logged, no alert)
- **Level 10**: Warning (logged, dashboard alert)
- **Level 11**: Important (logged, dashboard alert)
- **Level 12**: High priority (logged, email alert)
- **Level 13**: Critical (logged, email + active response)
- **Level 14**: Emergency (logged, all alerts + active response)

### Step 2: Test Rules
```bash
# Test rule syntax
sudo /var/ossec/bin/ossec-logtest

# Paste test log:
{"llm_status": "analyzed", "llm_is_suspicious": 1, "llm_confidence": 85, "srcip": "192.168.1.100"}

# Should match rule 100200
```

### Step 3: Restart Wazuh
```bash
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo grep "100200" /var/ossec/logs/ossec.log
```

## Discord Integration

### Step 1: Create Discord Webhook

1. Open Discord server
2. Go to **Server Settings** → **Integrations** → **Webhooks**
3. Click **New Webhook**
4. Name: "Morpheus Security Alerts"
5. Select channel: `#security-alerts`
6. Copy webhook URL

### Step 2: Install Discord Integration
```bash
sudo nano /var/ossec/integrations/custom-discord
```
```python
#!/usr/bin/env python3
"""
Wazuh Discord Integration
Sends security alerts to Discord webhook
"""
import sys
import json
import requests
from datetime import datetime

# Read alert from stdin
alert_file = sys.argv[1]
webhook_url = sys.argv[3]

try:
    with open(alert_file) as f:
        alert = json.load(f)
    
    # Extract alert data
    rule_id = alert.get('rule', {}).get('id', 'N/A')
    rule_level = alert.get('rule', {}).get('level', 0)
    rule_description = alert.get('rule', {}).get('description', 'No description')
    
    # Extract Morpheus data
    data = alert.get('data', {})
    srcip = data.get('srcip', 'Unknown')
    dstip = data.get('dstip', 'Unknown')
    srcname = data.get('srcname', 'Unknown')
    policyname = data.get('policyname', 'Unknown')
    service = data.get('service', 'Unknown')
    
    # LLM data
    llm_response = data.get('llm_response', 'N/A')
    llm_confidence = data.get('llm_confidence', 0)
    dfp_score = data.get('dfp_score', 0.0)
    threat_class = data.get('threat_class', 'Unknown')
    
    # Determine color based on severity
    if rule_level >= 14:
        color = 0xFF0000  # Red - Emergency
        emoji = "🚨"
    elif rule_level >= 12:
        color = 0xFF6600  # Orange - Critical
        emoji = "⚠️"
    elif rule_level >= 10:
        color = 0xFFCC00  # Yellow - Warning
        emoji = "⚡"
    else:
        color = 0x00FF00  # Green - Info
        emoji = "ℹ️"
    
    # Build Discord embed
    embed = {
        "title": f"{emoji} Morpheus Security Alert",
        "description": f"**{rule_description}**",
        "color": color,
        "fields": [
            {
                "name": "🎯 Threat Details",
                "value": f"**Class:** {threat_class}\n**Confidence:** {llm_confidence}%\n**DFP Score:** {dfp_score:.2f}",
                "inline": True
            },
            {
                "name": "🌐 Network Info",
                "value": f"**Source:** {srcip} ({srcname})\n**Destination:** {dstip}\n**Service:** {service}",
                "inline": True
            },
            {
                "name": "📋 Policy",
                "value": f"**Policy:** {policyname}\n**Rule ID:** {rule_id}\n**Level:** {rule_level}",
                "inline": False
            },
            {
                "name": "🤖 LLM Analysis",
                "value": llm_response[:1000] if llm_response != 'N/A' else "No LLM analysis available",
                "inline": False
            }
        ],
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {
            "text": "Morpheus AI Threat Detection"
        }
    }
    
    # Send to Discord
    payload = {
        "embeds": [embed]
    }
    
    response = requests.post(webhook_url, json=payload, timeout=10)
    
    if response.status_code == 204:
        sys.exit(0)
    else:
        sys.exit(1)

except Exception as e:
    sys.stderr.write(f"Discord integration error: {str(e)}\n")
    sys.exit(1)
```

Make executable:
```bash
sudo chmod +x /var/ossec/integrations/custom-discord
sudo chown root:wazuh /var/ossec/integrations/custom-discord
```

### Step 3: Configure Integration
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside `<ossec_config>`:
```xml
<integration>
  <name>custom-discord</name>
  <hook_url>YOUR_DISCORD_WEBHOOK_URL_HERE</hook_url>
  <level>10</level>
  <rule_id>100200,100203,100204,100205,100206</rule_id>
  <alert_format>json</alert_format>
</integration>
```

**Replace** `YOUR_DISCORD_WEBHOOK_URL_HERE` with your actual webhook URL.

### Step 4: Test Discord Integration
```bash
# Restart Wazuh
sudo systemctl restart wazuh-manager

# Send test alert
sudo /var/ossec/bin/ossec-makelists

# Or manually test
sudo /var/ossec/integrations/custom-discord \
  /var/ossec/logs/alerts/alerts.json \
  "" \
  "YOUR_WEBHOOK_URL"
```

Check Discord for the alert!

## Active Response

### Step 1: Create Active Response Script
```bash
sudo nano /var/ossec/active-response/bin/firewall-block.sh
```
```bash
#!/bin/bash
# Block IP address using iptables

ACTION=$1
USER=$2
IP=$3
ALERT_ID=$4
RULE_ID=$5

LOCAL=`dirname $0`
cd $LOCAL
cd ../

# Logging
echo "`date` $0 $1 $2 $3 $4 $5" >> ${PWD}/active-responses.log

# Get action
if [ "x${ACTION}" = "xadd" ]; then
    # Block IP
    iptables -I INPUT -s ${IP} -j DROP
    echo "`date` Blocked ${IP}" >> ${PWD}/active-responses.log
    
elif [ "x${ACTION}" = "xdelete" ]; then
    # Unblock IP
    iptables -D INPUT -s ${IP} -j DROP
    echo "`date` Unblocked ${IP}" >> ${PWD}/active-responses.log
fi

exit 0
```

Make executable:
```bash
sudo chmod +x /var/ossec/active-response/bin/firewall-block.sh
sudo chown root:wazuh /var/ossec/active-response/bin/firewall-block.sh
```

### Step 2: Configure Active Response
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside `<ossec_config>`:
```xml
<!-- Active Response Command -->
<command>
  <name>firewall-block</name>
  <executable>firewall-block.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Active Response for Critical Threats -->
<active-response>
  <command>firewall-block</command>
  <location>local</location>
  <rules_id>100206</rules_id>
  <timeout>1800</timeout>
</active-response>

<!-- Active Response for High Confidence Threats -->
<active-response>
  <command>firewall-block</command>
  <location>local</location>
  <rules_id>100205</rules_id>
  <timeout>900</timeout>
</active-response>
```

**Explanation**:
- Rule 100206 (Critical): Block for 30 minutes
- Rule 100205 (High confidence): Block for 15 minutes

### Step 3: Test Active Response
```bash
# Restart Wazuh
sudo systemctl restart wazuh-manager

# Check active response logs
sudo tail -f /var/ossec/active-responses.log

# Manually trigger (for testing)
sudo /var/ossec/active-response/bin/firewall-block.sh add - 192.168.1.100 1234 100206

# Check if blocked
sudo iptables -L INPUT | grep 192.168.1.100

# Unblock
sudo /var/ossec/active-response/bin/firewall-block.sh delete - 192.168.1.100 1234 100206
```

## Email Alerts

### Configure SMTP
```bash
sudo nano /var/ossec/etc/ossec.conf
```
```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.gmail.com</smtp_server>
  <email_from>security@yourcompany.com</email_from>
  <email_to>soc-team@yourcompany.com</email_to>
  <email_maxperhour>50</email_maxperhour>
</global>

<email_alerts>
  <email_to>soc-team@yourcompany.com</email_to>
  <level>12</level>
  <do_not_delay />
  <do_not_group />
</email_alerts>
```

For Gmail, use app password (not regular password).

## Dashboard Setup

### Step 1: Create Visualizations

1. Login to Wazuh Dashboard
2. Go to **Dashboard** → **Create New**

#### Visualization 1: Threat Timeline
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"llm_is_suspicious": 1}}
      ]
    }
  },
  "aggs": {
    "threats_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "1h"
      }
    }
  }
}
```

#### Visualization 2: Top Threat Sources
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"llm_is_suspicious": 1}}
      ]
    }
  },
  "aggs": {
    "top_sources": {
      "terms": {
        "field": "srcip.keyword",
        "size": 10
      }
    }
  }
}
```

#### Visualization 3: Threat Classes Distribution
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"is_threat": 1}}
      ]
    }
  },
  "aggs": {
    "threat_types": {
      "terms": {
        "field": "threat_class.keyword",
        "size": 10
      }
    }
  }
}
```

#### Visualization 4: LLM Confidence Distribution
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"llm_status": "analyzed"}}
      ]
    }
  },
  "aggs": {
    "confidence_histogram": {
      "histogram": {
        "field": "llm_confidence",
        "interval": 10
      }
    }
  }
}
```

### Step 2: Create Dashboard

Combine visualizations into dashboard:

1. **Dashboard** → **Create Dashboard**
2. Add visualizations:
   - Threat Timeline (line chart)
   - Top Threat Sources (bar chart)
   - Threat Classes (pie chart)
   - LLM Confidence (histogram)
   - Recent Threats (data table)
3. Save as "Morpheus Threat Detection"

## Monitoring

### Check Services
```bash
# All Morpheus services
sudo systemctl status morpheus-pipeline
sudo systemctl status morpheus-llm-enricher
sudo systemctl status morpheus-base-indexer
sudo systemctl status morpheus-llm-indexer

# Wazuh services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Monitor Logs
```bash
# Wazuh alerts
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .

# Active response
sudo tail -f /var/ossec/logs/active-responses.log

# Integration logs
sudo tail -f /var/ossec/logs/integrations.log
```

### Check Alert Statistics
```bash
# Count alerts by rule
curl -k -u admin:password \
  https://<wazuh-dashboard-ip:9200>/wazuh-alerts-*/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "by_rule": {
        "terms": {
          "field": "rule.id",
          "size": 10
        }
      }
    }
  }' | jq .
```

## Best Practices

1. **Rule Tuning**: Adjust rule levels based on false positive rate
2. **Alert Fatigue**: Use levels 12+ for actionable alerts only
3. **Active Response**: Test thoroughly before production
4. **Discord Channels**: Separate channels by severity
5. **Email Limits**: Set `email_maxperhour` to prevent flooding
6. **Dashboard Updates**: Refresh visualizations regularly
7. **Backup Rules**: Version control all custom rules
8. **Index Retention**: Set appropriate data retention (30-90 days)

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues.

### Quick Checks
```bash
# Check if alerts are generating
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep "100200"

# Check Discord integration
sudo /var/ossec/integrations/custom-discord --help

# Check active response
sudo tail -f /var/ossec/logs/active-responses.log

# Check index health
curl -k -u admin:password \
  https://<wazuh-dashboard-ip>/_cluster/health?pretty
```

## Next Steps

- [Monitoring Guide](monitoring.md) - Set up comprehensive monitoring
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [Architecture](architecture.md) - Understand the complete system

## References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [OpenSearch Documentation](https://opensearch.org/docs/)
- [Wazuh Rules](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
