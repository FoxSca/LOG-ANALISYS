import requests
import json
import logging

# Author: Fabio Scardino
# Description: This script sends alerts to MISP.

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# MISP configuration
MISP_URL = 'your_misp_url'
MISP_API_KEY = 'your_misp_api_key'
VERIFY_SSL = False

def send_misp_alert(event_data):
    headers = {
        'Authorization': MISP_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.post(f'{MISP_URL}/events', headers=headers, data=json.dumps(event_data), verify=VERIFY_SSL)
    
    if response.status_code == 200:
        logger.info("Alert successfully sent to MISP.")
    else:
        logger.error(f"Failed to send alert to MISP: {response.text}")

def create_misp_event(message):
    event = {
        "Event": {
            "info": "Suspicious activity detected",
            "distribution": 0,
            "threat_level_id": 3,
            "analysis": 0,
            "Attribute": [
                {
                    "type": "text",
                    "category": "External analysis",
                    "value": message
                }
            ]
        }
    }
    return event

def handle_misp_alert(message):
    event_data = create_misp_event(message)
    send_misp_alert(event_data)
