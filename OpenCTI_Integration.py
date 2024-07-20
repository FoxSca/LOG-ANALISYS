import requests
import json
import logging

# Author: Fabio Scardino
# Description: This script sends alerts to OpenCTI.

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# OpenCTI configuration
OPENCTI_URL = 'your_opencti_url'
OPENCTI_API_KEY = 'your_opencti_api_key'

def send_opencti_alert(event_data):
    headers = {
        'Authorization': f'Bearer {OPENCTI_API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.post(f'{OPENCTI_URL}/api/indicators', headers=headers, data=json.dumps(event_data))
    
    if response.status_code == 200:
        logger.info("Alert successfully sent to OpenCTI.")
    else:
        logger.error(f"Failed to send alert to OpenCTI: {response.text}")

def create_opencti_event(message):
    event = {
        "name": "Suspicious activity detected",
        "description": message,
        "pattern_type": "stix",
        "pattern": "[file:hashes.'SHA-256' = 'your-file-hash']",
        "valid_from": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }
    return event

def handle_opencti_alert(message):
    event_data = create_opencti_event(message)
    send_opencti_alert(event_data)
