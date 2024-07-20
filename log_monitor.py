import os
import time
import logging
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot
from collections import defaultdict
import requests
import json
from elasticsearch import Elasticsearch
import re
import configparser

# Author: Fabio Scardino
# Description: This script monitors a log file for suspicious activities and sends alerts via Telegram, MISP, Elasticsearch, and OpenCTI.

# Configuration setup
config = configparser.ConfigParser()
config.read('config.ini')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Telegram configuration
TELEGRAM_TOKEN = config['TELEGRAM']['TOKEN']
CHAT_ID = config['TELEGRAM']['CHAT_ID']

bot = Bot(token=TELEGRAM_TOKEN)

def send_telegram_message(message):
    try:
        bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")

# MISP configuration
MISP_URL = config['MISP']['URL']
MISP_API_KEY = config['MISP']['API_KEY']
VERIFY_SSL = config['MISP'].getboolean('VERIFY_SSL')

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

# Elasticsearch configuration
ELASTICSEARCH_HOST = config['ELASTICSEARCH']['HOST']
ELASTICSEARCH_PORT = config['ELASTICSEARCH'].getint('PORT')
INDEX_NAME = config['ELASTICSEARCH']['INDEX_NAME']

es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': ELASTICSEARCH_PORT}])

def send_elasticsearch_alert(message):
    doc = {
        'message': message,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }
    response = es.index(index=INDEX_NAME, body=doc)
    
    if response['result'] == 'created':
        logger.info("Alert successfully sent to Elasticsearch.")
    else:
        logger.error(f"Failed to send alert to Elasticsearch: {response}")

def handle_elasticsearch_alert(message):
    send_elasticsearch_alert(message)

# OpenCTI configuration
OPENCTI_URL = config['OPENCTI']['URL']
OPENCTI_API_KEY = config['OPENCTI']['API_KEY']

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

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, destinations):
        self.log_file = log_file
        self.log_file_size = os.path.getsize(self.log_file)
        self.failed_attempts = defaultdict(int)
        self.suspicious_ips = defaultdict(int)
        self.destinations = destinations

    def on_modified(self, event):
        if event.src_path == self.log_file:
            current_size = os.path.getsize(self.log_file)
            if current_size > self.log_file_size:
                with open(self.log_file, 'r') as f:
                    f.seek(self.log_file_size)
                    new_lines = f.read()
                    self.analyze_log(new_lines)
                self.log_file_size = current_size

    def analyze_log(self, new_lines):
        for line in new_lines.split('\n'):
            if line:
                if self.is_heuristic_attack(line):
                    ip_address = self.extract_ip(line)
                    if ip_address:
                        self.suspicious_ips[ip_address] += 1
                        message = f'Heuristic attack detected from IP {ip_address}: {line}'
                        logger.info(message)
                        send_telegram_message(message)
                        if 'misp' in self.destinations:
                            handle_misp_alert(message)
                        if 'elasticsearch' in self.destinations:
                            handle_elasticsearch_alert(message)
                        if 'opencti' in self.destinations:
                            handle_opencti_alert(message)

    def is_heuristic_attack(self, log_entry):
        """
        Implement heuristic detection logic here.
        Example: Detect repeated failed login attempts, traversal, lateral attacks, and file uploads.
        """
        # Example pattern for a failed login attempt
        if 'failed login' in log_entry.lower():
            ip_address = self.extract_ip(log_entry)
            if ip_address:
                self.failed_attempts[ip_address] += 1
                if self.failed_attempts[ip_address] > 5:  # Threshold for failed attempts
                    return True
        
        # Detect suspicious activity
        if 'suspicious activity' in log_entry.lower():
            return True
        
        # Detect unusual access times
        if 'accessed at unusual time' in log_entry.lower():
            return True
        
        # Detect directory traversal attack patterns
        if self.is_traversal_attack(log_entry):
            return True
        
        # Detect lateral movement attack patterns
        if self.is_lateral_attack(log_entry):
            return True
        
        # Detect file upload patterns
        if self.is_file_upload(log_entry):
            return True

        return False

    def is_traversal_attack(self, log_entry):
        """
        Detect directory traversal attack patterns.
        """
        traversal_patterns = self.load_patterns('traversal_patterns.txt')
        for pattern in traversal_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_lateral_attack(self, log_entry):
        """
        Detect lateral movement attack patterns.
        """
        lateral_patterns = self.load_patterns('lateral_patterns.txt')
        for pattern in lateral_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_file_upload(self, log_entry):
        """
        Detect file upload patterns.
        """
        upload_patterns = self.load_patterns('upload_patterns.txt')
        for pattern in upload_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def extract_ip(self, log_entry):
        """
        Extract IP address from a log entry.
        Example implementation; adjust regex based on log format.
        """
        ip_pattern = re.compile(r
