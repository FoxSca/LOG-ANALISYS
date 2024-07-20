import os
import time
import logging
import json
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot
from collections import defaultdict
import requests
from elasticsearch import Elasticsearch
import configparser

# Author: Fabio Scardino
# Description: This script monitors a log file for suspicious activities and sends alerts via Telegram, MISP, Elasticsearch, and OpenCTI.

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration setup
config = configparser.ConfigParser()
config.read('config.ini')

# Setup external services
TELEGRAM_TOKEN = config['TELEGRAM']['TOKEN']
CHAT_ID = config['TELEGRAM']['CHAT_ID']
MISP_URL = config['MISP']['URL']
MISP_API_KEY = config['MISP']['API_KEY']
VERIFY_SSL = config['MISP'].getboolean('VERIFY_SSL')
ELASTICSEARCH_HOST = config['ELASTICSEARCH']['HOST']
ELASTICSEARCH_PORT = config['ELASTICSEARCH'].getint('PORT')
INDEX_NAME = config['ELASTICSEARCH']['INDEX_NAME']
OPENCTI_URL = config['OPENCTI']['URL']
OPENCTI_API_KEY = config['OPENCTI']['API_KEY']

bot = Bot(token=TELEGRAM_TOKEN)
es = Elasticsearch([{'host': ELASTICSEARCH_HOST, 'port': ELASTICSEARCH_PORT}])

def send_telegram_message(message):
    try:
        bot.send_message(chat_id=CHAT_ID, text=message)
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")

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

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file, destinations):
        self.log_file = log_file
        self.log_file_size = os.path.getsize(self.log_file)
        self.failed_attempts = defaultdict(int)
        self.suspicious_ips = defaultdict(int)
        self.destinations = destinations
        self.sql_patterns = self.load_patterns('sql_patterns.txt')
        self.anomalous_patterns = self.load_patterns('anomalous_patterns.txt')
        self.traversal_patterns = self.load_patterns('traversal_patterns.txt')
        self.lateral_patterns = self.load_patterns('lateral_patterns.txt')
        self.upload_patterns = self.load_patterns('upload_patterns.txt')

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
                if self.is_suspicious_activity(line):
                    ip_address = self.extract_ip(line)
                    if ip_address:
                        self.suspicious_ips[ip_address] += 1
                        message = f'Suspicious activity detected from IP {ip_address}: {line}'
                        logger.info(message)
                        if 'telegram' in self.destinations:
                            send_telegram_message(message)
                        if 'misp' in self.destinations:
                            send_misp_alert({'message': message})
                        if 'elasticsearch' in self.destinations:
                            send_elasticsearch_alert(message)
                        if 'opencti' in self.destinations:
                            send_opencti_alert({'message': message})

    def is_suspicious_activity(self, log_entry):
        return (self.is_sql_injection(log_entry) or
                self.is_heuristic_attack(log_entry) or
                self.is_anomalous_pattern(log_entry))

    def is_sql_injection(self, log_entry):
        for pattern in self.sql_patterns:
            if re.search(pattern, log_entry, re.IGNORECASE):
                return True
        return False

    def is_anomalous_pattern(self, log_entry):
        for pattern in self.anomalous_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_heuristic_attack(self, log_entry):
        if 'failed login' in log_entry.lower():
            ip_address = self.extract_ip(log_entry)
            if ip_address:
                self.failed_attempts[ip_address] += 1
                if self.failed_attempts[ip_address] > 5:
                    return True
        
        if 'suspicious activity' in log_entry.lower():
            return True
        
        if 'accessed at unusual time' in log_entry.lower():
            return True
        
        if self.is_traversal_attack(log_entry):
            return True
        
        if self.is_lateral_attack(log_entry):
            return True
        
        if self.is_file_upload(log_entry):
            return True

        return False

    def is_traversal_attack(self, log_entry):
        for pattern in self.traversal_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_lateral_attack(self, log_entry):
        for pattern in self.lateral_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_file_upload(self, log_entry):
        for pattern in self.upload_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def extract_ip(self, log_entry):
        ip_pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
        match = ip_pattern.search(log_entry)
        if match:
            return match.group(0)
        return None

    def load_patterns(self, filename):
        with open(filename, 'r') as file:
            return [line.strip() for line in file]

# GUI Application
class LogMonitorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Log File Monitor")
        self.geometry("400x300")
        
        self.log_file_path = ""
        self.destinations = []

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Log File Path:").pack(pady=10)
        
        self.log_file_entry = tk.Entry(self, width=50)
        self.log_file_entry.pack(pady=5)

        tk.Button(self, text="Browse", command=self.browse_log_file).pack(pady=5)

        tk.Label(self, text="Select Destinations:").pack(pady=10)

        self.telegram_var = tk.BooleanVar()
        self.misp_var = tk.BooleanVar()
        self.elasticsearch_var = tk.BooleanVar()
        self.opencti_var = tk.BooleanVar()

        tk.Checkbutton(self, text="Telegram", variable=self.telegram_var).pack(anchor='w')
        tk.Checkbutton(self, text="MISP", variable=self.misp_var).pack(anchor='w')
        tk.Checkbutton(self, text="Elasticsearch", variable=self.elasticsearch_var).pack(anchor='w')
        tk.Checkbutton(self, text="OpenCTI", variable=self.opencti_var).pack(anchor='w')

        tk.Button(self, text="Start Monitoring", command=self.start_monitoring).pack(pady=20)

    def browse_log_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log")])
        if file_path:
            self.log_file_path = file_path
            self.log_file_entry.delete(0, tk.END)
            self.log_file_entry.insert(0, file_path)

    def start_monitoring(self):
        if not self.log_file_path:
            messagebox.showwarning("Warning", "Please select a log file.")
            return
        
        self.destinations = []
        if self.telegram_var.get():
            self.destinations.append('telegram')
        if self.misp_var.get():
            self.destinations.append('misp')
        if self.elasticsearch_var.get():
            self.destinations.append('elasticsearch')
        if self.opencti_var.get():
            self.destinations.append('opencti')

        if not self.destinations:
            messagebox.showwarning("Warning", "Please select at least one destination.")
            return

        event_handler = LogFileHandler(self.log_file_path, self.destinations)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(self.log_file_path), recursive=False)
        observer.start()
        self.check_observer_running(observer)

    def check_observer_running(self, observer):
        if observer.is_alive():
            messagebox.showinfo("Monitoring", "Log monitoring started.")
            self.after(1000, self.check_observer_running, observer)
        else:
            messagebox.showwarning("Stopped", "Log monitoring stopped.")

if __name__ == "__main__":
    app = LogMonitorGUI()
    app.mainloop()
