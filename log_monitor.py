import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot
from collections import defaultdict

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Telegram configuration
TELEGRAM_TOKEN = 'your_telegram_bot_token'
CHAT_ID = 'your_chat_id'

bot = Bot(token=TELEGRAM_TOKEN)

def send_telegram_message(message):
    bot.send_message(chat_id=CHAT_ID, text=message)

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_file_size = os.path.getsize(self.log_file)
        self.failed_attempts = defaultdict(int)
        self.suspicious_ips = defaultdict(int)

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
                        logger.info(f'Heuristic attack detected from IP {ip_address}: {line}')
                        send_telegram_message(f'Heuristic attack detected from IP {ip_address}: {line}')

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
        traversal_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '..%c0%af', '..%c1%9c']
        for pattern in traversal_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_lateral_attack(self, log_entry):
        """
        Detect lateral movement attack patterns.
        """
        lateral_patterns = [
            'remote desktop protocol (rdp)',
            'smb',
            'ps exec',
            'powershell remoting',
            'wmi',
            'admin$',
            'c$'
        ]
        for pattern in lateral_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def is_file_upload(self, log_entry):
        """
        Detect file upload patterns.
        """
        upload_patterns = [
            'file uploaded',
            'upload complete',
            'uploaded successfully',
            'file transfer'
        ]
        for pattern in upload_patterns:
            if pattern in log_entry.lower():
                return True
        return False

    def extract_ip(self, log_entry):
        """
        Extract IP address from a log entry.
        Example implementation; adjust regex based on log format.
        """
        import re
        ip_pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
        match = ip_pattern.search(log_entry)
        if match:
            return match.group(0)
        return None

if __name__ == "__main__":
    log_file_path = 'path_to_your_log_file.log'
    
    event_handler = LogFileHandler(log_file_path)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(log_file_path), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
