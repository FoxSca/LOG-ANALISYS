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
            if self.is_heuristic_attack(line):
                logger.info(f'Heuristic attack detected: {line}')
                send_telegram_message(f'Heuristic attack detected: {line}')

    def is_heuristic_attack(self, log_entry):
        """
        Implement heuristic detection logic here.
        Example: Detect repeated failed login attempts.
        """
        # Example pattern for a failed login attempt
        if 'failed login' in log_entry.lower():
            ip_address = self.extract_ip(log_entry)
            self.failed_attempts[ip_address] += 1
            if self.failed_attempts[ip_address] > 5:  # Threshold for failed attempts
                return True
        
        # Add more heuristic checks here
        if 'suspicious activity' in log_entry.lower():
            return True
        
        # Example of checking for unusual access times
        if 'accessed at unusual time' in log_entry.lower():
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
