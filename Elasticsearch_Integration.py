from elasticsearch import Elasticsearch
import logging

# Author: Fabio Scardino
# Description: This script sends alerts to Elasticsearch.

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Elasticsearch configuration
ELASTICSEARCH_HOST = 'your_elasticsearch_host'
ELASTICSEARCH_PORT = 9200
INDEX_NAME = 'alerts'

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
