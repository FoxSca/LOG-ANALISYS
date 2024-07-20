This comprehensive log monitoring system is designed to detect and alert on various security threats and anomalies in log files. The system can be configured to send alerts to multiple destinations, including Telegram, MISP, Elasticsearch, and OpenCTI. The script includes a graphical user interface (GUI) to simplify configuration and management.
Key Features

    Log Monitoring: Continuously monitors specified log files for suspicious activities, including SQL Injection attacks, failed access attempts, and various attack patterns.

    Advanced Detection: Utilizes pattern files to identify specific attack vectors and anomalies, such as SQL Injection attempts and unusual behaviors.

    Alert Integration: Supports sending alerts to different platforms, including Telegram, MISP, Elasticsearch, and OpenCTI, based on user preferences.

    User-Friendly GUI: Provides an intuitive graphical interface for configuring log files, selecting alert destinations, and starting/stopping monitoring.

    Customizable Patterns: Allows users to define their own detection patterns for different types of attacks and anomalies.

Pattern Files

The system uses several pattern files to detect various types of attacks and anomalies. Create these pattern files in the same directory as the script:

    traversal_patterns.txt: Contains patterns for detecting directory traversal attacks.
    lateral_patterns.txt: Contains patterns for detecting lateral movement attacks.
    upload_patterns.txt: Contains patterns for detecting file upload attacks.
    sql_patterns.txt: Contains patterns for detecting SQL Injection attacks.
    anomalous_patterns.txt: Contains patterns for detecting anomalies in log data.

Installation and Setup

    Create Pattern Files:

        Save the following pattern files in the same directory as the script:

        traversal_patterns.txt

        text

../
..\
%2e%2e%2f
%2e%2e%5c
..%c0%af
..%c1%9c

lateral_patterns.txt

text

remote desktop protocol (rdp)
smb
ps exec
powershell remoting
wmi
admin$
c$

upload_patterns.txt

text

file uploaded
upload complete
uploaded successfully
file transfer

sql_patterns.txt

text

union select
select * from
select.+from
select.+where
select.+union
union all select
union.+select
union.+all.+select
select.+into.+outfile
select.+into.+dumpfile
union.+all.+select
select.+from.+information_schema.tables
select.+from.+mysql.db
select.+from.+pg_catalog.pg_tables
select.+from.+sysobjects
select.+from.+sys.databases
select.+from.+sys.tables
select.+from.+sqlite_master
select.+from.+db2inst1.syscat.tables
select.+from.+db2inst1.systables
select.+from.+oracle.dba_tables
select.+from.+oracle.all_tables
select.+from.+oracle.user_tables
select.+from.+mysql.columns
select.+from.+mysql.tables
select.+from.+mysql.schemata
select.+from.+information_schema.columns
select.+from.+information_schema.tables
select.+from.+pg_tables
select.+from.+pg_views
select.+from.+pg_indexes
select.+from.+pg_class
select.+from.+pg_proc
select.+from.+pg_user
select.+from.+pg_roles
select.+from.+pg_database
select.+from.+pg_namespace
select.+from.+pg_sequence
select.+from.+pg_trigger
select.+from.+pg_type
select.+from.+pg_language
select.+from.+pg_stats
select.+from.+pg_aggregate
select.+from.+pg_am
select.+from.+pg_operator
select.+from.+pg_range
select.+from.+pg_rewrite
select.+from.+pg_shdescription
select.+from.+pg_shdepend
select.+from.+pg_table_def
select.+from.+pg_tablespace
select.+from.+pg_subscription
select.+from.+pg_publication
select.+from.+pg_inherits
select.+from.+pg_extension
select.+from.+pg_foreign_data_wrapper
select.+from.+pg_foreign_server
select.+from.+pg_user_mappings
select.+from.+pg_foreign_table
select.+from.+pg_foreign_table
select.+from.+pg_default_acl
select.+from.+pg_default_acl
select.+from.+pg_event_trigger
select.+from.+pg_pltemplate
select.+from.+pg_locks
select.+from.+pg_stat_activity
select.+from.+pg_stat_replication
select.+from.+pg_stat_statements
select.+from.+pg_stat_sys_tables
select.+from.+pg_stat_sys_indexes
select.+from.+pg_stat_user_tables
select.+from.+pg_stat_user_indexes
select.+from.+pg_stat_database
select.+from.+pg_stat_archiver
select.+from.+pg_stat_ssl
select.+from.+pg_stat_bgwriter
select.+from.+pg_stat_wal_receiver
select.+from.+pg_stat_wal_senders
select.+from.+pg_stat_progress_vacuum
select.+from.+pg_stat_progress_analyze
select.+from.+pg_stat_progress_create_index
select.+from.+pg_stat_progress_basebackup
select.+from.+pg_stat_progress_create_subscription
select.+from.+pg_stat_progress_create_extension
select.+from.+pg_stat_progress_cluster
select.+from.+pg_stat_progress_analyze
select.+from.+pg_stat_progress_vacuum
select.+from.+pg_stat_progress_basebackup
select.+from.+pg_stat_progress_create_index
select.+from.+pg_stat_progress_create_subscription
select.+from.+pg_stat_progress_create_extension
select.+from.+pg_stat_progress_wal_receiver
select.+from.+pg_stat_progress_wal_senders

anomalous_patterns.txt

text

    unusual access times
    repeated failed login attempts
    suspicious activity
    unusual patterns
    unauthorized access
    abnormal request rate
    unexpected errors
    irregular user behavior
    abnormal system calls
    anomalous access patterns

Install Dependencies:

    Create a requirements.txt file with the following content:

    text

watchdog
python-telegram-bot
requests
elasticsearch
opencti

Install the required libraries using:

bash

    pip install -r requirements.txt

Configure:

    Create a config.ini file with the following sections:

    ini

    [telegram]
    token = your_telegram_bot_token
    chat_id = your_chat_id

    [misp]
    url = your_misp_url
    key = your_misp_key

    [elasticsearch]
    url = your_elasticsearch_url

    [opencti]
    url = your_opencti_url
    token = your_opencti_token

Run the Script:

    Execute the script using:

    bash

        python gui_log_monitor.py

    Using the GUI:
        Log File Path: Enter the path to the log file you want to monitor.
        Destinations: Select the alert destinations (Telegram, MISP, Elasticsearch, OpenCTI) where you want to send notifications.
        Start Monitoring: Click "Start Monitoring" to begin the log monitoring process.

Script Flow

    Initialization: The script initializes logging, loads configuration settings, and sets up the GUI.

    GUI Interaction: Users input the log file path and select alert destinations via the GUI.

    Log Monitoring: The script monitors the log file for specific patterns related to SQL Injection, directory traversal, lateral movement, file uploads, and anomalies.

    Pattern Matching: Logs are analyzed for predefined patterns. Alerts are generated based on the detected patterns and user-selected destinations.

    Alerts: Notifications are sent to the configured destinations, and the monitoring status is displayed in the GUI.

This system provides a robust solution for real-time log analysis and threat detection, integrating various alerting mechanisms to ensure comprehensive security coverage.
