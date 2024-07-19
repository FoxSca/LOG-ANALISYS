This Python script monitors a specified log file in real-time to detect heuristic, traversal, lateral attacks, and file uploads. When such events are detected, the script sends alerts to a specified Telegram chat. The script uses the watchdog library to monitor file changes and the python-telegram-bot library to send Telegram messages.
Prerequisites

    Python: Ensure Python is installed on your system.
    Telegram Bot: Create a Telegram bot via BotFather on Telegram and obtain the bot token. Obtain your chat ID by sending a message to your bot or using a tool like IDBot.
    Dependencies: Install the required Python packages using pip:

    bash

pip install python-telegram-bot watchdog

Explanation of the Script

    Imports and Logging:
        Import necessary libraries (os, time, logging, watchdog, telegram, collections).
        Set up logging to monitor script activity.

    Telegram Bot Configuration:
        Configure the Telegram bot with your bot token and chat ID.
        send_telegram_message function sends a message to your specified Telegram chat.

    Log File Handler:
        LogFileHandler class monitors changes to the log file.
        on_modified method checks for new log entries when the file is modified.
        analyze_log method analyzes new log entries for heuristic attack patterns.
        is_heuristic_attack method contains heuristic detection logic for:
            Failed login attempts
            Suspicious activity
            Unusual access times
            Directory traversal attacks
            Lateral movement attacks
            File uploads
        is_traversal_attack method detects directory traversal attack patterns.
        is_lateral_attack method detects lateral movement attack patterns.
        is_file_upload method detects file upload patterns.
        extract_ip method extracts IP addresses from log entries using a regular expression.

    Observer Setup:
        Initialize and start the observer to watch the specified log file directory.
        Continuously monitor the log file and handle keyboard interruption gracefully.

Usage

    Save the Script:
    Save the script to a file, e.g., log_monitor.py.

    Edit the Script:
        Replace 'your_telegram_bot_token' with your actual Telegram bot token.
        Replace 'your_chat_id' with your actual Telegram chat ID.
        Replace 'path_to_your_log_file.log' with the actual path to the log file you want to monitor.

    Run the Script:
    Execute the script using Python:

    bash

    python log_monitor.py

Customization

    Heuristic Detection:
        Modify the is_heuristic_attack, is_traversal_attack, is_lateral_attack, and is_file_upload methods to add more sophisticated detection patterns based on your log file format and specific attack signatures.
        Adjust the threshold for failed login attempts or add more checks for different types of suspicious activities.

    Logging:
        Enhance logging to provide more detailed insights into the detection process and script performance.

By following these steps and using the provided script, you can effectively monitor your log files in real-time, detect heuristic, traversal, lateral attacks, and file uploads, and receive timely alerts via Telegram.
