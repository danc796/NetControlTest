"""
Enhanced logging utilities for the Central Management Server.
Sets up comprehensive logging configuration with file and console output.
"""

import logging
import os
from datetime import datetime
import socket
import traceback

# Global logger object
central_logger = None

def setup_logging(log_level="INFO", log_dir="logs"):
    """Set up application logging with enhanced details"""
    global central_logger
    
    # Return existing logger if already set up
    if central_logger is not None:
        return central_logger

    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)

    # Define log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"central_server_{timestamp}.log")

    # Map string log level to constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    numeric_level = level_map.get(log_level.upper(), logging.INFO)

    # Configure detailed formatter
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )

    # Set up file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(detailed_formatter)

    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(detailed_formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Add the handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Create a server logger
    central_logger = logging.getLogger('central_server')
    central_logger.setLevel(numeric_level)
    
    # Log startup information
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    
    central_logger.info(f"====== CENTRAL SERVER STARTED ======")
    central_logger.info(f"Hostname: {hostname}")
    central_logger.info(f"IP Address: {ip_address}")
    central_logger.info(f"Logging level: {logging.getLevelName(numeric_level)}")
    central_logger.info(f"Log file: {log_file}")
    
    return central_logger

def log_connection(address, username=None, action="connected"):
    """Log connection events with details"""
    if central_logger:
        if username:
            central_logger.info(f"Client {address} ({username}) {action}")
        else:
            central_logger.info(f"Client {address} {action}")

def log_server_action(address, username, server_ip, server_port, action):
    """Log server-related actions"""
    if central_logger:
        central_logger.info(f"User {username} ({address}) {action} server {server_ip}:{server_port}")

def log_error(message, exception=None):
    """Log detailed error information"""
    if central_logger:
        if exception:
            error_details = ''.join(traceback.format_exception(type(exception), 
                                                               exception, 
                                                               exception.__traceback__))
            central_logger.error(f"{message}: {str(exception)}\n{error_details}")
        else:
            central_logger.error(message)