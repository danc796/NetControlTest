import logging
import os
from datetime import datetime


def setup_logging(log_level="INFO"):
    """Set up application logging with proper cleanup for restarts"""
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    # Define log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"nc_client_{timestamp}.log")

    # Map string log level to constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    numeric_level = level_map.get(log_level.upper(), logging.INFO)

    # Clear all existing handlers from root logger to avoid duplicates
    # This is especially important during application restarts
    root_logger = logging.getLogger('')
    for handler in root_logger.handlers[:]:
        handler.close()  # Properly close the handler to release file handles
        root_logger.removeHandler(handler)

    # Set up file handler
    file_handler = logging.FileHandler(log_file)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(numeric_level)

    # Set up console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)

    # Configure root logger
    root_logger.setLevel(numeric_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Log startup information
    logging.info("=" * 50)
    logging.info(f"Application starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info(f"Logging initialized at level {logging.getLevelName(numeric_level)}")
    logging.info(f"Log file: {log_file}")
    logging.info("=" * 50)

    return root_logger