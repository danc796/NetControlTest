import logging
import sys
import os
from datetime import datetime


def setup_logging(log_level="INFO"):
    """Set up logging with specified log level and in a logs directory"""
    # First check if the root logger already has handlers to avoid duplicates
    if logging.getLogger('').hasHandlers():
        return

    # Create logs directory if it doesn't exist
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    # Define log file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = os.path.join(log_dir, f"nc_server_{timestamp}.log")

    # Map string log level to constant
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = level_map.get(log_level.upper(), logging.INFO)

    # Remove any existing handlers from the root logger
    root_logger = logging.getLogger('')
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logging.info(f"Logging initialized at level {logging.getLevelName(log_level)}")
    logging.info(f"Log file: {log_file}")
    return log_file