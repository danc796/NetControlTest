"""
Main entry point for the NetControl Central Management Server.
Handles command-line arguments, server startup, and shutdown.
"""

import argparse
import logging
import signal
import sys
import os

from central_server.database.schema import create_schema
from central_server.connection.manager import ConnectionManager
from central_server.utils.logging import setup_logging
from central_server.utils.config import ConfigManager


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="NetControl Central Server")
    parser.add_argument("-p", "--port", type=int, default=None,
                        help="Port to listen on (default: from config or 5001)")
    parser.add_argument("-a", "--address", type=str, default=None,
                        help="IP address to bind to (default: from config or 0.0.0.0)")
    parser.add_argument("-l", "--log-level", type=str,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default=None, help="Logging level (default: from config or INFO)")
    return parser.parse_args()


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    print("\nShutting down central server...")
    if hasattr(signal_handler, "server"):
        signal_handler.server.stop()
    sys.exit(0)


def main():
    """Main entry point for the central server"""
    # Parse command-line arguments
    args = parse_arguments()

    # Load configuration
    config = ConfigManager()

    # Determine log level and directory
    log_level = args.log_level or config.get_log_level()
    log_dir = config.get_log_dir()

    # Setup logging
    os.makedirs(log_dir, exist_ok=True)
    setup_logging(log_level, log_dir)

    # Create database schema
    if not create_schema():
        logging.critical("Failed to create database schema, exiting.")
        sys.exit(1)

    # Determine server host and port
    host = args.address or config.get_server_host()
    port = args.port or config.get_server_port()

    # Create and start server
    server = ConnectionManager(
        host=host,
        port=port
    )
    signal_handler.server = server

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        logging.info(f"Starting NetControl Central Server on {host}:{port} with AES encryption")
        server.start()
    except Exception as e:
        logging.critical(f"Server failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()