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


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="NetControl Central Server")
    parser.add_argument("-p", "--port", type=int, default=5001,
                        help="Port to listen on (default: 5001)")
    parser.add_argument("-a", "--address", type=str, default="0.0.0.0",
                        help="IP address to bind to (default: 0.0.0.0)")
    parser.add_argument("-l", "--log-level", type=str,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Logging level (default: INFO)")
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

    # Determine log level and directory
    log_level = args.log_level
    log_dir = "logs"

    # Setup logging
    os.makedirs(log_dir, exist_ok=True)
    setup_logging(log_level, log_dir)

    # Create database schema
    if not create_schema():
        logging.critical("Failed to create database schema, exiting.")
        sys.exit(1)

    # Determine server host and port
    host = args.address
    port = args.port

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