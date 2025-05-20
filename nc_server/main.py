import argparse
import logging
import signal
import sys
import os

from nc_server.connection.manager import ConnectionManager
from nc_server.utils.logging import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="NC Server")
    parser.add_argument("-p", "--port", type=int, default=5000,
                        help="Port to listen on (default: 5000)")
    parser.add_argument("-a", "--address", type=str, default="0.0.0.0",
                        help="IP address to bind to (default: 0.0.0.0)")
    parser.add_argument("-l", "--log-level", type=str,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Logging level")
    return parser.parse_args()


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    print("\nShutting down server...")
    if hasattr(signal_handler, "server"):
        signal_handler.server.stop()
    sys.exit(0)


def main():
    """Main entry point for the nc server"""
    # Parse command-line arguments
    args = parse_arguments()

    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)

    # Setup logging
    setup_logging(args.log_level)

    # Create and start server
    server = ConnectionManager(host=args.address, port=args.port)
    signal_handler.server = server

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        logging.info(f"Starting NC Server on {args.address}:{args.port}")
        server.start()
    except Exception as e:
        logging.critical(f"Server failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()