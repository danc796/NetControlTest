import psutil
import logging


def get_network_info():
    """Gather network information"""
    try:
        # Get network connections
        connections = []
        for conn in psutil.net_connections():
            try:
                connections.append(conn._asdict())
            except Exception as e:
                logging.debug(f"Error processing connection: {e}")

        # Get network I/O counters
        io_counters = dict(psutil.net_io_counters()._asdict())

        return {
            'connections': connections,
            'io_counters': io_counters
        }
    except Exception as e:
        logging.error(f"Error gathering network info: {e}")
        return {
            'connections': [],
            'io_counters': {}
        }