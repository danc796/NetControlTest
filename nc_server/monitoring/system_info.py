import platform
import psutil
import logging

def get_system_info():
    """Gather system information"""
    try:
        return {
            'hostname': platform.node(),
            'os': platform.system(),
            'os_version': platform.version(),
            'cpu_count': psutil.cpu_count(),
            'total_memory': psutil.virtual_memory().total,
            'disk_partitions': [partition.mountpoint for partition in psutil.disk_partitions()]
        }
    except Exception as e:
        logging.error(f"Error gathering system info: {e}")
        return {
            'hostname': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'cpu_count': 0,
            'total_memory': 0,
            'disk_partitions': []
        }