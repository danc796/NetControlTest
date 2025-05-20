import psutil
import logging
import platform


def get_hardware_info():
    """Monitor hardware metrics including removable drives"""
    try:
        disk_usage = {}

        # Safely collect disk usage information
        for partition in psutil.disk_partitions(all=True):  # Changed to all=True to include all drives
            try:
                # Skip optical drives on Windows which often cause errors
                if platform.system() == 'Windows' and 'cdrom' in partition.opts.lower():
                    continue

                # Attempt to get usage for all drives (including removable)
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = dict(usage._asdict())
                except PermissionError:
                    # Skip drives we can't access (like empty card readers)
                    continue

            except Exception as e:
                logging.warning(f"Could not access drive {partition.mountpoint}: {e}")
                continue

        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_usage': dict(psutil.virtual_memory()._asdict()),
            'disk_usage': disk_usage,
            'network_io': dict(psutil.net_io_counters()._asdict())
        }
    except Exception as e:
        logging.error(f"Error gathering hardware info: {e}")
        return {
            'cpu_percent': 0,
            'memory_usage': {},
            'disk_usage': {},
            'network_io': {}
        }