import json
import os
import logging

DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 5000
    },
    "rdp": {
        "port": 5900,
        "refresh_rate": 0.05,
        "image_quality": 95
    },
    "security": {
        "allow_command_execution": False
    },
    "logging": {
        "level": "INFO",
        "log_dir": "logs"
    }
}

CONFIG_FILE = "nc_server_config.json"

def load_config():
    """Load configuration from file or create default config"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                logging.info(f"Configuration loaded from {CONFIG_FILE}")
                return config
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            logging.info("Using default configuration")
            return DEFAULT_CONFIG
    else:
        # Save default config
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_config(config):
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(config, config_file, indent=4)
        logging.info(f"Configuration saved to {CONFIG_FILE}")
        return True
    except Exception as e:
        logging.error(f"Error saving configuration: {e}")
        return False

def get_config_value(section, key, default=None):
    """Get specific configuration value"""
    config = load_config()
    return config.get(section, {}).get(key, default)

def set_config_value(section, key, value):
    """Set specific configuration value"""
    config = load_config()
    if section not in config:
        config[section] = {}
    config[section][key] = value
    return save_config(config)