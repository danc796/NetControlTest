"""
Configuration utilities for the Central Management Server.
Handles loading, saving, and accessing configuration settings.
"""

import json
import os
import logging

DEFAULT_CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 5001
    },
    "security": {
        "allow_unverified_certs": True
    },
    "database": {
        "path": "central_server.db"
    },
    "logging": {
        "level": "INFO",
        "log_dir": "logs"
    }
}

CONFIG_FILE = "central_server_config.json"

class ConfigManager:
    def __init__(self, config_file=CONFIG_FILE):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from file or create default config"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    logging.info(f"Configuration loaded from {self.config_file}")
                    return config
            except Exception as e:
                logging.error(f"Error loading configuration: {e}")
                logging.info("Using default configuration")
                return self._save_default_config()
        else:
            # Save default config
            return self._save_default_config()

    def _save_default_config(self):
        """Save default configuration to file"""
        try:
            with open(self.config_file, 'w') as config_file:
                json.dump(DEFAULT_CONFIG, config_file, indent=4)
            logging.info(f"Default configuration saved to {self.config_file}")
            return DEFAULT_CONFIG.copy()
        except Exception as e:
            logging.error(f"Error saving default configuration: {e}")
            return DEFAULT_CONFIG.copy()

    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as config_file:
                json.dump(self.config, config_file, indent=4)
            logging.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            return False

    def get(self, section, key, default=None):
        """Get a configuration value"""
        return self.config.get(section, {}).get(key, default)

    def set(self, section, key, value):
        """Set a configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        return self.save_config()

    def get_server_host(self):
        """Get the server host"""
        return self.get("server", "host", DEFAULT_CONFIG["server"]["host"])

    def get_server_port(self):
        """Get the server port"""
        return self.get("server", "port", DEFAULT_CONFIG["server"]["port"])

    def get_use_ssl(self):
        """Get whether to use SSL"""
        return False  # Always return False since SSL is removed

    def get_database_path(self):
        """Get the database path"""
        return self.get("database", "path", DEFAULT_CONFIG["database"]["path"])

    def get_log_level(self):
        """Get the logging level"""
        return self.get("logging", "level", DEFAULT_CONFIG["logging"]["level"])

    def get_log_dir(self):
        """Get the logging directory"""
        return self.get("logging", "log_dir", DEFAULT_CONFIG["logging"]["log_dir"])