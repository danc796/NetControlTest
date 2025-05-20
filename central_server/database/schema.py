"""
Database schema for the Central Management Server.
Creates the necessary tables for users, servers, and connections.
"""

import sqlite3
import os
import logging
import hashlib

DATABASE_PATH = "central_server.db"


def create_schema():
    """Create the database schema if it doesn't exist"""
    if os.path.exists(DATABASE_PATH) and os.path.getsize(DATABASE_PATH) > 0:
        logging.info(f"Database already exists at {DATABASE_PATH}")
        return True

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_admin INTEGER DEFAULT 0
        )
        ''')

        # Create servers table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            server_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address, port)
        )
        ''')

        # Create active connections table with modified structure
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_connections (
            server_id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL,  /* IP address of the server */
            connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connect_by TEXT NOT NULL,  /* Client IP address */
            sharing_with TEXT DEFAULT '',
            FOREIGN KEY (server_id) REFERENCES servers(server_id)
        )
        ''')

        # Create default admin user
        default_password = "admin"
        password_hash = hashlib.sha256(default_password.encode()).hexdigest()

        cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, is_admin)
        VALUES (?, ?, 1)
        ''', ("admin", password_hash))

        conn.commit()
        conn.close()

        logging.info(f"Database schema created successfully at {DATABASE_PATH}")
        return True

    except Exception as e:
        logging.error(f"Error creating database schema: {e}")
        return False