"""
Database schema for the Central Management Server.
Creates the necessary tables for users, servers with recent_connection field.
"""

import sqlite3
import os
import logging
import hashlib

DATABASE_PATH = "central_server.db"


def create_schema():
    """Create the database schema if it doesn't exist"""
    if os.path.exists(DATABASE_PATH) and os.path.getsize(DATABASE_PATH) > 0:
        # If database exists, check if we need to update the schema
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()

            # Check if servers table needs to be updated
            cursor.execute("PRAGMA table_info(servers)")
            columns = [col[1] for col in cursor.fetchall()]

            # If sharing_with column exists but recent_connection doesn't, rename it
            if 'sharing_with' in columns and 'recent_connection' not in columns:
                cursor.execute("ALTER TABLE servers RENAME COLUMN sharing_with TO recent_connection")
                logging.info("Renamed sharing_with column to recent_connection")
            elif 'recent_connection' not in columns:
                # If neither exists, add recent_connection column
                cursor.execute("ALTER TABLE servers ADD COLUMN recent_connection TEXT DEFAULT ''")
                logging.info("Added recent_connection column to servers table")

            # Remove active_connections table if it exists
            cursor.execute("DROP TABLE IF EXISTS active_connections")

            conn.commit()
            conn.close()

            logging.info(f"Database schema updated successfully at {DATABASE_PATH}")
        except Exception as e:
            logging.error(f"Error updating database schema: {e}")

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

        # Create servers table with recent_connection column
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS servers (
            server_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            recent_connection TEXT DEFAULT '',
            UNIQUE(ip_address, port)
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