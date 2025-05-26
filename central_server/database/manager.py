"""
Database manager for the Central Management Server.
Handles database operations for users, servers, and connections.
"""

import sqlite3
import logging
import hashlib
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_path="central_server.db"):
        self.db_path = db_path

    def get_connection(self):
        """Get a database connection"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # This enables column access by name
            return conn
        except Exception as e:
            logging.error(f"Database connection error: {e}")
            return None

    def authenticate_user(self, username, password):
        """Authenticate a user by username and password"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Hash the password for comparison
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password_hash = ?",
                (username, password_hash)
            )

            user = cursor.fetchone()

            if user:
                # Update last login timestamp
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE user_id = ?",
                    (datetime.now(), user['user_id'])
                )
                conn.commit()

            conn.close()
            return dict(user) if user else None

        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return None

    def create_user(self, username, password, is_admin=0):
        """Create a new user"""
        try:
            # Check if username already exists
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                conn.close()
                return False, "Username already exists"

            # Hash the password and create the user
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (username, password_hash, is_admin)
            )

            conn.commit()
            conn.close()
            return True, "User created successfully"

        except Exception as e:
            logging.error(f"Error creating user: {e}")
            return False, str(e)

    def get_all_users(self):
        """Get all users"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT user_id, username, created_at, last_login, is_admin FROM users")
            users = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return users
        except Exception as e:
            logging.error(f"Error getting users: {e}")
            return []

    def register_server(self, ip_address, port, client_ip):
        """Register a server - simplified to not set sharing_with here"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # First, ensure the server exists in the servers table
            cursor.execute(
                """
                INSERT OR IGNORE INTO servers (ip_address, port) 
                VALUES (?, ?)
                """,
                (ip_address, port)
            )

            # Update the server record with last_seen time
            cursor.execute(
                """
                UPDATE servers 
                SET last_seen = ? 
                WHERE ip_address = ? AND port = ?
                """,
                (datetime.now(), ip_address, port)
            )

            conn.commit()
            conn.close()
            return True, "Server registered successfully"

        except Exception as e:
            logging.error(f"Error registering server: {e}")
            return False, str(e)

    def unregister_server(self, ip_address, port):
        """Unregister a server - DO NOT clear recent_connection"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Get the server_id
            cursor.execute(
                "SELECT server_id FROM servers WHERE ip_address = ? AND port = ?",
                (ip_address, port)
            )
            server_record = cursor.fetchone()

            if not server_record:
                conn.close()
                return False, "Server not found"

            # Just update last_seen time - DON'T clear recent_connection
            cursor.execute(
                """
                UPDATE servers 
                SET last_seen = ? 
                WHERE ip_address = ? AND port = ?
                """,
                (datetime.now(), ip_address, port)
            )

            conn.commit()
            conn.close()
            return True, "Server unregistered successfully"

        except Exception as e:
            logging.error(f"Error unregistering server: {e}")
            return False, str(e)

    def set_connection_sharing(self, ip_address, port, is_shared, username):
        """Set whether a connection is shared - only update recent_connection when sharing is enabled"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Get the server_id
            cursor.execute(
                "SELECT server_id FROM servers WHERE ip_address = ? AND port = ?",
                (ip_address, port)
            )
            server_record = cursor.fetchone()

            if not server_record:
                conn.close()
                return False, "Server not found"

            server_id = server_record['server_id']

            # Only update recent_connection when sharing is enabled (new connection)
            if is_shared:
                # Set the recent_connection field to the username
                cursor.execute(
                    """
                    UPDATE servers
                    SET recent_connection = ?, last_seen = ?
                    WHERE server_id = ?
                    """,
                    (username, datetime.now(), server_id)
                )
                logging.info(f"Set recent_connection to '{username}' for server {ip_address}:{port}")
            else:
                # When is_shared is False, we DON'T clear recent_connection - just update last_seen
                cursor.execute(
                    """
                    UPDATE servers
                    SET last_seen = ?
                    WHERE server_id = ?
                    """,
                    (datetime.now(), server_id)
                )
                logging.info(f"Updated last_seen for server {ip_address}:{port} (keeping recent_connection)")

            conn.commit()
            conn.close()

            return True, "Connection sharing status updated"

        except Exception as e:
            logging.error(f"Error setting connection sharing: {e}")
            return False, str(e)

    def get_all_active_servers(self):
        """Get all servers that have a recent connection"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT ip_address, port
                FROM servers
                WHERE recent_connection <> ''
                """
            )

            servers = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return servers

        except Exception as e:
            logging.error(f"Error getting active servers: {e}")
            return []

    def get_shared_servers(self):
        """Get all servers that have a recent connection"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT ip_address, port
                FROM servers
                WHERE recent_connection <> ''
                """
            )

            servers = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return servers

        except Exception as e:
            logging.error(f"Error getting shared servers: {e}")
            return []

    def get_user_connections(self, username):
        """Get all servers that a user has as recent connection"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT ip_address, port
                FROM servers
                WHERE recent_connection = ?
                """,
                (username,)
            )

            connections = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return connections

        except Exception as e:
            logging.error(f"Error getting user connections: {e}")
            return []

    def get_all_connection_details(self):
        """Get detailed information about all servers with recent connections"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT 
                    ip_address as server_ip,
                    last_seen as connected_at,
                    'System' as connect_by,
                    recent_connection
                FROM servers
                WHERE recent_connection <> ''
                """
            )

            connection_details = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return connection_details

        except Exception as e:
            logging.error(f"Error getting connection details: {e}")
            return []

    def clean_disconnected_user(self, username):
        """When user disconnects, DON'T remove them from recent_connection - just log"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Count how many servers have this user as recent_connection
            cursor.execute(
                """
                SELECT COUNT(*) as count
                FROM servers
                WHERE recent_connection = ?
                """,
                (username,)
            )
            result = cursor.fetchone()
            count = result['count'] if result else 0

            conn.close()

            # Just log that user disconnected, but don't clear recent_connection
            logging.info(f"User {username} disconnected. They remain as recent_connection for {count} servers")
            return True, f"User {username} disconnected (recent_connection preserved for {count} servers)"

        except Exception as e:
            logging.error(f"Error cleaning up user {username}: {e}")
            return False, str(e)

    def update_recent_connection(self, ip_address, port, username):
        """Update the recent_connection field for a server when a new connection is made"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE servers
                SET recent_connection = ?, last_seen = ?
                WHERE ip_address = ? AND port = ?
                """,
                (username, datetime.now(), ip_address, port)
            )

            conn.commit()
            conn.close()

            logging.info(f"Updated recent_connection to '{username}' for server {ip_address}:{port}")
            return True, "Recent connection updated successfully"

        except Exception as e:
            logging.error(f"Error updating recent connection: {e}")
            return False, str(e)