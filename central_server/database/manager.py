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
        """Register a server that a user is connected to, storing the client IP"""
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

            # Get the server_id
            cursor.execute(
                "SELECT server_id FROM servers WHERE ip_address = ? AND port = ?",
                (ip_address, port)
            )
            server_record = cursor.fetchone()

            if not server_record:
                conn.close()
                return False, "Failed to register server"

            server_id = server_record['server_id']

            # Update the last_seen timestamp
            cursor.execute(
                "UPDATE servers SET last_seen = ? WHERE server_id = ?",
                (datetime.now(), server_id)
            )

            # Add or update connection in active_connections
            cursor.execute(
                """
                INSERT OR REPLACE INTO active_connections 
                (server_id, ip_address, connected_at, connect_by)
                VALUES (?, ?, ?, ?)
                """,
                (server_id, ip_address, datetime.now(), client_ip)
            )

            conn.commit()
            conn.close()
            return True, "Server registered successfully"

        except Exception as e:
            logging.error(f"Error registering server: {e}")
            return False, str(e)

    def unregister_server(self, ip_address, port):
        """Unregister a server by removing its connection entry"""
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

            # Remove the connection from active_connections
            cursor.execute(
                "DELETE FROM active_connections WHERE server_id = ?",
                (server_id,)
            )

            # Note: We don't delete the server from the servers table as per your requirement

            conn.commit()
            conn.close()
            return True, "Server connection unregistered successfully"

        except Exception as e:
            logging.error(f"Error unregistering server: {e}")
            return False, str(e)

    def set_connection_sharing(self, ip_address, port, is_shared, username):
        """Set whether a connection is shared or not"""
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

            # Update the sharing status
            if is_shared:
                # Get current sharing_with value
                cursor.execute(
                    "SELECT sharing_with FROM active_connections WHERE server_id = ?",
                    (server_id,)
                )
                result = cursor.fetchone()

                if not result:
                    # No entry yet, create one
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO active_connections
                        (server_id, ip_address, connected_at, connect_by, sharing_with)
                        SELECT ?, ?, CURRENT_TIMESTAMP, 'system', ?
                        """,
                        (server_id, ip_address, username)
                    )
                else:
                    # Update existing sharing_with
                    current_sharing = result['sharing_with']
                    if current_sharing:
                        # Check if username already in list
                        sharing_list = [s.strip() for s in current_sharing.split(',')]
                        if username not in sharing_list:
                            sharing_list.append(username)
                            new_sharing = ', '.join(sharing_list)
                            cursor.execute(
                                """
                                UPDATE active_connections
                                SET sharing_with = ?
                                WHERE server_id = ?
                                """,
                                (new_sharing, server_id)
                            )
                    else:
                        # First name in sharing list
                        cursor.execute(
                            """
                            UPDATE active_connections
                            SET sharing_with = ?
                            WHERE server_id = ?
                            """,
                            (username, server_id)
                        )
            else:
                # Remove username from sharing_with list
                cursor.execute(
                    "SELECT sharing_with FROM active_connections WHERE server_id = ?",
                    (server_id,)
                )
                result = cursor.fetchone()

                if result and result['sharing_with']:
                    sharing_list = [s.strip() for s in result['sharing_with'].split(',')]
                    if username in sharing_list:
                        sharing_list.remove(username)
                        new_sharing = ', '.join(sharing_list)
                        cursor.execute(
                            """
                            UPDATE active_connections
                            SET sharing_with = ?
                            WHERE server_id = ?
                            """,
                            (new_sharing, server_id)
                        )

            conn.commit()
            conn.close()

            return True, "Connection sharing status updated"

        except Exception as e:
            logging.error(f"Error setting connection sharing: {e}")
            return False, str(e)

    def get_all_active_servers(self):
        """Get all servers that are actively connected"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT s.ip_address, s.port
                FROM servers s
                JOIN active_connections ac ON s.server_id = ac.server_id
                """
            )

            servers = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return servers

        except Exception as e:
            logging.error(f"Error getting active servers: {e}")
            return []

    def get_shared_servers(self):
        """Get all servers that have sharing enabled"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT s.ip_address, s.port
                FROM servers s
                JOIN active_connections ac ON s.server_id = ac.server_id
                WHERE ac.sharing_with <> ''
                """
            )

            servers = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return servers

        except Exception as e:
            logging.error(f"Error getting shared servers: {e}")
            return []

    def get_user_connections(self, username):
        """Get all servers that a user is sharing"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT s.ip_address, s.port
                FROM servers s
                JOIN active_connections ac ON s.server_id = ac.server_id
                WHERE ac.sharing_with LIKE ?
                """,
                (f"%{username}%",)
            )

            connections = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return connections

        except Exception as e:
            logging.error(f"Error getting user connections: {e}")
            return []

    def get_all_connection_details(self):
        """Get detailed information about all active connections"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT 
                    ac.ip_address as server_ip,
                    ac.connected_at,
                    ac.connect_by,
                    ac.sharing_with
                FROM active_connections ac
                """
            )

            connection_details = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return connection_details

        except Exception as e:
            logging.error(f"Error getting connection details: {e}")
            return []

    def clean_disconnected_user(self, username):
        """Remove a user from all sharing lists when they disconnect"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Find all connections where this user is in the sharing_with list
            cursor.execute(
                """
                SELECT server_id, sharing_with
                FROM active_connections
                WHERE sharing_with LIKE ?
                """,
                (f"%{username}%",)
            )

            connections = cursor.fetchall()

            # Update each connection to remove the username
            for connection in connections:
                server_id = connection['server_id']
                sharing_with = connection['sharing_with']

                # Update the sharing_with list
                sharing_list = [name.strip() for name in sharing_with.split(',')]
                if username in sharing_list:
                    sharing_list.remove(username)

                new_sharing = ', '.join(sharing_list)

                cursor.execute(
                    """
                    UPDATE active_connections
                    SET sharing_with = ?
                    WHERE server_id = ?
                    """,
                    (new_sharing, server_id)
                )

            conn.commit()
            conn.close()
            return True, f"User {username} removed from all sharing lists"

        except Exception as e:
            logging.error(f"Error cleaning up user {username}: {e}")
            return False, str(e)