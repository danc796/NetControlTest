import socket
import json
import logging
import threading
import time
from nc_client.connection.encryption import EncryptionManager


class CentralServerClient:
    def __init__(self, parent_app, host=None, port=5001):
        """Initialize the central server client with AES encryption"""
        self.parent_app = parent_app
        self.host = host
        self.port = port

        # Connection state
        self.socket = None
        self.cipher_suite = None
        self.encryption_key = None
        self.connected = False
        self.authenticated = False

        # User information
        self.user_id = None
        self.username = None
        self.is_admin = False

        # Initialize encryption manager
        self.encryption_manager = EncryptionManager()

        # Retry settings
        self.max_retries = 3
        self.retry_delay = 5  # seconds

        # Connection thread
        self.connection_thread = None

        # Active servers
        self.active_servers = []
        self.shared_servers = []

        # Auto-share is now always enabled and cannot be toggled
        self.auto_share = True

    def connect(self):
        """Connect to the central server with AES encryption"""
        if not self.host:
            logging.error("Central server host not specified")
            return False

        # Attempt to connect
        retry_count = 0
        while retry_count < self.max_retries:
            try:
                # Create a socket with timeout
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.settimeout(5.0)

                # Connect to server
                client_socket.connect((self.host, self.port))

                # Use socket directly
                wrapped_socket = client_socket

                # For backward compatibility, receive dummy certificate size
                cert_size_bytes = wrapped_socket.recv(4)
                cert_size = int.from_bytes(cert_size_bytes, byteorder='big')

                if cert_size > 0:
                    # Just read and discard the certificate data
                    cert_data = b''
                    while len(cert_data) < cert_size:
                        chunk = wrapped_socket.recv(min(4096, cert_size - len(cert_data)))
                        if not chunk:
                            raise ConnectionError("Connection closed while receiving certificate")
                        cert_data += chunk
                    logging.info(f"Received central server certificate ({cert_size} bytes)")

                # Get encryption key
                self.encryption_key = wrapped_socket.recv(44)

                # Set encryption key in the encryption manager
                self.encryption_manager.set_encryption_key(self.encryption_key)

                # Set cipher suite
                self.cipher_suite = self.encryption_manager

                # Use the socket
                self.socket = wrapped_socket

                self.connected = True
                logging.info(f"Connected to central server at {self.host}:{self.port} with AES encryption")

                # Start heartbeat thread
                self.connection_thread = threading.Thread(target=self.heartbeat_loop)
                self.connection_thread.daemon = True
                self.connection_thread.start()

                return True

            except Exception as e:
                logging.error(f"Error connecting to central server: {e}")
                retry_count += 1

                if retry_count < self.max_retries:
                    logging.info(f"Retrying connection in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logging.error("Max retries reached, could not connect to central server")
                    return False
        return None

    def heartbeat_loop(self):
        """Maintain connection with heartbeats"""
        while self.connected:
            try:
                # Send a simple ping every 30 seconds
                time.sleep(30)
                if self.socket and self.connected:
                    self.send_command("ping", {})
            except Exception as e:
                logging.error(f"Heartbeat error: {e}")
                # Don't set connected to False here - let the send_command handle it

            # Refresh server lists periodically
            if self.authenticated:
                try:
                    self.refresh_server_lists()
                except:
                    pass

    def login(self, username, password):
        """Log in to the central server"""
        if not self.connected:
            if not self.connect():
                return False, "Could not connect to central server"

        response = self.send_command("login", {
            "username": username,
            "password": password
        })

        if response and response.get("status") == "success":
            self.authenticated = True
            self.user_id = response.get("data", {}).get("user_id")
            self.username = response.get("data", {}).get("username")
            self.is_admin = response.get("data", {}).get("is_admin", False)

            logging.info(f"Successfully logged in as {self.username}")

            # Refresh server lists
            self.refresh_server_lists()

            # Register existing connections with the central server (auto-share)
            if self.parent_app and hasattr(self.parent_app, 'connection_manager'):
                self.auto_register_existing_connections()

            return True, "Login successful"
        else:
            error_msg = response.get("message", "Login failed") if response else "No response from server"
            logging.error(f"Login failed: {error_msg}")
            return False, error_msg

    def auto_register_existing_connections(self):
        """Register all existing connections with the central server after login"""
        if not self.authenticated:
            return

        if not hasattr(self.parent_app, 'connection_manager'):
            return

        connections = self.parent_app.connection_manager.connections

        for conn_id, connection in connections.items():
            if connection.get('connection_active', False):
                host, port = connection.get('host'), connection.get('port')
                logging.info(f"Auto-registering existing connection to {host}:{port}")

                # First register the server
                success, _ = self.register_server(host, port)

                # Then set sharing (already handled by register_server with auto-share)
                connection['is_shared'] = True

                # Log the result
                if success:
                    logging.info(f"Successfully registered and shared {host}:{port}")
                else:
                    logging.warning(f"Failed to register {host}:{port} with central server")

    def set_auto_share(self, enabled):
        """Enable or disable auto-sharing feature"""
        self.auto_share = enabled
        logging.info(f"Auto-sharing {'enabled' if enabled else 'disabled'}")
        return True, f"Auto-sharing {'enabled' if enabled else 'disabled'}"

    def get_auto_share_status(self):
        """Get current auto-share setting"""
        return self.auto_share

    def create_user(self, username, password, is_admin=False):
        """Create a new user (admin only)"""
        if not self.authenticated or not self.is_admin:
            return False, "Not authorized. Admin privileges required."

        response = self.send_command("create_user", {
            "username": username,
            "password": password,
            "is_admin": is_admin
        })

        if response and response.get("status") == "success":
            logging.info(f"Created new user: {username}")
            return True, response.get("message", "User created successfully")
        else:
            error_msg = response.get("message", "Failed to create user") if response else "No response from server"
            logging.error(f"User creation failed: {error_msg}")
            return False, error_msg

    def get_all_users(self):
        """Get list of all users (admin only)"""
        if not self.authenticated:
            return False, "Not authenticated", []

        if not self.is_admin:
            return False, "Admin privileges required", []

        response = self.send_command("get_all_users", {})

        if response and response.get("status") == "success":
            users = response.get("data", [])
            return True, f"Retrieved {len(users)} users", users
        else:
            error_msg = response.get("message", "Failed to get users") if response else "No response from server"
            logging.error(f"Getting users failed: {error_msg}")
            return False, error_msg, []

    def change_password(self, old_password, new_password):
        """Change the current user's password"""
        if not self.authenticated:
            return False, "Not authenticated"

        if not old_password or not new_password:
            return False, "Both old and new passwords are required"

        response = self.send_command("change_password", {
            "user_id": self.user_id,
            "old_password": old_password,
            "new_password": new_password
        })

        if response and response.get("status") == "success":
            logging.info("Password changed successfully")
            return True, "Password changed successfully"
        else:
            error_msg = response.get("message", "Failed to change password") if response else "No response from server"
            logging.error(f"Password change failed: {error_msg}")
            return False, error_msg

    def delete_user(self, username):
        """Delete a user (admin only)"""
        if not self.authenticated or not self.is_admin:
            return False, "Admin privileges required"

        response = self.send_command("delete_user", {
            "username": username
        })

        if response and response.get("status") == "success":
            logging.info(f"Deleted user: {username}")
            return True, f"User '{username}' deleted successfully"
        else:
            error_msg = response.get("message", "Failed to delete user") if response else "No response from server"
            logging.error(f"User deletion failed: {error_msg}")
            return False, error_msg

    def promote_to_admin(self, username):
        """Promote a user to admin status (admin only)"""
        if not self.authenticated or not self.is_admin:
            return False, "Admin privileges required"

        response = self.send_command("promote_to_admin", {
            "username": username
        })

        if response and response.get("status") == "success":
            logging.info(f"Promoted user to admin: {username}")
            return True, f"User '{username}' promoted to admin successfully"
        else:
            error_msg = response.get("message", "Failed to promote user") if response else "No response from server"
            logging.error(f"User promotion failed: {error_msg}")
            return False, error_msg

    def refresh_server_lists(self):
        """Refresh the lists of active and shared servers"""
        if not self.authenticated:
            return

        # Get all active servers
        success, _, servers = self.get_all_servers()
        if success:
            self.active_servers = servers

        # Get shared servers
        success, _, servers = self.get_shared_servers()
        if success:
            self.shared_servers = servers

    def register_server(self, ip_address, port):
        """Register a server connection with the central server (always shared)"""
        if not self.authenticated:
            return False, "Not authenticated"

        # Ensure port is an integer in the message
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                return False, "Invalid port number"

        # Send the command with proper formatting
        response = self.send_command("register_server", {
            "ip_address": ip_address,
            "port": port
        })

        if response and response.get("status") == "success":
            logging.info(f"Registered server {ip_address}:{port}")

            # Always share the server
            share_success, share_message = self.set_sharing(ip_address, port, True)

            if share_success:
                logging.info(f"Automatically shared server {ip_address}:{port}")
            else:
                logging.warning(f"Failed to share server {ip_address}:{port}: {share_message}")

            # Refresh the server lists immediately
            self.refresh_server_lists()
            return True, "Server registered and shared"
        else:
            error_msg = response.get("message", "Failed to register server") if response else "No response from server"
            logging.error(f"Server registration failed: {error_msg}")
            return False, error_msg

    def unregister_server(self, ip_address, port):
        """Unregister a server connection from the central server"""
        if not self.authenticated:
            return False, "Not authenticated"

        response = self.send_command("unregister_server", {
            "ip_address": ip_address,
            "port": port
        })

        if response and response.get("status") == "success":
            logging.info(f"Unregistered server {ip_address}:{port}")
            return True, "Server unregistered"
        else:
            error_msg = response.get("message",
                                     "Failed to unregister server") if response else "No response from server"
            logging.error(f"Server unregistration failed: {error_msg}")
            return False, error_msg

    def set_sharing(self, ip_address, port, is_shared):
        """Set sharing status for a server connection"""
        if not self.authenticated:
            return False, "Not authenticated"

        response = self.send_command("set_sharing", {
            "ip_address": ip_address,
            "port": port,
            "is_shared": is_shared
        })

        if response and response.get("status") == "success":
            state = "enabled" if is_shared else "disabled"
            logging.info(f"Sharing {state} for server {ip_address}:{port}")

            # Refresh server lists
            self.refresh_server_lists()

            return True, f"Sharing {state}"
        else:
            error_msg = response.get("message",
                                     "Failed to set sharing status") if response else "No response from server"
            logging.error(f"Setting sharing status failed: {error_msg}")
            return False, error_msg

    def get_all_servers(self):
        """Get all active servers from the central server"""
        if not self.authenticated:
            return False, "Not authenticated", []

        response = self.send_command("get_all_servers", {})

        if response and response.get("status") == "success":
            servers = response.get("data", [])
            return True, f"Found {len(servers)} active servers", servers
        else:
            error_msg = response.get("message", "Failed to get servers") if response else "No response from server"
            logging.error(f"Getting servers failed: {error_msg}")
            return False, error_msg, []

    def get_shared_servers(self):
        """Get shared servers from the central server"""
        if not self.authenticated:
            return False, "Not authenticated", []

        response = self.send_command("get_shared_servers", {})

        if response and response.get("status") == "success":
            servers = response.get("data", [])
            return True, f"Found {len(servers)} shared servers", servers
        else:
            error_msg = response.get("message",
                                     "Failed to get shared servers") if response else "No response from server"
            logging.error(f"Getting shared servers failed: {error_msg}")
            return False, error_msg, []

    def get_user_connections(self):
        """Get user's connections from the central server"""
        if not self.authenticated:
            return False, "Not authenticated", []

        response = self.send_command("get_user_connections", {})

        if response and response.get("status") == "success":
            connections = response.get("data", [])
            return True, f"Found {len(connections)} connections", connections
        else:
            error_msg = response.get("message", "Failed to get connections") if response else "No response from server"
            logging.error(f"Getting connections failed: {error_msg}")
            return False, error_msg, []

    def is_sharing_connection(self, ip_address, port):
        """Check if a connection is being shared"""
        success, _, connections = self.get_user_connections()
        if not success:
            return False

        for connection in connections:
            if connection.get('ip_address') == ip_address and str(connection.get('port')) == str(port):
                return bool(connection.get('is_shared', False))

        return False

    def send_command(self, command_type, data):
        """Send a command to the central server with AES encryption"""
        if not self.socket or not self.connected:
            logging.error("Not connected to central server")
            self.connected = False
            return None

        try:
            # Prepare command
            command = {
                'type': command_type,
                'data': data
            }

            # Convert to JSON
            json_data = json.dumps(command)

            # Encrypt data
            encrypted_data = self.cipher_suite.encrypt_data(json_data)

            # Send encrypted data
            self.socket.send(encrypted_data)

            # Receive encrypted response
            response_data = self.socket.recv(16384)

            if not response_data:
                logging.error("Received empty response from central server")
                self.connected = False
                return None

            # Decrypt response
            try:
                decrypted_data = self.cipher_suite.decrypt_data(response_data)
                response = json.loads(decrypted_data)
                return response
            except json.JSONDecodeError:
                logging.error("Invalid JSON response from server")
                self.connected = False
                return None

        except Exception as e:
            logging.error(f"Error sending command to central server: {e}")
            self.connected = False
            return None

    def connect_to_shared_servers(self):
        """Connect to all shared servers"""
        if not self.authenticated:
            return False, "Not authenticated"

        # Get shared servers
        success, _, servers = self.get_shared_servers()
        if not success:
            return False, "Failed to get shared servers"

        # Connect to each server
        connected_count = 0
        for server in servers:
            ip_address = server.get('ip_address')
            port = server.get('port')

            if ip_address and port:
                # Check if already connected
                already_connected = False
                for conn_id in self.parent_app.connection_manager.connections:
                    connection = self.parent_app.connection_manager.connections[conn_id]
                    if connection.get('host') == ip_address and connection.get('port') == int(port):
                        already_connected = True
                        break

                if not already_connected:
                    # Add the connection
                    self.parent_app.connection_manager.add_connection(ip_address, port)
                    connected_count += 1

        if connected_count > 0:
            return True, f"Connected to {connected_count} shared servers"
        else:
            return True, "No new shared servers to connect to"

    def disconnect(self):
        """Disconnect from the central server"""
        self.connected = False
        self.authenticated = False

        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            finally:
                self.socket = None

        logging.info("Disconnected from central server")