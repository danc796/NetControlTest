"""
Connection Manager for the Central Management Server.
Handles client connections, command processing, and responses.
"""

import socket
import threading
import json
import logging
from datetime import datetime

from central_server.database.manager import DatabaseManager
from central_server.connection.encryption import EncryptionManager
from central_server.auth.user_manager import UserManager
from central_server.utils.logging import log_connection, log_server_action, log_error


class ConnectionManager:
    def __init__(self, host='0.0.0.0', port=5001):
        """Initialize the central server connection manager with AES encryption"""
        logging.info("Initializing Central Server Connection Manager with AES encryption")

        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # Address -> client info

        # Initialize the encryption manager with AES
        self.encryption_manager = EncryptionManager()
        self.encryption_key = self.encryption_manager.encryption_key

        # Initialize database manager
        self.database = DatabaseManager()

        # Initialize user manager
        self.user_manager = UserManager(self.database)

        self.running = True

        # Command handlers mapping
        self.command_handlers = {
            'login': self.handle_login,
            'register_server': self.handle_register_server,
            'unregister_server': self.handle_unregister_server,
            'set_sharing': self.handle_set_sharing,
            'get_all_servers': self.handle_get_all_servers,
            'get_shared_servers': self.handle_get_shared_servers,
            'get_user_connections': self.handle_get_user_connections,
            'get_connection_details': self.handle_get_connection_details,
            'create_user': self.handle_create_user,
            'get_all_users': self.handle_get_all_users,
            'change_password': self.handle_change_password,
            'delete_user': self.handle_delete_user,
            'promote_to_admin': self.handle_promote_to_admin,
            'ping': self.handle_ping
        }

    def start(self):
        """Start the server and listen for connections"""
        try:
            # Configure the socket for reuse
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            logging.info(f"Central server started on {self.host}:{self.port} with AES encryption")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    logging.info(f"New connection from {address}")

                    # Start client handler thread
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_handler.daemon = True
                    client_handler.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting connection: {e}")
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.stop()

    def handle_client(self, client_socket, address):
        """Handle client connection with AES encryption"""
        try:
            # Use socket directly
            wrapped_socket = client_socket
            log_connection(address, action="established connection with AES encryption")

            # Set a timeout for operations
            wrapped_socket.settimeout(5.0)

            # For backward compatibility, send dummy certificate size (0 bytes)
            wrapped_socket.send((0).to_bytes(4, byteorder='big'))

            # Send encryption key
            wrapped_socket.send(self.encryption_key)

            # Longer timeout for regular operations
            wrapped_socket.settimeout(30.0)

            # Store client information
            self.clients[address] = {
                'socket': wrapped_socket,
                'last_seen': datetime.now(),
                'user_id': None,
                'username': None
            }

            # Main communication loop
            while self.running:
                try:
                    # Receive encrypted data
                    data = wrapped_socket.recv(4096)
                    if not data:
                        logging.info(f"Client {address} disconnected (empty data)")
                        break

                    # Decrypt the data
                    try:
                        decrypted_data = self.encryption_manager.decrypt_data(data)
                        command = json.loads(decrypted_data)

                        # Process the command
                        response = self.process_command(command, address)

                        # Encrypt and send response
                        response_json = json.dumps(response)
                        encrypted_response = self.encryption_manager.encrypt_data(response_json)
                        wrapped_socket.send(encrypted_response)

                    except json.JSONDecodeError as e:
                        logging.error(f"Invalid JSON from {address}: {e}")
                        continue

                except socket.timeout:
                    # Just continue on timeout (this is normal)
                    continue
                except Exception as e:
                    logging.error(f"Error handling client {address}: {e}")
                    break

        except Exception as e:
            log_error(f"Client handler error for {address}", e)
        finally:
            # Clean up client connection
            client_info = self.clients.pop(address, None)

            if client_info and client_info.get('username'):
                username = client_info.get('username')
                client_ip = address[0]

                # Find all connections made by this client
                try:
                    conn = self.database.get_connection()
                    cursor = conn.cursor()

                    # Find servers registered by this client
                    cursor.execute(
                        "SELECT server_id, ip_address FROM active_connections WHERE connect_by = ?",
                        (client_ip,)
                    )

                    servers = cursor.fetchall()

                    # Remove from active_connections
                    if servers:
                        for server in servers:
                            cursor.execute(
                                "DELETE FROM active_connections WHERE server_id = ?",
                                (server['server_id'],)
                            )

                        conn.commit()
                        log_connection(address, username, f"disconnected and removed {len(servers)} connections")

                    conn.close()

                    # Also remove from sharing lists
                    success, message = self.database.clean_disconnected_user(username)
                    if not success:
                        log_error(f"Error removing user from sharing lists: {username}", message)

                except Exception as e:
                    log_error(f"Error during disconnection cleanup for {username}", e)

                log_connection(address, username, "disconnected")

            try:
                client_socket.close()
            except Exception as close_error:
                logging.error(f"Error closing socket: {close_error}")

            logging.info(f"Connection closed from {address}")

    def process_command(self, command, address):
        """Process client command and return response"""
        try:
            cmd_type = command.get('type', '')
            cmd_data = command.get('data', {})

            # Debug logging
            logging.debug(f"Received command: {cmd_type} with data: {cmd_data}")

            # Get the appropriate handler for this command type
            handler = self.command_handlers.get(cmd_type)

            if handler:
                # Ensure cmd_data is a dictionary
                if not isinstance(cmd_data, dict):
                    cmd_data = {}

                # Special handling for commands that need authentication
                client_info = self.clients.get(address, {})
                user_id = client_info.get('user_id')

                # Login doesn't need authentication, but other commands do
                if cmd_type != 'login' and cmd_type != 'ping' and not user_id:
                    return {'status': 'error', 'message': 'Authentication required'}

                # Call the handler with the command data
                return handler(cmd_data, address)
            else:
                logging.warning(f"Unknown command received: {cmd_type}")
                return {'status': 'error', 'message': f'Unknown command: {cmd_type}'}

        except Exception as e:
            logging.error(f"Error processing command: {str(e)}")
            return {'status': 'error', 'message': 'Internal server error'}

    def handle_login(self, data, address):
        """Handle login request"""
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'status': 'error', 'message': 'Username and password are required'}

        success, user = self.user_manager.authenticate_user(username, password)

        if success:
            # Store user info in client connection
            self.clients[address]['user_id'] = user['user_id']

            # Add these two lines here:
            self.clients[address]['username'] = user['username']
            log_connection(address, user['username'], "authenticated")

            logging.info(f"User {username} logged in successfully")

            return {
                'status': 'success',
                'message': 'Login successful',
                'data': {
                    'user_id': user['user_id'],
                    'username': user['username'],
                    'is_admin': user['is_admin']
                }
            }
        else:
            logging.warning(f"Failed login attempt for username: {username}")
            return {'status': 'error', 'message': 'Invalid username or password'}

    def handle_register_server(self, data, address):
        """Handle server registration"""
        ip_address = data.get('ip_address')
        port = data.get('port')

        if not ip_address or not port:
            return {'status': 'error', 'message': 'IP address and port are required'}

        username = self.clients[address]['username']
        client_ip = address[0]  # Extract client IP from address tuple

        success, message = self.database.register_server(ip_address, port, client_ip)

        if success:
            log_server_action(address, username, ip_address, port, "registered")
        else:
            log_error(f"Failed to register server {ip_address}:{port} for user {username}: {message}")

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_unregister_server(self, data, address):
        """Handle server unregistration"""
        ip_address = data.get('ip_address')
        port = data.get('port')

        if not ip_address or not port:
            return {'status': 'error', 'message': 'IP address and port are required'}

        username = self.clients[address]['username']

        # First, ensure we're removed from sharing list
        self.database.set_connection_sharing(ip_address, port, False, username)

        # Then unregister the server connection
        success, message = self.database.unregister_server(ip_address, port)

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_set_sharing(self, data, address):
        """Handle connection sharing setting"""
        ip_address = data.get('ip_address')
        port = data.get('port')
        is_shared = data.get('is_shared', False)

        if not ip_address or not port:
            return {'status': 'error', 'message': 'IP address and port are required'}

        username = self.clients[address]['username']

        success, message = self.database.set_connection_sharing(
            ip_address, port, is_shared, username
        )

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_get_all_servers(self, data, address):
        """Handle request for all active servers"""
        servers = self.database.get_all_active_servers()

        return {
            'status': 'success',
            'data': servers
        }

    def handle_get_shared_servers(self, data, address):
        """Handle request for shared servers"""
        servers = self.database.get_shared_servers()

        return {
            'status': 'success',
            'data': servers
        }

    def handle_get_user_connections(self, data, address):
        """Handle request for user's connections"""
        username = self.clients[address]['username']
        connections = self.database.get_user_connections(username)

        return {
            'status': 'success',
            'data': connections
        }

    def handle_get_connection_details(self, data, address):
        """Handle request for detailed connection information"""
        user_id = self.clients[address]['user_id']
        username = self.clients[address]['username']

        # Only admins can see all connection details
        is_admin = False
        try:
            conn = self.database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            is_admin = result and result['is_admin'] == 1
            conn.close()
        except Exception as e:
            logging.error(f"Error checking admin status: {e}")

        if not is_admin:
            return {
                'status': 'error',
                'message': 'Admin privileges required to view all connection details'
            }

        # Get connection details with the format requested
        connections = self.database.get_all_connection_details()

        log_connection(address, username, "retrieved connection details")

        return {
            'status': 'success',
            'data': connections
        }

    def handle_ping(self, data, address):
        """Handle ping request"""
        # Update last seen time
        if address in self.clients:
            self.clients[address]['last_seen'] = datetime.now()

        return {
            'status': 'success',
            'message': 'pong',
            'timestamp': str(datetime.now())
        }

    def handle_create_user(self, data, address):
        """Handle user creation request from an admin"""
        # Get admin user information
        admin_id = self.clients[address]['user_id']
        admin_username = self.clients[address]['username']

        # Get new user information
        new_username = data.get('username')
        new_password = data.get('password')
        is_admin = data.get('is_admin', False)

        if not new_username or not new_password:
            return {'status': 'error', 'message': 'Username and password are required'}

        # Create the user
        success, message = self.user_manager.create_user_as_admin(
            admin_id, new_username, new_password, is_admin
        )

        if success:
            log_connection(address, admin_username, f"created new user '{new_username}'")

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_get_all_users(self, data, address):
        """Handle request for all users (admin only)"""
        user_id = self.clients[address]['user_id']
        username = self.clients[address]['username']

        # Only admins can see all users
        is_admin = False
        try:
            conn = self.database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            is_admin = result and result['is_admin'] == 1
            conn.close()
        except Exception as e:
            logging.error(f"Error checking admin status: {e}")

        if not is_admin:
            return {
                'status': 'error',
                'message': 'Admin privileges required to view all users'
            }

        # Get all users
        users = self.user_manager.get_all_users()

        log_connection(address, username, "retrieved all users")

        return {
            'status': 'success',
            'data': users
        }

    def handle_change_password(self, data, address):
        """Handle password change request"""
        user_id = self.clients[address]['user_id']
        username = self.clients[address]['username']
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not old_password or not new_password:
            return {'status': 'error', 'message': 'Old and new passwords are required'}

        success, message = self.user_manager.change_password(user_id, old_password, new_password)

        if success:
            log_connection(address, username, "changed password")

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_delete_user(self, data, address):
        """Handle user deletion request (admin only)"""
        admin_id = self.clients[address]['user_id']
        admin_username = self.clients[address]['username']
        username_to_delete = data.get('username')

        if not username_to_delete:
            return {'status': 'error', 'message': 'Username is required'}

        # Verify admin status
        is_admin = False
        try:
            conn = self.database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (admin_id,))
            result = cursor.fetchone()
            is_admin = result and result['is_admin'] == 1
            conn.close()
        except Exception as e:
            logging.error(f"Error checking admin status: {e}")

        if not is_admin:
            return {
                'status': 'error',
                'message': 'Admin privileges required to delete users'
            }

        # Delete the user
        success, message = self.user_manager.delete_user(username_to_delete)

        if success:
            log_connection(address, admin_username, f"deleted user '{username_to_delete}'")

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def handle_promote_to_admin(self, data, address):
        """Handle request to promote user to admin (admin only)"""
        admin_id = self.clients[address]['user_id']
        admin_username = self.clients[address]['username']
        username_to_promote = data.get('username')

        if not username_to_promote:
            return {'status': 'error', 'message': 'Username is required'}

        # Verify admin status
        is_admin = False
        try:
            conn = self.database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (admin_id,))
            result = cursor.fetchone()
            is_admin = result and result['is_admin'] == 1
            conn.close()
        except Exception as e:
            logging.error(f"Error checking admin status: {e}")

        if not is_admin:
            return {
                'status': 'error',
                'message': 'Admin privileges required to promote users'
            }

        # Promote the user
        success, message = self.user_manager.promote_to_admin(username_to_promote)

        if success:
            log_connection(address, admin_username, f"promoted user '{username_to_promote}' to admin")

        return {
            'status': 'success' if success else 'error',
            'message': message
        }

    def stop(self):
        """Stop the server and clean up connections"""
        logging.info("Shutting down central server...")
        self.running = False

        # Close all client connections
        for client in list(self.clients.values()):
            try:
                client['socket'].close()
            except:
                pass

        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass

        logging.info("Central server shutdown complete")