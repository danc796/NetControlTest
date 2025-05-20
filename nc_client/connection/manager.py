import socket
import json
import threading
import time
import logging
from nc_client.connection.encryption import EncryptionManager


class ConnectionManager:
    def __init__(self, parent_app):
        self.parent_app = parent_app
        self.connections = {}

        # Initialize encryption manager
        self.encryption_manager = EncryptionManager()

    def add_connection(self, host, port):
        """Add a new remote connection with auto-reconnect support and automatic sharing"""
        if not host:
            self.parent_app.toast.show_toast("Please enter an IP address", "warning")
            return

        try:
            port = int(port) if port else 5000
            if port < 0 or port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            self.parent_app.toast.show_toast("Invalid port number. Please enter a number between 0-65535", "warning")
            return

        connection_id = f"{host}:{port}"

        # Check if this connection already exists
        if connection_id in self.connections:
            self.parent_app.toast.show_toast(f"Connection to {host}:{port} already exists", "warning")
            return

        # Store connection info first (even before successful connection)
        self.connections[connection_id] = {
            'socket': None,
            'cipher_suite': None,
            'host': host,
            'port': port,
            'system_info': None,
            'connection_active': False,
            'reconnect_attempts': 0,
            'last_reconnect_time': time.time(),
            'is_shared': True  # Default to sharing enabled
        }

        # Add to computer list with 'Connecting' status
        self.parent_app.connection_tab.computer_list.insert('', 'end', connection_id, text=host,
                                                           values=('Connecting...',))

        # Start connection in a separate thread to avoid UI freezing
        connect_thread = threading.Thread(
            target=self.connect_to_server,
            args=(connection_id,)
        )
        connect_thread.daemon = True
        connect_thread.start()

    def connect_to_server(self, connection_id):
        """Connect to server with AES encryption and auto-register with central server"""
        connection = self.connections.get(connection_id)
        if not connection:
            return

        host, port = connection['host'], connection['port']

        try:
            # Create socket with timeout
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5.0)

            # Attempt connection
            client_socket.connect((host, port))

            # Use socket directly
            wrapped_socket = client_socket
            logging.info(f"Connection established with {host}:{port} using AES encryption")

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
                logging.info(f"Received server certificate ({cert_size} bytes)")

            # Get encryption key
            key = wrapped_socket.recv(44)

            # Create a new encryption manager for each connection
            encryption_manager = EncryptionManager()
            encryption_manager.set_encryption_key(key)

            # Update connection info
            self.connections[connection_id]['socket'] = wrapped_socket
            self.connections[connection_id]['cipher_suite'] = encryption_manager
            self.connections[connection_id]['connection_active'] = True
            self.connections[connection_id]['reconnect_attempts'] = 0
            # Always set is_shared to True
            self.connections[connection_id]['is_shared'] = True

            # Update UI from the main thread
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Connected"))

            # Update shared status in UI
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "shared", "Yes"))

            self.parent_app.after(0, lambda h=host, p=port:
            self.parent_app.toast.show_toast(f"Connected to {h}:{p}", "success"))

            # Register with central server automatically if authenticated
            if hasattr(self.parent_app, 'central_client') and self.parent_app.central_client.authenticated:
                # Schedule auto-registration with a slight delay to ensure connection is stable
                self.parent_app.after(500, lambda: self.auto_register_with_central_server(connection_id))

            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self.monitor_connection,
                args=(connection_id,)
            )
            monitor_thread.daemon = True
            monitor_thread.start()

        except (socket.timeout, ConnectionRefusedError) as e:
            # Handle timeouts and connection refusals
            error_msg = "Connection timed out" if isinstance(e, socket.timeout) else "Connection refused"

            # Update UI from the main thread
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Retrying..."))

            self.parent_app.after(0, lambda h=host, p=port, msg=error_msg:
            self.parent_app.toast.show_toast(f"{msg} for {h}:{p}. Retrying...", "warning"))

            # Schedule a reconnection attempt
            self.schedule_reconnection(connection_id)

        except Exception as e:
            # Handle other errors
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Error"))

            self.parent_app.after(0, lambda err=str(e):
            self.parent_app.toast.show_toast(f"Connection error: {err}", "error"))

            # Log the error for troubleshooting
            logging.error(f"Connection error for {host}:{port}: {e}")

    def auto_register_with_central_server(self, connection_id):
        """Automatically register and share the connection with central server"""
        try:
            if not self.parent_app.central_client.authenticated:
                logging.info("Not authenticated with central server, skipping auto-registration")
                return

            connection = self.connections.get(connection_id)
            if not connection or not connection.get('connection_active', False):
                logging.info(f"Connection {connection_id} not active, skipping auto-registration")
                return

            host, port = connection.get('host'), connection.get('port')

            # First register the server
            success, message = self.parent_app.central_client.register_server(host, port)

            if success:
                logging.info(f"Successfully registered server {host}:{port} with central server")

                # Then enable sharing (set to True by default)
                share_success, share_message = self.parent_app.central_client.set_sharing(host, port, True)

                if share_success:
                    logging.info(f"Successfully enabled sharing for {host}:{port}")
                    self.connections[connection_id]['is_shared'] = True
                    self.parent_app.toast.show_toast(f"Server {host}:{port} is now shared with other users", "info")

                    # Update the UI to reflect sharing status
                    self.parent_app.after(0, lambda conn_id=connection_id:
                    self.parent_app.connection_tab.computer_list.set(conn_id, "shared", "Yes"))
                else:
                    logging.warning(f"Failed to enable sharing for {host}:{port}: {share_message}")
            else:
                logging.warning(f"Failed to register server {host}:{port} with central server: {message}")

        except Exception as e:
            logging.error(f"Error during auto-registration with central server: {e}")

    def remove_connection(self, connection_id):
        """Remove selected connection with proper cleanup and unregister from central server"""
        if connection_id in self.connections:
            connection = self.connections[connection_id]

            # First unregister from central server if authenticated
            if hasattr(self.parent_app, 'central_client') and self.parent_app.central_client.authenticated:
                host, port = connection.get('host'), connection.get('port')
                try:
                    self.parent_app.central_client.unregister_server(host, port)
                    logging.info(f"Unregistered server {host}:{port} from central server")
                except Exception as e:
                    logging.error(f"Error unregistering server from central server: {e}")

            # Cancel any scheduled reconnection attempts
            if connection.get('scheduled_reconnect'):
                try:
                    self.parent_app.after_cancel(connection['scheduled_reconnect'])
                except Exception as e:
                    logging.error(f"Error canceling reconnection: {e}")

            # Close socket if it exists
            if connection.get('socket'):
                try:
                    connection['socket'].close()
                except Exception as e:
                    logging.error(f"Error closing socket: {e}")

            # First remove from UI to prevent any further UI updates
            try:
                if connection_id in self.parent_app.connection_tab.computer_list.get_children():
                    self.parent_app.connection_tab.computer_list.delete(connection_id)
            except Exception as e:
                logging.error(f"Error removing connection from UI: {e}")

            # Then remove from connections dictionary
            try:
                del self.connections[connection_id]
            except Exception as e:
                logging.error(f"Error removing connection from dictionary: {e}")

            # Reset active connection if it was the one removed
            if self.parent_app.active_connection == connection_id:
                self.parent_app.active_connection = None

    def send_command(self, connection_id, command_type, data):
        """Send command with AES encryption"""
        connection = self.connections.get(connection_id)
        if not connection:
            print(f"No connection found for ID: {connection_id}")
            return None

        # Check if connection is active, if not try to reconnect first
        if not connection.get('connection_active', False):
            if not self.attempt_reconnection(connection_id):
                return None  # Failed to reconnect, can't send command

        try:
            # Prepare command
            command = {
                'type': command_type,
                'data': data
            }
            print(f"Sending command: {command_type}")

            # Convert to JSON
            json_data = json.dumps(command)

            # Set socket timeout based on command type
            if command_type in ['start_rdp', 'stop_rdp']:
                connection['socket'].settimeout(30.0)  # Longer timeout for these operations
            else:
                connection['socket'].settimeout(10.0)  # Standard timeout

            # Get cipher suite
            cipher_suite = connection.get('cipher_suite')
            if not cipher_suite:
                print("No cipher suite available")
                connection['connection_active'] = False
                return None

            # Encrypt and send data
            encrypted_data = cipher_suite.encrypt_data(json_data)
            connection['socket'].send(encrypted_data)
            print("Command sent successfully")

            # Receive response with timeout handling
            try:
                print("Waiting for response...")
                encrypted_response = connection['socket'].recv(16384)

                # Update last successful communication time
                connection['last_health_check'] = time.time()

                if not encrypted_response:
                    print("Received empty response from server")
                    # Mark connection as inactive to trigger reconnection
                    connection['connection_active'] = False
                    return None

                print(f"Received encrypted response of length: {len(encrypted_response)}")

                # Decrypt the response
                try:
                    decrypted_data = cipher_suite.decrypt_data(encrypted_response)
                    response = json.loads(decrypted_data)
                    print("Response parsed successfully")

                    # Mark as successfully communicated
                    connection['connection_active'] = True
                    connection['reconnect_attempts'] = 0

                    # Set status to Connected if it's not already
                    current_status = self.parent_app.connection_tab.computer_list.item(connection_id, "values")[0]
                    if "Connected" not in current_status:
                        self.parent_app.after(0, lambda conn_id=connection_id:
                        self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Connected"))

                    return response

                except json.JSONDecodeError as e:
                    print(f"JSON parsing error: {str(e)}")
                    # Mark connection as inactive
                    connection['connection_active'] = False
                    return None

            except socket.timeout:
                print(f"Response timeout for {connection_id}")
                # Mark as potentially inactive, but don't immediately disconnect
                # Some operations like power management might not need responses
                if command_type not in ['power_management']:
                    connection['connection_active'] = False
                return None

        except ConnectionResetError:
            print(f"Connection reset for {connection_id}")
            # Mark connection as inactive to trigger reconnection
            connection['connection_active'] = False
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Reconnecting..."))
            self.schedule_reconnection(connection_id)
            return None

        except (BrokenPipeError, OSError) as e:
            print(f"Connection broken for {connection_id}: {str(e)}")
            # Mark connection as inactive to trigger reconnection
            connection['connection_active'] = False
            self.parent_app.after(0, lambda conn_id=connection_id:
            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Reconnecting..."))
            self.schedule_reconnection(connection_id)
            return None

        except Exception as e:
            print(f"Send command error: {str(e)}")
            # Mark connection as inactive
            connection['connection_active'] = False
            return None

    def attempt_reconnection(self, connection_id):
        """Attempt to reconnect to a failed connection with AES encryption"""
        connection = self.connections.get(connection_id)
        if not connection:
            return False

        host, port = connection['host'], connection['port']
        print(f"Attempting to reconnect to {host}:{port}")

        try:
            # Close existing socket if any
            if 'socket' in connection and connection['socket']:
                try:
                    connection['socket'].close()
                except:
                    pass

            # Create new socket with timeout
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(3.0)

            # Attempt connection
            client_socket.connect((host, port))

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
                logging.info(f"Received server certificate on reconnect ({cert_size} bytes)")

            # Get encryption key
            key = wrapped_socket.recv(44)

            # Create a new encryption manager
            encryption_manager = EncryptionManager()
            encryption_manager.set_encryption_key(key)

            # Update connection info
            self.connections[connection_id]['socket'] = wrapped_socket
            self.connections[connection_id]['cipher_suite'] = encryption_manager
            self.connections[connection_id]['connection_active'] = True

            # Log the successful reconnection
            logging.info(f"Successfully reconnected to {host}:{port}")
            self.parent_app.toast.show_toast(f"Reconnected to {host}:{port}", "success")

            return True

        except (socket.timeout, ConnectionRefusedError) as e:
            error_msg = "Connection timed out" if isinstance(e, socket.timeout) else "Connection refused"
            logging.warning(f"Reconnection attempt failed: {error_msg} for {host}:{port}")
            return False

        except Exception as e:
            logging.error(f"Reconnection error: {str(e)}")
            return False

    def attempt_reconnection_from_scheduler(self, connection_id):
        """Attempt reconnection from the scheduler"""
        connection = self.connections.get(connection_id)
        if not connection:
            return

        # Clear the scheduled reconnect ID
        connection['scheduled_reconnect'] = None

        # Update UI
        self.parent_app.connection_tab.computer_list.set(connection_id, "status", "Connecting...")

        # Start a new connection thread
        connect_thread = threading.Thread(
            target=self.connect_to_server,
            args=(connection_id,)
        )
        connect_thread.daemon = True
        connect_thread.start()

    def schedule_reconnection(self, connection_id):
        """Schedule a reconnection attempt with exponential backoff"""
        # First check if connection still exists - if not, just return
        connection = self.connections.get(connection_id)
        if not connection:
            return

        # Check if this connection has been manually disconnected/removed
        if connection_id not in self.parent_app.connection_tab.computer_list.get_children():
            # Connection was manually removed, so don't try to reconnect
            logging.info(f"Not scheduling reconnection for manually removed connection: {connection_id}")
            return

        # Increment retry counter
        connection['reconnect_attempts'] += 1

        # Calculate backoff delay (min 2 seconds, max 60 seconds)
        # Example: 1st retry = 2s, 2nd = 4s, 3rd = 8s, etc. up to 60s max
        backoff = min(2 ** connection['reconnect_attempts'], 60)

        # Update UI - safely check if item exists first
        def update_status():
            try:
                # Double check if the item still exists before updating
                if connection_id in self.parent_app.connection_tab.computer_list.get_children():
                    self.parent_app.connection_tab.computer_list.set(
                        connection_id,
                        "status",
                        f"Retry in {backoff}s"
                    )
            except Exception as e:
                logging.error(f"Error updating UI for {connection_id}: {e}")
                # Don't raise the exception - just log it
                pass

        # Schedule the UI update on the main thread
        self.parent_app.after(0, update_status)

        # Schedule the reconnection - but first check if the connection is still tracked
        def safe_reconnect_callback():
            # Check again if connection still exists and is in UI before attempting reconnection
            if (connection_id in self.connections and
                    connection_id in self.parent_app.connection_tab.computer_list.get_children()):
                self.attempt_reconnection_from_scheduler(connection_id)
            else:
                logging.info(f"Skipping reconnection for removed connection: {connection_id}")

        reconnect_id = self.parent_app.after(
            backoff * 1000,  # Convert to milliseconds
            safe_reconnect_callback
        )

        # Store the reconnection ID so we can cancel it if needed
        connection['scheduled_reconnect'] = reconnect_id
        connection['last_reconnect_time'] = time.time() + backoff

    def monitor_connection(self, connection_id):
        """Monitor individual connection with automatic reconnection"""
        connection = self.connections.get(connection_id)
        if not connection:
            return

        reconnect_delay = 5  # Initial reconnect delay in seconds
        max_reconnect_delay = 60  # Maximum reconnect delay

        while connection_id in self.connections:
            try:
                # Get system info
                response = self.send_command(connection_id, 'system_info', {})
                if response and response.get('status') == 'success':
                    self.connections[connection_id]['system_info'] = response['data']
                    # Reset reconnect delay on successful communication
                    reconnect_delay = 5
                    # Update status in computer list
                    self.parent_app.connection_tab.computer_list.set(connection_id, "status", "Connected")
                    self.connections[connection_id]['connection_active'] = True
                else:
                    # Handle failed response
                    raise ConnectionError("Invalid response from server")

            except Exception as e:
                print(f"Monitoring error for {connection_id}: {str(e)}")
                self.parent_app.connection_tab.computer_list.set(connection_id, "status", "Reconnecting...")
                self.connections[connection_id]['connection_active'] = False

                # Attempt to reconnect
                if self.attempt_reconnection(connection_id):
                    # Successfully reconnected, reset delay
                    reconnect_delay = 5
                    self.parent_app.connection_tab.computer_list.set(connection_id, "status", "Connected")
                    self.connections[connection_id]['connection_active'] = True
                else:
                    # Failed to reconnect, back off and try again later
                    self.parent_app.connection_tab.computer_list.set(connection_id, "status",
                                                                     f"Retry in {reconnect_delay}s")
                    time.sleep(reconnect_delay)
                    # Exponential backoff with maximum
                    reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)

            time.sleep(5)  # Check every 5 seconds

    def initialize_connection_monitoring(self):
        """Initialize connection monitoring thread"""
        # Start connection health monitoring thread
        self.connection_monitor_thread = threading.Thread(
            target=self.monitor_connection_health,
            daemon=True
        )
        self.connection_monitor_thread.start()
        logging.info("Connection health monitoring thread started")

    def monitor_connection_health(self):
        """Periodically check all connections and initiate reconnects as needed"""
        logging.info("Starting connection health monitoring")

        while getattr(self.parent_app, 'running', True):
            try:
                # Iterate through a copy of the connections dict to avoid modification during iteration
                for conn_id, connection in list(self.connections.items()):
                    # Skip connections that are already in reconnection process
                    if connection.get('scheduled_reconnect'):
                        continue

                    # Skip active connections that were recently checked
                    if connection.get('connection_active') and connection.get('last_health_check'):
                        # Only check active connections every 30 seconds
                        if time.time() - connection.get('last_health_check', 0) < 30:
                            continue

                    # Check connection status
                    try:
                        # Very simple ping without extensive processing
                        if connection.get('socket') and connection.get('cipher_suite'):
                            # Send a small ping command
                            try:
                                connection['socket'].settimeout(2.0)  # Short timeout for health check
                                ping_cmd = json.dumps({'type': 'ping', 'data': {}})
                                # Get cipher suite
                                cipher_suite = connection.get('cipher_suite')
                                # Encrypt the data
                                encrypted_data = cipher_suite.encrypt_data(ping_cmd)
                                connection['socket'].send(encrypted_data)

                                # Wait for response
                                encrypted_response = connection['socket'].recv(1024)
                                if encrypted_response:
                                    # If we got any response, mark as active
                                    connection['connection_active'] = True
                                    connection['last_health_check'] = time.time()
                                    connection['reconnect_attempts'] = 0  # Reset counter on success
                                    # Update UI if status doesn't show "Connected"
                                    current_status = \
                                    self.parent_app.connection_tab.computer_list.item(conn_id, "values")[0]
                                    if "Connected" not in current_status:
                                        self.parent_app.after(0, lambda
                                            id=conn_id: self.parent_app.connection_tab.computer_list.set(
                                            id, "status", "Connected"
                                        ))
                                else:
                                    # Empty response, connection may be broken
                                    raise ConnectionError("Empty response")

                            except (socket.timeout, ConnectionError, BrokenPipeError, OSError) as e:
                                # Connection appears to be down
                                connection['connection_active'] = False
                                current_status = self.parent_app.connection_tab.computer_list.item(conn_id, "values")[0]
                                if "Reconnecting" not in current_status:
                                    self.parent_app.after(0, lambda
                                        id=conn_id: self.parent_app.connection_tab.computer_list.set(
                                        id, "status", "Reconnecting..."
                                    ))
                                self.schedule_reconnection(conn_id)

                    except Exception as e:
                        logging.error(f"Health check error for {conn_id}: {str(e)}")

                # Sleep between checks
                time.sleep(5)

            except Exception as e:
                logging.error(f"Connection health monitoring error: {str(e)}")
                time.sleep(10)  # Longer sleep on error

    def close_all_connections(self):
        """Close all active connections"""
        try:
            for conn_id in list(self.connections.keys()):
                try:
                    connection = self.connections.get(conn_id)
                    if connection:
                        # Cancel any scheduled reconnection attempts
                        if connection.get('scheduled_reconnect'):
                            self.parent_app.after_cancel(connection['scheduled_reconnect'])

                        # Close socket if it exists
                        if connection.get('socket'):
                            try:
                                connection['socket'].close()
                            except:
                                pass

                except Exception as e:
                    logging.error(f"Error closing connection {conn_id}: {str(e)}")

            # Clear all connections
            self.connections.clear()
            logging.info("All connections closed")

        except Exception as e:
            logging.error(f"Error in close_all_connections: {str(e)}")