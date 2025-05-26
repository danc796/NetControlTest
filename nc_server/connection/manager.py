import socket
import threading
import json
import logging
import time
from datetime import datetime
import struct

from nc_server.monitoring.system_info import get_system_info
from nc_server.monitoring.hardware import get_hardware_info
from nc_server.monitoring.network import get_network_info
from nc_server.power.controller import handle_power_action
from nc_server.rdp.server import RDPServer
from nc_server.connection.encryption import EncryptionManager


class ConnectionManager:
    def __init__(self, host='0.0.0.0', port=5000):
        """Initialize the connection manager with AES encryption"""
        logging.info("Initializing NC Server Connection Manager with AES encryption")

        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}

        # Initialize the encryption manager with AES
        self.encryption_manager = EncryptionManager()
        self.encryption_key = self.encryption_manager.encryption_key

        self.running = True

        self.rdp_server = None
        self.rdp_thread = None

        # Command handlers mapping
        self.command_handlers = {
            'system_info': self.handle_system_info,
            'hardware_monitor': self.handle_hardware_monitor,
            'power_management': self.handle_power_management,
            'execute_command': self.handle_command_execution,
            'network_monitor': self.handle_network_monitor,
            'start_rdp': self.handle_start_rdp,
            'stop_rdp': self.handle_stop_rdp,
            'ping': self.handle_ping
        }

    def start(self):
        """Start the server and listen for connections"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            logging.info(f"Server started on {self.host}:{self.port} with AES encryption")

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
        """Handle client connection with RSA + AES hybrid encryption"""
        encryption_manager = None
        try:
            # Use socket directly
            wrapped_socket = client_socket
            logging.info(f"Connection established with {address} using RSA + AES hybrid encryption")

            # Set a timeout for operations
            wrapped_socket.settimeout(10.0)

            # Create individual encryption manager for this client
            encryption_manager = EncryptionManager()

            # Step 1: Send RSA public key to client
            public_key_bytes = encryption_manager.get_public_key_bytes()
            public_key_size = len(public_key_bytes)

            # Send public key size first
            wrapped_socket.send(struct.pack('>I', public_key_size))
            # Send public key
            wrapped_socket.send(public_key_bytes)

            logging.info(f"Sent RSA public key ({public_key_size} bytes) to {address}")

            # Step 2: Receive encrypted AES key from client
            encrypted_key_size_bytes = wrapped_socket.recv(4)
            if len(encrypted_key_size_bytes) != 4:
                raise ConnectionError("Failed to receive encrypted key size")

            encrypted_key_size = struct.unpack('>I', encrypted_key_size_bytes)[0]

            # Receive encrypted AES key
            encrypted_key = b''
            while len(encrypted_key) < encrypted_key_size:
                chunk = wrapped_socket.recv(encrypted_key_size - len(encrypted_key))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving encrypted key")
                encrypted_key += chunk

            logging.info(f"Received encrypted AES key ({encrypted_key_size} bytes) from {address}")

            # Step 3: Decrypt and set the AES key
            if not encryption_manager.set_client_encryption_key(encrypted_key):
                raise Exception("Failed to decrypt client AES key")

            # Shorter timeout for regular operations
            wrapped_socket.settimeout(1.0)

            # Store client information with individual encryption manager
            self.clients[address] = {
                'socket': wrapped_socket,
                'encryption_manager': encryption_manager,
                'last_seen': datetime.now(),
                'system_info': get_system_info()
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
                        decrypted_data = encryption_manager.decrypt_data(data)
                        command = json.loads(decrypted_data)

                        # Process the command
                        response = self.process_command(command)

                        # Encrypt and send response
                        response_json = json.dumps(response)
                        encrypted_response = encryption_manager.encrypt_data(response_json)
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
            logging.error(f"Client handler error for {address}: {e}")
        finally:
            # Clean up client connection
            self.clients.pop(address, None)
            try:
                client_socket.close()
            except Exception as close_error:
                logging.error(f"Error closing socket: {close_error}")

            logging.info(f"Connection closed from {address}")

    def process_command(self, command):
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

                # Call the handler with the command data
                return handler(cmd_data)
            else:
                logging.warning(f"Unknown command received: {cmd_type}")
                return {'status': 'error', 'message': f'Unknown command: {cmd_type}'}

        except Exception as e:
            logging.error(f"Error processing command: {str(e)}")
            return {'status': 'error', 'message': 'Internal server error'}

    def handle_system_info(self, data):
        """Handle system information request"""
        return {
            'status': 'success',
            'data': get_system_info()
        }

    def handle_hardware_monitor(self, data):
        """Handle hardware monitoring request"""
        return {
            'status': 'success',
            'data': get_hardware_info()
        }

    def handle_power_management(self, data):
        """Handle power management request"""
        action = data.get('action')
        seconds = data.get('seconds')
        return handle_power_action(action, seconds)

    def handle_command_execution(self, data):
        """Handle command execution request"""
        import subprocess
        command = data.get('command')
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                'status': 'success',
                'data': {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'return_code': result.returncode
                }
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def handle_network_monitor(self, data):
        """Handle network monitoring request"""
        return {
            'status': 'success',
            'data': get_network_info()
        }

    def handle_ping(self, data):
        """Handle ping request (for connection testing)"""
        return {
            'status': 'success',
            'message': 'pong'
        }

    def handle_start_rdp(self, data):
        """Start RDP server"""
        try:
            # Force close any existing RDP server
            if self.rdp_server is not None:
                logging.info("Stopping existing RDP server before starting a new one")
                self.rdp_server.stop()
                self.rdp_server = None

                # Wait for thread to terminate
                if self.rdp_thread and self.rdp_thread.is_alive():
                    self.rdp_thread.join(timeout=2)
                    self.rdp_thread = None

                # Wait for resources to be released
                time.sleep(1)

            # Use the actual server's IP
            rdp_host = socket.gethostbyname(socket.gethostname())
            rdp_port = 5900  # Default RDP port

            # Create and start RDP server
            self.rdp_server = RDPServer(host='0.0.0.0', port=rdp_port)
            self.rdp_thread = threading.Thread(target=self.rdp_server.start)
            self.rdp_thread.daemon = True
            self.rdp_thread.start()

            # Wait for server to start
            time.sleep(1.5)

            return {
                'status': 'success',
                'data': {
                    'ip': rdp_host,
                    'port': rdp_port
                }
            }
        except Exception as e:
            logging.error(f"Failed to start RDP server: {e}")

            # Clean up in case of error
            if hasattr(self, 'rdp_server') and self.rdp_server:
                try:
                    self.rdp_server.stop()
                    self.rdp_server = None
                except:
                    pass

            return {
                'status': 'error',
                'message': str(e)
            }

    def handle_stop_rdp(self, data):
        """Stop RDP server"""
        try:
            if self.rdp_server:
                logging.info("Stopping RDP server")
                self.rdp_server.stop()
                self.rdp_server = None

                # Clean up thread reference
                if self.rdp_thread:
                    if self.rdp_thread.is_alive():
                        self.rdp_thread.join(timeout=3)
                    self.rdp_thread = None

                return {'status': 'success', 'message': 'RDP server stopped successfully'}
            else:
                return {'status': 'success', 'message': 'No RDP server was running'}
        except Exception as e:
            logging.error(f"Error stopping RDP server: {e}")

            # Force reset server state even if there's an error
            self.rdp_server = None
            self.rdp_thread = None

            return {'status': 'error', 'message': f'Error stopping RDP server: {e}'}

    def stop(self):
        """Stop the server and clean up connections"""
        logging.info("Shutting down server...")
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

        # Stop RDP server if running
        if self.rdp_server:
            try:
                self.rdp_server.stop()
            except:
                pass

        logging.info("Server shutdown complete")