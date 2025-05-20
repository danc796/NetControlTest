import socket
import threading
import logging
import sys
import tkinter as tk
import time
import struct
from PIL import Image, ImageTk
import cv2
import numpy as np


class RDPClient:
    def __init__(self, parent_app):
        self.parent_app = parent_app
        self.rdp_active = False
        self.rdp_socket = None
        self.rdp_display_thread = None
        self.rdp_connection = None
        self.rdp_tab_active = False
        self.server_width = None
        self.server_height = None
        self.image_x = 0
        self.image_y = 0
        self.scale_factor = 1.0
        self.image_id = None
        self.last_move_time = 0
        self.move_throttle = 0.02  # 50 Hz maximum for mouse movement

        # UI references - these will be set when needed
        self.rdp_tab = None
        self.x_offset = None
        self.y_offset = None

    def register_ui(self, rdp_tab):
        """Register UI elements from the RDP tab"""
        self.rdp_tab = rdp_tab
        self.x_offset = rdp_tab.x_offset
        self.y_offset = rdp_tab.y_offset

    def toggle_rdp(self):
        """Toggle RDP session on/off"""
        if not self.rdp_active:
            self.start_rdp()
        else:
            self.stop_rdp()

    def start_rdp(self):
        """Start integrated RDP session with enhanced UI feedback"""
        if not self.parent_app.active_connection:
            self.rdp_tab.rdt_status.configure(text="Please select a computer first")
            return

        try:
            # Request RDP server start
            response = self.parent_app.connection_manager.send_command(
                self.parent_app.active_connection, 'start_rdp', {})

            if response and response.get('status') == 'success':
                ip, port = response['data']['ip'], response['data']['port']

                # Update status with clear feedback
                self.rdp_tab.rdt_status.configure(text="Connecting to remote desktop...")

                # Update status in the control panel
                self.rdp_tab.rdp_status_indicator.configure(
                    text=f"Connecting to {self.parent_app.connection_manager.connections[self.parent_app.active_connection]['host']}...",
                    text_color="#FFAA00"
                )

                self.rdp_tab.rdp_button.configure(text="Connecting...", state="disabled")

                # Create a socket
                self.rdp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.rdp_socket.settimeout(5.0)
                self.rdp_socket.connect((ip, port))

                # Send platform info
                platform_code = b'win' if sys.platform == "win32" else b'osx' if sys.platform == "darwin" else b'x11'
                self.rdp_socket.sendall(platform_code)

                # Hide the welcome message
                self.rdp_tab.rdp_message.place_forget()

                # Set up display thread
                self.rdp_active = True
                self.rdp_connection = self.parent_app.active_connection
                self.rdp_display_thread = threading.Thread(target=self.rdp_display_loop)
                self.rdp_display_thread.daemon = True
                self.rdp_display_thread.start()

                # Set up input handlers
                self.setup_rdp_input_handlers()

                # Update UI with successful connection status
                self.rdp_tab.rdt_status.configure(text="Remote desktop session active")

                # Update status in the control panel
                self.rdp_tab.rdp_status_indicator.configure(
                    text=f"Connected to {self.parent_app.connection_manager.connections[self.parent_app.active_connection]['host']}",
                    text_color="#00CC00"  # Green for active connection
                )

                self.rdp_tab.rdp_button.configure(text="Connected", state="disabled")
                self.rdp_tab.rdp_close_button.configure(state="normal")
            else:
                self.rdp_tab.rdt_status.configure(text="Failed to start remote desktop")

                # Update status in the control panel
                self.rdp_tab.rdp_status_indicator.configure(
                    text="Connection failed",
                    text_color="#FF0000"  # Red for error
                )

                self.rdp_tab.rdp_button.configure(text="Start Remote Desktop", state="normal")
        except Exception as e:
            self.rdp_tab.rdt_status.configure(text=f"RDP Error: {str(e)}")

            # Update status in the control panel
            self.rdp_tab.rdp_status_indicator.configure(
                text="Connection error",
                text_color="#FF0000"  # Red for error
            )

            logging.error(f"RDP error: {str(e)}")
            self.rdp_tab.rdp_button.configure(text="Start Remote Desktop", state="normal")
            self.stop_rdp()

    def stop_rdp(self):
        """Simplified stop RDP function"""
        try:
            self.rdp_active = False

            # Close socket
            if self.rdp_socket:
                try:
                    self.rdp_socket.close()
                except:
                    pass
                self.rdp_socket = None

            # Clear display
            if hasattr(self.rdp_tab, 'rdp_canvas'):
                self.rdp_tab.rdp_canvas.delete("all")
                # Show welcome message again
                self.rdp_tab.rdp_message.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

            # Stop RDP server
            if self.rdp_connection:
                self.parent_app.connection_manager.send_command(self.rdp_connection, 'stop_rdp', {})
                self.rdp_connection = None

            # Update status
            self.rdp_tab.rdt_status.configure(text="Remote desktop session ended")

            # Update status indicator
            self.rdp_tab.rdp_status_indicator.configure(text="Not connected", text_color="#888888")

            # Update buttons - always reset to initial state
            self.rdp_tab.rdp_button.configure(text="Start Remote Desktop", state="normal")
            self.rdp_tab.rdp_close_button.configure(state="disabled")

        except Exception as e:
            logging.error(f"Error stopping RDP: {str(e)}")

            # Force reset of critical UI elements even if there was an error
            self.rdp_tab.rdp_button.configure(text="Start Remote Desktop", state="normal")

    # === Display functionality ===

    def receive_rdp_frame(self):
        """Receive a frame from the RDP server"""
        # Get header
        header = self.receive_exact(5)
        img_type, length = struct.unpack(">BI", header)

        # Get image data
        img_data = b''
        buffer_size = 10240
        while length > 0:
            chunk_size = min(buffer_size, length)
            chunk = self.receive_exact(chunk_size)
            img_data += chunk
            length -= len(chunk)

        return img_type, img_data

    def receive_exact(self, size):
        """Receive exact number of bytes"""
        data = b''
        while len(data) < size and self.rdp_active:
            try:
                chunk = self.rdp_socket.recv(size - len(data))
                if not chunk:
                    raise ConnectionError("Connection lost")
                data += chunk
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Error receiving data: {str(e)}")
                raise
        return data

    def rdp_display_loop(self):
        """Display loop for RDP with proper resolution handling and positioning"""
        try:
            last_image = None

            # First, receive the server resolution information
            try:
                resolution_header = self.receive_exact(9)
                msg_type, width, height = struct.unpack(">BII", resolution_header)

                if msg_type == 0:  # Resolution info message
                    self.server_width = width
                    self.server_height = height
                    print(f"Received server resolution: {self.server_width}x{self.server_height}")
            except Exception as e:
                logging.error(f"Error receiving resolution: {str(e)}")

            # Initialize image placement tracking
            self.image_x = 0
            self.image_y = 0
            self.scale_factor = 1.0
            self.image_id = None

            # Track the last time we had a full redraw
            last_full_redraw = time.time()

            while self.rdp_active:
                try:
                    img_type, img_data = self.receive_rdp_frame()

                    # Process image
                    np_arr = np.frombuffer(img_data, dtype=np.uint8)
                    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

                    if img is None:
                        print("Warning: Failed to decode image, skipping frame")
                        continue

                    if img_type == 0 and last_image is not None:  # Diff frame
                        img = cv2.bitwise_xor(last_image, img)

                    last_image = img.copy()

                    # Convert to PIL format
                    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                    pil_img = Image.fromarray(img_rgb)

                    # Update canvas if it exists
                    canvas = self.rdp_tab.rdp_canvas
                    if canvas:
                        # Get canvas dimensions (with check for initialization)
                        canvas_width = canvas.winfo_width() or 800
                        canvas_height = canvas.winfo_height() or 600

                        # Original image dimensions
                        img_width, img_height = pil_img.size

                        # Only resize if needed and if canvas dimensions are valid
                        if (canvas_width > 10 and canvas_height > 10 and
                                (img_width > canvas_width or img_height > canvas_height)):

                            # Calculate scales with preserved aspect ratio
                            width_scale = canvas_width / img_width
                            height_scale = canvas_height / img_height
                            scale = min(width_scale, height_scale)

                            # New dimensions
                            new_width = int(img_width * scale)
                            new_height = int(img_height * scale)

                            # Update scale factor for coordinate mapping
                            self.scale_factor = img_width / new_width  # From display to server

                            # Resize image
                            pil_img = pil_img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                        else:
                            # Direct 1:1 mapping
                            self.scale_factor = 1.0

                        # Calculate position to center the image
                        self.image_x = max(0, (canvas_width - pil_img.width) // 2)
                        self.image_y = max(0, (canvas_height - pil_img.height) // 2)

                        # Convert to PhotoImage
                        photo_img = ImageTk.PhotoImage(image=pil_img)

                        # Current time for redraw decision
                        current_time = time.time()

                        # Clear and redraw everything periodically (every 2 seconds)
                        # to prevent artifacts from building up
                        if current_time - last_full_redraw > 2.0:
                            canvas.delete("all")
                            self.image_id = canvas.create_image(
                                self.image_x, self.image_y,
                                anchor=tk.NW,
                                image=photo_img
                            )
                            last_full_redraw = current_time
                        else:
                            # If we have an existing image, just update its image
                            if self.image_id and canvas.type(self.image_id) == "image":
                                canvas.itemconfig(self.image_id, image=photo_img)
                            else:
                                # If no existing image or it's not valid, create a new one
                                canvas.delete("all")
                                self.image_id = canvas.create_image(
                                    self.image_x, self.image_y,
                                    anchor=tk.NW,
                                    image=photo_img
                                )

                        # Keep reference to prevent garbage collection
                        canvas.photo = photo_img

                except socket.timeout:
                    # Timeout is expected, just continue
                    continue
                except ConnectionError as ce:
                    logging.error(f"Connection error: {ce}")
                    break
                except Exception as e:
                    logging.error(f"Error in RDP display loop: {e}")
                    # Don't break on minor display errors, just continue
                    continue

        except Exception as e:
            logging.error(f"RDP display error: {e}")
        finally:
            # Clean up on exit
            self.parent_app.after(0, self.stop_rdp)

    # === Input functionality ===

    def setup_rdp_input_handlers(self):
        """Set up input handlers for RDP with built-in cursor position correction"""
        canvas = self.rdp_tab.rdp_canvas
        if not canvas:
            return

        # Mouse constants
        MOUSE_LEFT = 201
        MOUSE_SCROLL = 202
        MOUSE_RIGHT = 203
        MOUSE_MOVE = 204

        # Function to map canvas coordinates to server coordinates with built-in correction
        def map_to_server_coordinates(event):
            """Map canvas coordinates to server coordinates with fixed correction"""
            try:
                # Get coordinates relative to canvas
                canvas_x = event.x
                canvas_y = event.y

                # Apply the image position offset
                rel_x = canvas_x - self.image_x
                rel_y = canvas_y - self.image_y

                # Apply scaling to get server coordinates
                server_x = int(rel_x * self.scale_factor)
                server_y = int(rel_y * self.scale_factor)

                # Apply offsets from UI sliders
                server_x += self.x_offset.get()
                server_y += self.y_offset.get()

                # Ensure coordinates are within server bounds
                if self.server_width and self.server_height:
                    server_x = max(0, min(server_x, self.server_width - 1))
                    server_y = max(0, min(server_y, self.server_height - 1))

                return server_x, server_y
            except Exception as e:
                print(f"Coordinate mapping error: {e}")
                # Fallback to original coordinates
                return event.x, event.y

        def mouse_event_handler(event_type, action, event):
            """Handle mouse events with server coordinate mapping"""
            try:
                server_x, server_y = map_to_server_coordinates(event)
                self.send_rdp_mouse_event(event_type, action, server_x, server_y)
            except Exception as e:
                print(f"Mouse event error: {e}")

        def motion_handler(event):
            """Handle mouse motion with throttling"""
            current_time = time.time()
            elapsed = current_time - self.last_move_time

            if elapsed >= self.move_throttle:
                self.last_move_time = current_time
                mouse_event_handler(MOUSE_MOVE, 0, event)

        # Bind mouse events
        canvas.bind("<Button-1>", lambda e: mouse_event_handler(MOUSE_LEFT, 100, e))
        canvas.bind("<ButtonRelease-1>", lambda e: mouse_event_handler(MOUSE_LEFT, 117, e))
        canvas.bind("<Button-3>", lambda e: mouse_event_handler(MOUSE_RIGHT, 100, e))
        canvas.bind("<ButtonRelease-3>", lambda e: mouse_event_handler(MOUSE_RIGHT, 117, e))
        canvas.bind("<Motion>", motion_handler)

        # Ensure canvas gets focus when clicked
        canvas.bind("<Button>", lambda e: canvas.focus_set())

        # Mouse wheel handling
        if sys.platform in ("win32", "darwin"):
            canvas.bind("<MouseWheel>",
                        lambda e: mouse_event_handler(MOUSE_SCROLL,
                                                      1 if e.delta > 0 else 0, e))
        else:
            canvas.bind("<Button-4>",
                        lambda e: mouse_event_handler(MOUSE_SCROLL, 1, e))
            canvas.bind("<Button-5>",
                        lambda e: mouse_event_handler(MOUSE_SCROLL, 0, e))

        # Keyboard events
        def handle_key_press(event):
            if self.rdp_tab_active and self.rdp_active:
                self.send_rdp_key_event(event.keysym, 100)

        def handle_key_release(event):
            if self.rdp_tab_active and self.rdp_active:
                self.send_rdp_key_event(event.keysym, 117)

        # Bind keyboard events
        canvas.bind("<KeyPress>", handle_key_press)
        canvas.bind("<KeyRelease>", handle_key_release)

        # Set focus to canvas
        canvas.focus_set()

    def send_rdp_mouse_event(self, button, action, x, y):
        """Send mouse event to RDP server"""
        if not self.rdp_active or not self.rdp_socket:
            return

        try:
            self.rdp_socket.sendall(struct.pack('>BBHH', button, action, x, y))
        except Exception as e:
            logging.error(f"Error sending mouse event: {str(e)}")
            self.stop_rdp()

    def send_rdp_key_event(self, key, action):
        """Send keyboard event to RDP server - simplified implementation"""
        if not self.rdp_active or not self.rdp_socket:
            return

        try:
            # Simple mapping of common keys to scan codes
            # This is a basic implementation - a full implementation would map all keys
            key_map = {
                'a': 30, 'b': 48, 'c': 46, 'd': 32, 'e': 18, 'f': 33, 'g': 34, 'h': 35,
                'i': 23, 'j': 36, 'k': 37, 'l': 38, 'm': 50, 'n': 49, 'o': 24, 'p': 25,
                'q': 16, 'r': 19, 's': 31, 't': 20, 'u': 22, 'v': 47, 'w': 17, 'x': 45,
                'y': 21, 'z': 44, '1': 2, '2': 3, '3': 4, '4': 5, '5': 6, '6': 7, '7': 8,
                '8': 9, '9': 10, '0': 11, 'space': 57, 'Return': 28, 'Escape': 1,
                'BackSpace': 14, 'Tab': 15, 'Left': 75, 'Right': 77, 'Up': 72, 'Down': 80
            }

            # Convert key to lowercase for consistency
            key_lower = key.lower()

            # Get scan code
            scan_code = key_map.get(key_lower, key_map.get(key, 0))

            # Send key event
            if scan_code > 0:
                self.rdp_socket.sendall(struct.pack('>BBHH', scan_code, action, 0, 0))
        except Exception as e:
            logging.error(f"Error sending key event: {str(e)}")