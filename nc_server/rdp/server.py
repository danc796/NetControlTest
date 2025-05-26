import socket
import threading
import logging
import time
import numpy as np
import cv2
from PIL import ImageGrab
import struct
import pyautogui as ag
import mouse


class RDPServer:
    def __init__(self, host='0.0.0.0', port=80):
        # Configuration
        self.REFRESH_RATE = 0.05
        self.SCROLL_SENSITIVITY = 5
        self.IMAGE_QUALITY = 95
        self.BUFFER_SIZE = 1024

        # Server setup
        self.host = (host, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.host)
        self.socket.listen(1)

        # Set a timeout to make the server stoppable
        self.socket.settimeout(1.0)

        # Image state
        self.last_image = None
        self.lock = threading.Lock()
        self.shift_pressed = False

        # Control flags
        self.running = True
        self.active_connections = []
        self.threads = []

        # Mouse constants
        self.MOUSE_LEFT = 201
        self.MOUSE_SCROLL = 202
        self.MOUSE_RIGHT = 203
        self.MOUSE_MOVE = 204

    def start(self):
        """Start the RDP server and listen for connections with improved error handling"""
        logging.info(f"RDP server started on {self.host[0]}:{self.host[1]}")

        while self.running:
            try:
                conn, addr = self.socket.accept()
                logging.info(f"New RDP connection from {addr}")

                # Store connection reference
                self.active_connections.append(conn)

                # Start display and input threads for the client
                display_thread = threading.Thread(target=self.handle_display, args=(conn,))
                input_thread = threading.Thread(target=self.handle_input, args=(conn,))

                display_thread.daemon = True
                input_thread.daemon = True

                self.threads.append(display_thread)
                self.threads.append(input_thread)

                display_thread.start()
                input_thread.start()

            except socket.timeout:
                # This is normal - allows checking the running flag
                continue
            except Exception as e:
                if self.running:  # Only log if we weren't intentionally stopped
                    logging.error(f"RDP server connection error: {e}")
                break

    def stop(self):
        """Stop the RDP server and clean up connections"""
        logging.info("Stopping RDP server...")
        self.running = False

        # Close all active connections
        for conn in self.active_connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass

        self.active_connections = []

        # Close main socket
        try:
            self.socket.close()
        except:
            pass

        logging.info("RDP server stopped")

    def handle_display(self, conn):
        """Handle screen capture and transmission with improved handling for cursor movement"""
        try:
            # Initial screen capture
            initial_image = np.array(ImageGrab.grab())
            initial_image = cv2.cvtColor(initial_image, cv2.COLOR_RGB2BGR)

            # Get screen resolution and send it to client
            screen_width, screen_height = initial_image.shape[1], initial_image.shape[0]
            resolution_header = struct.pack(">BII", 0, screen_width, screen_height)
            conn.sendall(resolution_header)

            # Send initial frame
            _, image_bytes = cv2.imencode('.jpg', initial_image,
                                          [cv2.IMWRITE_JPEG_QUALITY, self.IMAGE_QUALITY])

            header = struct.pack(">BI", 1, len(image_bytes))
            conn.sendall(header)
            conn.sendall(image_bytes)

            self.last_image = initial_image

            # Frame rate control with separate handling for mouse movement frames
            standard_frame_interval = 1.0 / 15.0
            last_frame_time = time.time()
            last_significant_frame_time = time.time()

            # Track cursor position to detect cursor-only changes
            cursor_region_size = 40  # Size of cursor region in pixels

            # Change detection parameters
            min_pixel_change = int(screen_width * screen_height * 0.001)
            content_change_threshold = 8  # Lower threshold for actual content changes

            while self.running and conn in self.active_connections:
                current_time = time.time()
                elapsed = current_time - last_frame_time
                elapsed_since_significant = current_time - last_significant_frame_time

                # Control frame rate, but allow through at least one frame every 200ms
                # regardless of content change (to ensure cursor movement is reflected)
                force_update = elapsed_since_significant > 0.2

                if elapsed < standard_frame_interval and not force_update:
                    time.sleep(max(0.005, min(standard_frame_interval - elapsed, 0.05)))
                    continue

                # Update frame timestamp
                last_frame_time = time.time()

                try:
                    # Capture screen
                    screen = np.array(ImageGrab.grab())
                    screen = cv2.cvtColor(screen, cv2.COLOR_RGB2BGR)

                    send_update = False
                    is_cursor_only_change = False

                    if self.last_image is not None and screen.shape == self.last_image.shape:
                        # Calculate absolute difference between frames
                        diff = cv2.absdiff(screen, self.last_image)

                        # Generate a mask of significant changes
                        _, threshold_diff = cv2.threshold(cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY),
                                                          content_change_threshold, 255, cv2.THRESH_BINARY)

                        # Find contours of changed regions
                        contours, _ = cv2.findContours(threshold_diff, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

                        if contours:
                            # Get the bounding rectangle of all changes
                            all_contours = np.vstack([contour for contour in contours])
                            x, y, w, h = cv2.boundingRect(all_contours)

                            # If changed area is small and compact, it might just be the cursor
                            area = w * h
                            change_count = np.count_nonzero(threshold_diff)

                            if area < cursor_region_size * cursor_region_size * 4 and change_count < min_pixel_change * 2:
                                # Likely just cursor movement - update but mark as cursor-only
                                is_cursor_only_change = True
                                send_update = True
                            elif change_count > min_pixel_change:
                                # Significant content change
                                send_update = True
                                last_significant_frame_time = current_time

                        # Force update periodically regardless of detected changes
                        if force_update:
                            send_update = True
                            last_significant_frame_time = current_time
                    else:
                        # First frame or resolution change - always send
                        send_update = True
                        last_significant_frame_time = current_time

                    if send_update:
                        # For cursor-only changes, use a higher compression rate to reduce bandwidth
                        quality = self.IMAGE_QUALITY - 10 if is_cursor_only_change else self.IMAGE_QUALITY

                        # Encode and send frame
                        _, frame_data = cv2.imencode('.jpg', screen, [cv2.IMWRITE_JPEG_QUALITY, quality])

                        # Send frame data
                        header = struct.pack(">BI", 1, len(frame_data))
                        conn.sendall(header)
                        conn.sendall(frame_data)

                        # Update last image
                        self.last_image = screen

                except Exception as frame_error:
                    logging.error(f"Frame capture error: {frame_error}")
                    continue

        except Exception as e:
            logging.error(f"Display handling error: {e}")
        finally:
            if conn in self.active_connections:
                try:
                    conn.close()
                    self.active_connections.remove(conn)
                except:
                    pass

    def handle_input(self, conn):
        """Handle input events from client with improved error handling"""
        try:
            # Get client platform info
            platform = conn.recv(3)
            logging.info(f"Client platform: {platform.decode()}")

            # Input event loop
            while self.running and conn in self.active_connections:
                try:
                    event_data = conn.recv(6)
                    if not event_data or len(event_data) != 6:
                        break

                    key, action, x, y = struct.unpack('>BBHH', event_data)
                    self.process_input(key, action, x, y)
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Input reception error: {e}")
                    break

        except Exception as e:
            logging.error(f"Input handling error: {e}")
        finally:
            # Clean up the connection if it's still in our list
            if conn in self.active_connections:
                try:
                    conn.close()
                    self.active_connections.remove(conn)
                except:
                    pass

    def process_input(self, key, action, x, y):
        """Process individual input events"""
        try:
            # Update shift key state
            if key in (42, 54):  # Left or right shift
                self.shift_pressed = (action == 100)  # 100 for keydown, 117 for keyup
                return

            # Handle keyboard input
            if key < 200:  # Not a mouse event
                try:
                    if action == 100:  # Key down
                        ag.keyDown(self.scan_to_key(key, self.shift_pressed))
                    elif action == 117:  # Key up
                        ag.keyUp(self.scan_to_key(key, self.shift_pressed))
                except KeyError:
                    logging.warning(f"Unrecognized scan code: {key}")
            else:
                # Handle mouse events
                if key == self.MOUSE_MOVE:
                    mouse.move(x, y)
                elif key == self.MOUSE_LEFT:
                    if action == 100:
                        ag.mouseDown(button=ag.LEFT)
                    elif action == 117:
                        ag.mouseUp(button=ag.LEFT)
                elif key == self.MOUSE_RIGHT:
                    if action == 100:
                        ag.mouseDown(button=ag.RIGHT)
                    elif action == 117:
                        ag.mouseUp(button=ag.RIGHT)

        except Exception as e:
            logging.error(f"Input processing error: {e}")

    def scan_to_key(self, scan_code, shift_pressed):
        """Convert scan code to PyAutoGUI key name, considering shift state"""
        scan_map = {
            30: 'a', 48: 'b', 46: 'c', 32: 'd', 18: 'e', 33: 'f', 34: 'g', 35: 'h',
            23: 'i', 36: 'j', 37: 'k', 38: 'l', 50: 'm', 49: 'n', 24: 'o', 25: 'p',
            16: 'q', 19: 'r', 31: 's', 20: 't', 22: 'u', 47: 'v', 17: 'w', 45: 'x',
            21: 'y', 44: 'z', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7',
            9: '8', 10: '9', 11: '0', 26: '[', 27: ']', 43: '\\', 39: ';', 40: "'",
            41: '`', 51: ',', 52: '.', 53: '/', 12: '-', 13: '=', 28: 'enter',
            1: 'esc', 14: 'backspace', 15: 'tab', 57: 'space', 42: 'shift',
            54: 'rshift', 29: 'ctrl', 56: 'alt', 72: 'up', 80: 'down', 75: 'left',
            77: 'right', 59: 'f1', 60: 'f2', 61: 'f3', 62: 'f4', 63: 'f5', 64: 'f6',
            65: 'f7', 66: 'f8', 67: 'f9', 68: 'f10', 87: 'f11', 88: 'f12', 83: 'delete',
            71: 'home', 79: 'end', 81: 'pagedown', 73: 'pageup', 55: '*', 74: '-',
            78: '+'
        }

        # Define shifted keys dynamically
        shifted_map = {
            '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&',
            '8': '*', '9': '(', '0': ')', '[': '{', ']': '}', '\\': '|', ';': ':',
            "'": '"', '`': '~', ',': '<', '.': '>', '/': '?', '-': '_', '=': '+'
        }

        # Get the base key
        key = scan_map.get(scan_code)
        if not key:
            return None

        # Return shifted key if Shift is pressed and a shifted variant exists
        if shift_pressed and key in shifted_map:
            return shifted_map[key]

        return key