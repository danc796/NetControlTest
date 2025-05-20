import tkinter as tk
import customtkinter as ctk
import logging
from datetime import datetime


class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_login_success):
        super().__init__(parent)
        self.parent = parent
        self.on_login_success = on_login_success

        # Set theme colors
        self.bg_color = "#1E1E1E"
        self.fg_color = "#3B8ED0"
        self.accent_color = "#2B7DE9"

        # Configure frame
        self.configure(fg_color=self.bg_color)

        # Create login UI
        self.create_login_ui()

    def create_login_ui(self):
        """Create the login UI"""
        # App logo/title section
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(pady=(60, 20))

        # Title with visual enhancement
        title_label = ctk.CTkLabel(
            logo_frame,
            text="NetControl",
            font=("Helvetica", 32, "bold"),
            text_color="#3B8ED0"  # Blue color
        )
        title_label.pack()

        # Subtitle
        subtitle_label = ctk.CTkLabel(
            logo_frame,
            text="Remote Management System",
            font=("Helvetica", 14),
            text_color="#AAAAAA"  # Light gray
        )
        subtitle_label.pack(pady=(0, 5))

        # Current date/time for visual interest
        date_label = ctk.CTkLabel(
            logo_frame,
            text=datetime.now().strftime("%B %d, %Y"),
            font=("Helvetica", 12),
            text_color="#777777"  # Gray
        )
        date_label.pack()

        # Login form - with a more visually appealing container
        login_container = ctk.CTkFrame(self)
        login_container.pack(padx=50, pady=20)

        # Login header
        login_header = ctk.CTkLabel(
            login_container,
            text="Central Server Login",
            font=("Helvetica", 18, "bold")
        )
        login_header.pack(pady=(15, 20))

        # Login form
        login_frame = ctk.CTkFrame(login_container)
        login_frame.pack(fill=tk.X, padx=30, pady=10)

        # Server info
        server_frame = ctk.CTkFrame(login_frame)
        server_frame.pack(fill=tk.X, pady=10)

        # Server icon and label for visual appeal
        ctk.CTkLabel(server_frame, text="🖥️", font=("", 16)).grid(row=0, column=0, padx=(0, 5), pady=5)
        ctk.CTkLabel(server_frame, text="Server:", font=("Helvetica", 12, "bold")).grid(row=0, column=1, padx=5, pady=5,
                                                                                        sticky="e")
        self.host_entry = ctk.CTkEntry(server_frame, placeholder_text="IP Address", width=200)
        self.host_entry.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        # Port
        ctk.CTkLabel(server_frame, text="🔌", font=("", 16)).grid(row=1, column=0, padx=(0, 5), pady=5)
        ctk.CTkLabel(server_frame, text="Port:", font=("Helvetica", 12, "bold")).grid(row=1, column=1, padx=5, pady=5,
                                                                                      sticky="e")
        self.port_entry = ctk.CTkEntry(server_frame, placeholder_text="5001", width=200)
        self.port_entry.grid(row=1, column=2, padx=10, pady=5, sticky="w")
        self.port_entry.insert(0, "5001")

        # Authentication
        auth_frame = ctk.CTkFrame(login_frame)
        auth_frame.pack(fill=tk.X, pady=10)

        # Username with icon
        ctk.CTkLabel(auth_frame, text="👤", font=("", 16)).grid(row=0, column=0, padx=(0, 5), pady=5)
        ctk.CTkLabel(auth_frame, text="Username:", font=("Helvetica", 12, "bold")).grid(row=0, column=1, padx=5, pady=5,
                                                                                        sticky="e")
        self.username_entry = ctk.CTkEntry(auth_frame, placeholder_text="Username", width=200)
        self.username_entry.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        # Password with icon
        ctk.CTkLabel(auth_frame, text="🔑", font=("", 16)).grid(row=1, column=0, padx=(0, 5), pady=5)
        ctk.CTkLabel(auth_frame, text="Password:", font=("Helvetica", 12, "bold")).grid(row=1, column=1, padx=5, pady=5,
                                                                                        sticky="e")
        self.password_entry = ctk.CTkEntry(auth_frame, placeholder_text="Password", show="*", width=200)
        self.password_entry.grid(row=1, column=2, padx=10, pady=5, sticky="w")

        # Status message
        self.status_label = ctk.CTkLabel(
            login_frame,
            text="",
            text_color="#FF5555"
        )
        self.status_label.pack(pady=10)

        # Login button container for visual appeal
        button_container = ctk.CTkFrame(login_container, fg_color="transparent")
        button_container.pack(pady=15, padx=20)

        # Login button with improved styling
        self.login_button = ctk.CTkButton(
            button_container,
            text="LOGIN",
            command=self.attempt_login,
            width=200,
            height=40,
            fg_color=self.accent_color,
            hover_color="#1D5EAD",
            font=("Helvetica", 14, "bold")
        )
        self.login_button.pack(pady=5)

        # Version info at bottom
        version_label = ctk.CTkLabel(
            login_container,
            text="NetControl v1.2.0",
            font=("Helvetica", 10),
            text_color="#777777"
        )
        version_label.pack(pady=(5, 15))

        # Add key binding for Enter key
        self.username_entry.bind("<Return>", lambda event: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda event: self.attempt_login())

    def attempt_login(self):
        """Attempt to log in to central server"""
        host = self.host_entry.get()
        port = self.port_entry.get() or "5001"
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not host or not username or not password:
            self.status_label.configure(text="Please fill in all fields")
            return

        # Try to connect
        try:
            port = int(port)
        except ValueError:
            self.status_label.configure(text="Invalid port number")
            return

        # Update button state and status
        self.login_button.configure(state="disabled", text="Connecting...")
        self.status_label.configure(text="Connecting to central server...", text_color="#FFAA00")

        # Schedule the login attempt to allow UI to update
        self.after(100, lambda: self._perform_login(host, port, username, password))

    def _perform_login(self, host, port, username, password):
        """Perform the actual login attempt"""
        result = self.parent.connect_to_central_server(host, port, username, password)

        if result:
            # Call success callback
            self.on_login_success()
        else:
            # Reset button and show error
            self.login_button.configure(state="normal", text="Login")
            self.status_label.configure(text="Login failed. Please check your credentials.", text_color="#FF5555")