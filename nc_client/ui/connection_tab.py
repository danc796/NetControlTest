import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, messagebox
import logging


class ConnectionTab:
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app

        # Create connection controls
        self.create_connection_controls()

    def create_connection_controls(self):
        # Add connection controls
        connection_frame = ctk.CTkFrame(self.parent)
        connection_frame.pack(fill=tk.X, padx=5, pady=5)

        self.host_entry = ctk.CTkEntry(connection_frame, placeholder_text="IP Address")
        self.host_entry.pack(fill=tk.X, padx=5, pady=2)

        self.port_entry = ctk.CTkEntry(connection_frame, placeholder_text="Port (default: 5000)")
        self.port_entry.pack(fill=tk.X, padx=5, pady=2)

        btn_frame = ctk.CTkFrame(connection_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)

        ctk.CTkButton(btn_frame, text="Connect",
                      command=self.on_connect).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(btn_frame, text="Disconnect",
                      command=self.on_disconnect).pack(side=tk.LEFT, padx=2)

        # Create computer list with selection capability and additional column for sharing status
        self.computer_list = ttk.Treeview(self.parent, columns=("status", "shared"), show="tree headings")
        self.computer_list.heading("#0", text="Computers")
        self.computer_list.heading("status", text="Status")
        self.computer_list.heading("shared", text="Shared")

        # Configure columns width
        self.computer_list.column("status", width=100)
        self.computer_list.column("shared", width=50)

        self.computer_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.computer_list.bind('<<TreeviewSelect>>', self.on_computer_select)

    def on_connect(self):
        """Connect button handler - delegates to connection manager"""
        host = self.host_entry.get()
        port = self.port_entry.get()
        self.app.connection_manager.add_connection(host, port)

        # Clear input fields
        self.host_entry.delete(0, tk.END)
        self.port_entry.delete(0, tk.END)

    def on_disconnect(self):
        """Disconnect button handler - simply disconnects the selected server without restarting"""
        selected = self.computer_list.selection()
        if not selected:
            messagebox.showwarning("Selection", "Please select a computer to disconnect")
            return

        # Just remove the connection - no restart
        try:
            # Get connection info for logging
            connection_id = selected[0]
            connection = self.app.connection_manager.connections.get(connection_id)
            if connection:
                host, port = connection.get('host'), connection.get('port')
                logging.info(f"Disconnecting from server {host}:{port}")

            # Remove the connection
            self.app.connection_manager.remove_connection(connection_id)

            # Notify the user
            if connection:
                self.app.toast.show_toast(f"Disconnected from {host}:{port}", "info")
        except Exception as e:
            logging.error(f"Error during disconnect: {e}")
            self.app.toast.show_toast(f"Error disconnecting: {str(e)}", "error")

    def on_computer_select(self, event):
        """Handle computer selection"""
        selected = self.computer_list.selection()
        if selected:
            # Notify the main app of the selection
            self.app.on_computer_select(selected[0])
        else:
            self.app.on_computer_select(None)