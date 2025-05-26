import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import logging


class CentralServerTab:
    def __init__(self, parent, notebook, app):
        self.parent = parent
        self.notebook = notebook
        self.app = app

        # Create the central server tab
        self.create_central_server_tab()

    def create_central_server_tab(self):
        """Create the central server tab with enhanced user management and scrolling"""
        # Main frame that will hold the scrollable frame
        central_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(central_frame, text="Central Server")

        # Create a scrollable frame to contain all content
        self.scrollable_frame = ctk.CTkScrollableFrame(central_frame, width=800, height=600)
        self.scrollable_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Title
        title_label = ctk.CTkLabel(
            self.scrollable_frame,
            text="Central Server Connection",
            font=("Helvetica", 20, "bold")
        )
        title_label.pack(pady=(20, 10))

        # Status section
        self.status_frame = ctk.CTkFrame(self.scrollable_frame)
        self.status_frame.pack(fill=tk.X, padx=20, pady=10)

        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text=f"Connected as {self.app.central_client.username}",
            font=("Helvetica", 14),
            text_color="#00CC00"
        )
        self.status_label.pack(pady=10)

        # Connection details
        self.details_label = ctk.CTkLabel(
            self.status_frame,
            text=f"Server: {self.app.central_client.host}:{self.app.central_client.port}",
            font=("Helvetica", 12)
        )
        self.details_label.pack(pady=5)

        # Logout button
        self.logout_button = ctk.CTkButton(
            self.status_frame,
            text="Logout",
            command=self.logout,
            width=150,
            height=30
        )
        self.logout_button.pack(pady=10)

        # Server list section
        self.create_server_list_section()

        # Change Password section - Available to all users
        self.change_password_frame = ctk.CTkFrame(self.scrollable_frame)
        self.change_password_frame.pack(fill=tk.X, padx=20, pady=(20, 10))

        ctk.CTkLabel(
            self.change_password_frame,
            text="Change Password",
            font=("Helvetica", 16, "bold")
        ).pack(pady=(10, 5))

        password_form = ctk.CTkFrame(self.change_password_frame)
        password_form.pack(pady=5)

        ctk.CTkLabel(password_form, text="Current Password:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.current_password_entry = ctk.CTkEntry(password_form, placeholder_text="Current Password", show="*",
                                                   width=200)
        self.current_password_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(password_form, text="New Password:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.change_new_password_entry = ctk.CTkEntry(password_form, placeholder_text="New Password", show="*",
                                                      width=200)
        self.change_new_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(password_form, text="Confirm Password:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.confirm_password_entry = ctk.CTkEntry(password_form, placeholder_text="Confirm Password", show="*",
                                                   width=200)
        self.confirm_password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkButton(
            password_form,
            text="Change Password",
            command=self.change_password,
            width=150
        ).grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Admin section - make it more visible and ensure it appears
        # Create an admin section container
        admin_container = ctk.CTkFrame(self.scrollable_frame)
        admin_container.pack(fill=tk.X, padx=20, pady=(20, 10), expand=True)

        # Store reference to the container
        self.admin_container = admin_container

        # Create the admin frame inside the container
        self.admin_frame = ctk.CTkFrame(admin_container)
        # Don't pack it yet - we'll do that in update_ui based on admin status

        ctk.CTkLabel(
            self.admin_frame,
            text="Admin Functions",
            font=("Helvetica", 16, "bold")
        ).pack(pady=(10, 5))

        # User creation form
        user_creation_frame = ctk.CTkFrame(self.admin_frame)
        user_creation_frame.pack(fill=tk.X, pady=5)

        ctk.CTkLabel(user_creation_frame, text="Create New User", font=("Helvetica", 14)).pack(pady=(5, 2))

        form_frame = ctk.CTkFrame(user_creation_frame)
        form_frame.pack(pady=5)

        ctk.CTkLabel(form_frame, text="Username:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.new_username_entry = ctk.CTkEntry(form_frame, placeholder_text="New Username", width=200)
        self.new_username_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        ctk.CTkLabel(form_frame, text="Password:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.new_password_entry = ctk.CTkEntry(form_frame, placeholder_text="New Password", show="*", width=200)
        self.new_password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        self.is_admin_var = tk.BooleanVar(value=False)
        self.is_admin_checkbox = ctk.CTkCheckBox(form_frame, text="Make Admin", variable=self.is_admin_var)
        self.is_admin_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

        ctk.CTkButton(
            form_frame,
            text="Create User",
            command=self.create_user,
            width=150
        ).grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # User Management section - Admin only
        user_management_frame = ctk.CTkFrame(self.admin_frame)
        user_management_frame.pack(fill=tk.X, pady=5)

        ctk.CTkLabel(user_management_frame, text="User Management", font=("Helvetica", 14)).pack(pady=(5, 2))

        # User selection dropdown and buttons
        user_select_frame = ctk.CTkFrame(user_management_frame)
        user_select_frame.pack(pady=5)

        ctk.CTkLabel(user_select_frame, text="Select User:").grid(row=0, column=0, padx=10, pady=5, sticky="e")

        # Combobox for user selection
        self.user_list_var = tk.StringVar()
        self.user_dropdown = ctk.CTkOptionMenu(
            user_select_frame,
            variable=self.user_list_var,
            values=["Loading users..."],
            width=200
        )
        self.user_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        # Refresh button
        ctk.CTkButton(
            user_select_frame,
            text="↻",
            command=self.refresh_user_list,
            width=30
        ).grid(row=0, column=2, padx=(0, 10), pady=5)

        # User actions buttons
        button_frame = ctk.CTkFrame(user_select_frame)
        button_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

        ctk.CTkButton(
            button_frame,
            text="Delete User",
            command=self.delete_user,
            width=120,
            fg_color="#E53935",  # Red color for delete
            hover_color="#C62828"
        ).pack(side=tk.LEFT, padx=5, pady=10)

        ctk.CTkButton(
            button_frame,
            text="Promote to Admin",
            command=self.promote_to_admin,
            width=120
        ).pack(side=tk.LEFT, padx=5, pady=10)

        # Update UI periodically
        self.update_ui()

    def create_server_list_section(self):
        """Create the server list section with Treeview - visible to all users"""
        server_frame = ctk.CTkFrame(self.scrollable_frame)
        server_frame.pack(fill=tk.X, padx=20, pady=10)

        # Title and refresh button in header
        header_frame = ctk.CTkFrame(server_frame)
        header_frame.pack(fill=tk.X, pady=5)

        # Added section description for non-admin users
        if self.app.central_client.is_admin:
            title_text = "Server Management"
        else:
            title_text = "Available Servers"

        ctk.CTkLabel(
            header_frame,
            text=title_text,
            font=("Helvetica", 16, "bold")
        ).pack(side=tk.LEFT, padx=10, pady=5)

        refresh_button = ctk.CTkButton(
            header_frame,
            text="↻",
            command=self.refresh_server_list,
            width=30,
            height=30
        )
        refresh_button.pack(side=tk.RIGHT, padx=10, pady=5)

        # Server list Treeview
        self.server_list_frame = ctk.CTkFrame(server_frame)
        self.server_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create Treeview for server list
        columns = ("ip_address", "port", "discovered", "last_seen")
        self.server_tree = ttk.Treeview(self.server_list_frame, columns=columns, show="headings", height=10)

        # Define column headings
        self.server_tree.heading("ip_address", text="IP Address")
        self.server_tree.heading("port", text="Port")
        self.server_tree.heading("discovered", text="First Discovered")
        self.server_tree.heading("last_seen", text="Last Seen")

        # Configure column widths
        self.server_tree.column("ip_address", width=150)
        self.server_tree.column("port", width=80)
        self.server_tree.column("discovered", width=150)
        self.server_tree.column("last_seen", width=150)

        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(self.server_list_frame, orient="vertical", command=self.server_tree.yview)
        scrollbar_x = ttk.Scrollbar(self.server_list_frame, orient="horizontal", command=self.server_tree.xview)
        self.server_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        # Pack Treeview and scrollbars
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.server_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar_x.pack(fill=tk.X)

        # Status label for operation feedback - different text based on user role
        if self.app.central_client.is_admin:
            status_text = "Select a server to manage connections or connect"
        else:
            status_text = "Select a server to connect"

        self.server_status_label = ctk.CTkLabel(
            server_frame,
            text=status_text,
            font=("Helvetica", 12)
        )
        self.server_status_label.pack(pady=5)

        # Buttons for server actions
        button_frame = ctk.CTkFrame(server_frame)
        button_frame.pack(fill=tk.X, pady=5)

        # Only show View Connections button if user is admin
        if self.app.central_client.is_admin:
            self.view_connections_button = ctk.CTkButton(
                button_frame,
                text="View Connections",
                command=self.view_connections,
                width=150,
                state="disabled"
            )
            self.view_connections_button.pack(side=tk.LEFT, padx=5, pady=5)
        else:
            # Create a hidden button to keep references valid but don't pack it
            self.view_connections_button = ctk.CTkButton(
                button_frame,
                text="View Connections",
                command=self.view_connections,
                width=150,
                state="disabled"
            )

        self.connect_button = ctk.CTkButton(
            button_frame,
            text="Connect to Server",
            command=self.connect_to_selected_server,
            width=150,
            state="disabled"
        )
        self.connect_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Connect to server event
        self.server_tree.bind("<<TreeviewSelect>>", self.on_server_select)

        # Refresh server list initially
        self.refresh_server_list()

    def on_server_select(self, event=None):
        """Handle server selection in the Treeview, with different options based on user role"""
        selected = self.server_tree.selection()
        if selected:
            # Get selected server info
            item = self.server_tree.item(selected[0])
            values = item["values"]
            ip_address = values[0]
            port = values[1]

            # Enable connect button for all users
            self.connect_button.configure(state="normal")

            # For view connections button, only enable for admins
            if self.app.central_client.is_admin:
                self.view_connections_button.configure(state="normal")
                self.server_status_label.configure(
                    text=f"Selected: {ip_address}:{port} - You can view connections or connect to this server"
                )
            else:
                self.view_connections_button.configure(state="disabled")
                self.server_status_label.configure(
                    text=f"Selected: {ip_address}:{port} - Click 'Connect to Server' to connect"
                )
        else:
            # Disable buttons when no server is selected
            self.view_connections_button.configure(state="disabled")
            self.connect_button.configure(state="disabled")

            if self.app.central_client.is_admin:
                self.server_status_label.configure(text="Select a server to manage connections or connect")
            else:
                self.server_status_label.configure(text="Select a server to connect")

    def refresh_server_list(self):
        """Refresh the list of servers from database"""
        try:
            # Clear existing items
            for item in self.server_tree.get_children():
                self.server_tree.delete(item)

            # Update status
            self.server_status_label.configure(text="Loading servers...")

            # Get server list from central server
            success, message, servers = self.app.central_client.get_all_servers_from_db()

            if success and servers:
                # Add each server to the treeview
                for i, server in enumerate(servers):
                    self.server_tree.insert(
                        "",
                        tk.END,
                        iid=f"{server.get('ip_address')}:{server.get('port')}",
                        values=(
                            server.get('ip_address', ''),
                            server.get('port', ''),
                            server.get('first_discovered', ''),
                            server.get('last_seen', '')
                        )
                    )

                self.server_status_label.configure(text=f"Found {len(servers)} servers")
            else:
                self.server_status_label.configure(text=f"Error: {message}")

        except Exception as e:
            logging.error(f"Error refreshing server list: {e}")
            self.server_status_label.configure(text=f"Error: {str(e)}")

    def view_connections(self):
        """View connection history for selected server"""
        selected = self.server_tree.selection()
        if not selected:
            return

        # Get selected server
        item = self.server_tree.item(selected[0])
        values = item["values"]
        ip_address = values[0]
        port = values[1]

        # Create a dialog to show connection history
        self.show_connections_dialog(ip_address, port)

    def show_connections_dialog(self, ip_address, port):
        """Show a dialog with connection info for a server (using servers table with sharing_with)"""
        # Create a toplevel dialog
        dialog = ctk.CTkToplevel(self.parent)
        dialog.title(f"Connection Information for {ip_address}:{port}")
        dialog.geometry("600x400")
        dialog.transient(self.parent)
        dialog.grab_set()

        # Make dialog modal
        dialog.focus_set()

        # Create main frame
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        ctk.CTkLabel(
            main_frame,
            text=f"Connection Information for {ip_address}:{port}",
            font=("Helvetica", 16, "bold")
        ).pack(pady=10)

        # Create Treeview for connection info
        columns = ("server_ip", "recent_connection", "connected_at")
        connections_tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=10)

        # Define column headings
        connections_tree.heading("server_ip", text="Server IP")
        connections_tree.heading("recent_connection", text="Recent Connection")
        connections_tree.heading("connected_at", text="Connection Time")

        # Configure column widths
        connections_tree.column("server_ip", width=150)
        connections_tree.column("recent_connection", width=150)
        connections_tree.column("connected_at", width=150)

        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(main_frame, orient="vertical", command=connections_tree.yview)
        scrollbar_x = ttk.Scrollbar(main_frame, orient="horizontal", command=connections_tree.xview)
        connections_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        # Pack Treeview and scrollbars
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        connections_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        scrollbar_x.pack(fill=tk.X)

        # Status label
        status_label = ctk.CTkLabel(
            main_frame,
            text="Loading connection information...",
            font=("Helvetica", 12)
        )
        status_label.pack(pady=5)

        # Button frame
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        # Refresh button
        refresh_button = ctk.CTkButton(
            button_frame,
            text="Refresh",
            command=lambda: self.load_connection_info(connections_tree, status_label, ip_address, port)
        )
        refresh_button.pack(side=tk.LEFT, padx=5)

        # Close button
        close_button = ctk.CTkButton(
            button_frame,
            text="Close",
            command=dialog.destroy
        )
        close_button.pack(side=tk.RIGHT, padx=5)

        # Load connection info
        self.load_connection_info(connections_tree, status_label, ip_address, port)

    def load_connection_info(self, tree, status_label, ip_address, port):
        """Load connection info for a server from the servers table with sharing_with"""
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)

        status_label.configure(text="Loading connection information...")

        # Get connection info from central server
        success, message, info = self.app.central_client.get_server_connection_info(ip_address, port)

        if success and info:
            # Add each info entry to the treeview
            for i, entry in enumerate(info):
                tree.insert(
                    "",
                    tk.END,
                    iid=str(i),
                    values=(
                        entry.get('server_ip', ''),
                        entry.get('recent_connection', ''),
                        entry.get('connected_at', '')
                    )
                )

            status_label.configure(text="Connection information loaded successfully")
        else:
            status_label.configure(text=f"Error: {message}" if not success else "No connection information found")

    def load_connection_history(self, tree, status_label, ip_address, port):
        """Load connection history for a server (without using active_connections)"""
        # Clear existing items
        for item in tree.get_children():
            tree.delete(item)

        status_label.configure(text="Loading connection history...")

        # Get connection history from central server
        success, message, history = self.app.central_client.get_connection_history(ip_address, port)

        if success and history:
            # Add each history entry to the treeview
            for i, entry in enumerate(history):
                tree.insert(
                    "",
                    tk.END,
                    iid=str(i),
                    values=(
                        entry.get('server_id', ''),
                        entry.get('connection_time', ''),
                        entry.get('connect_by', ''),
                        entry.get('recent_connection', '')
                    )
                )

            status_label.configure(text=f"Found {len(history)} connection records")
        else:
            status_label.configure(text=f"Error: {message}" if not success else "No connection history found")

    def delete_connection(self, tree, status_label, ip_address, port):
        """Delete selected connection"""
        selected = tree.selection()
        if not selected:
            return

        # Confirm deletion
        if not messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this connection?"):
            return

        # Get selected connection
        item = tree.item(selected[0])
        values = item["values"]
        server_id = values[0]

        # Delete connection
        success, message = self.app.central_client.delete_connection(server_id)

        if success:
            status_label.configure(text="Connection deleted successfully")
            self.load_connection_info(tree, status_label, ip_address, port)
        else:
            status_label.configure(text=f"Error deleting connection: {message}")

    def connect_to_selected_server(self):
        """Connect to the selected server"""
        selected = self.server_tree.selection()
        if not selected:
            return

        # Get selected server
        item = self.server_tree.item(selected[0])
        values = item["values"]
        ip_address = values[0]
        port = values[1]

        # Add connection to connection manager
        self.app.connection_manager.add_connection(ip_address, port)

        # Show feedback
        self.app.toast.show_toast(f"Connecting to {ip_address}:{port}", "info")

    def logout(self):
        """Handle logout by completely restarting the application"""
        if self.app.central_client.authenticated:
            if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out? The application will restart."):
                # Disconnect from central server
                self.app.central_client.disconnect()

                # Log the restart
                logging.info("Restarting application after logout...")

                # Start the full restart process
                self.restart_application()

    def restart_application(self):
        """Completely restart the application without visible command prompts"""
        try:
            # Set flag to stop monitoring threads
            self.app.running = False

            # Close all connections
            self.app.connection_manager.close_all_connections()

            # Use subprocess.Popen with hidden window
            import sys
            import os
            import subprocess

            # Get the current executable path and arguments
            if getattr(sys, 'frozen', False):
                # If running as an executable
                executable = sys.executable
                args = []
            else:
                # If running as a script
                executable = sys.executable
                args = [os.path.abspath(sys.argv[0])]

            # Create a detached/hidden process based on platform
            if sys.platform.startswith('win'):
                # For Windows - use DETACHED_PROCESS flag to hide the window
                import ctypes

                # Create a proper startupinfo object to hide the window
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0  # SW_HIDE

                # Use DETACHED_PROCESS flag
                DETACHED_PROCESS = 0x00000008

                # Start the new process
                subprocess.Popen(
                    [executable] + args,
                    creationflags=DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                    startupinfo=startupinfo,
                    close_fds=True
                )
            else:
                # For Unix-like systems
                subprocess.Popen(
                    [executable] + args,
                    start_new_session=True,
                    close_fds=True
                )

            # Give the new process a moment to start
            import time
            time.sleep(0.5)

            # Now exit the application
            self.app.destroy()

            # Force a complete exit
            os._exit(0)

        except Exception as e:
            logging.error(f"Error during application restart: {e}")
            messagebox.showerror("Restart Error", f"Failed to restart: {str(e)}")

            # Fall back to the original restart method as a last resort
            self.app.restart_application()

    def update_ui(self):
        """Update UI elements periodically"""
        # Update status label with current username
        if self.app.central_client.authenticated and self.app.central_client.username:
            self.status_label.configure(
                text=f"Connected as {self.app.central_client.username}",
                text_color="#00CC00"
            )

            # Update server details
            self.details_label.configure(
                text=f"Server: {self.app.central_client.host}:{self.app.central_client.port}"
            )
        else:
            self.status_label.configure(
                text="Not connected",
                text_color="#FFFFFF"
            )
            self.details_label.configure(text="")

        # Show/hide admin panel with better visibility control
        if self.app.central_client.authenticated and self.app.central_client.is_admin:
            # Make sure admin frame is packed in its container
            self.admin_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Add a visual indicator that admin mode is active
            self.admin_container.configure(border_width=2, border_color="#00CC00")

            # Refresh user list when showing admin interface
            self.refresh_user_list()
        else:
            # Unpack if it was previously packed
            self.admin_frame.pack_forget()

            # Remove border if not admin
            self.admin_container.configure(border_width=0)

        # Schedule next update
        self.app.after(2000, self.update_ui)

    def create_user(self):
        """Handle creating a new user"""
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        is_admin = self.is_admin_var.get()

        if not username or not password:
            self.app.toast.show_toast("Please provide username and password", "warning")
            return

        success, message = self.app.central_client.create_user(username, password, is_admin)

        if success:
            self.app.toast.show_toast(message, "success")
            self.new_username_entry.delete(0, 'end')
            self.new_password_entry.delete(0, 'end')
            self.is_admin_var.set(False)
            # Refresh user list after creating a new user
            self.refresh_user_list()
        else:
            self.app.toast.show_toast(message, "error")

    def change_password(self):
        """Handle changing password for the current user"""
        current_password = self.current_password_entry.get().strip()
        new_password = self.change_new_password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        # Debug output
        print(
            f"Change password - Current: filled={bool(current_password)}, New: filled={bool(new_password)}, Confirm: filled={bool(confirm_password)}")

        if not current_password or not new_password or not confirm_password:
            self.app.toast.show_toast("Please fill in all password fields", "warning")
            return

        if new_password != confirm_password:
            self.app.toast.show_toast("New passwords do not match", "warning")
            return

        # Call the client method to change password
        success, message = self.app.central_client.change_password(current_password, new_password)

        if success:
            self.app.toast.show_toast(message, "success")
            # Clear password fields
            self.current_password_entry.delete(0, 'end')
            self.change_new_password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
        else:
            self.app.toast.show_toast(message, "error")

    def refresh_user_list(self):
        """Refresh the list of users for the dropdown"""
        if not self.app.central_client.authenticated or not self.app.central_client.is_admin:
            return

        # Get all users from the server
        success, message, users = self.app.central_client.get_all_users()

        if success and users:
            # Extract usernames and filter out the current user
            usernames = [user['username'] for user in users
                         if user['username'] != self.app.central_client.username]

            if usernames:
                # Update the dropdown values
                self.user_dropdown.configure(values=usernames)
                # Set the first user as selected
                self.user_list_var.set(usernames[0])
            else:
                self.user_dropdown.configure(values=["No other users"])
                self.user_list_var.set("No other users")
        else:
            self.user_dropdown.configure(values=["Error loading users"])
            self.user_list_var.set("Error loading users")
            self.app.toast.show_toast(f"Failed to load users: {message}", "error")

    def delete_user(self):
        """Delete the selected user"""
        if not self.app.central_client.authenticated or not self.app.central_client.is_admin:
            self.app.toast.show_toast("Admin privileges required", "error")
            return

        username = self.user_list_var.get()

        if username in ["Loading users...", "No other users", "Error loading users"]:
            self.app.toast.show_toast("No valid user selected", "warning")
            return

        # Confirm deletion
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete user '{username}'?"):
            # Call the client method to delete the user
            success, message = self.app.central_client.delete_user(username)

            if success:
                self.app.toast.show_toast(message, "success")
                # Refresh user list after deletion
                self.refresh_user_list()
            else:
                self.app.toast.show_toast(message, "error")

    def promote_to_admin(self):
        """Promote the selected user to admin status"""
        if not self.app.central_client.authenticated or not self.app.central_client.is_admin:
            self.app.toast.show_toast("Admin privileges required", "error")
            return

        username = self.user_list_var.get()

        if username in ["Loading users...", "No other users", "Error loading users"]:
            self.app.toast.show_toast("No valid user selected", "warning")
            return

        # Confirm promotion
        if messagebox.askyesno("Confirm Promotion", f"Are you sure you want to promote '{username}' to admin?"):
            # Call the client method to promote the user
            success, message = self.app.central_client.promote_to_admin(username)

            if success:
                self.app.toast.show_toast(message, "success")
                # Refresh user list after promotion
                self.refresh_user_list()
            else:
                self.app.toast.show_toast(message, "error")