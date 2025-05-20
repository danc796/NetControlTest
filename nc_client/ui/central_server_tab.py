import tkinter as tk, messagebox
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

        # Server actions
        actions_frame = ctk.CTkFrame(self.scrollable_frame)
        actions_frame.pack(fill=tk.X, padx=20, pady=(20, 10))

        # Shared servers
        shared_servers_frame = ctk.CTkFrame(actions_frame)
        shared_servers_frame.pack(fill=tk.X, pady=10)

        ctk.CTkLabel(
            shared_servers_frame,
            text="Shared Servers",
            font=("Helvetica", 16, "bold")
        ).pack(pady=(10, 5))

        self.shared_servers_label = ctk.CTkLabel(
            shared_servers_frame,
            text="No shared servers available"
        )
        self.shared_servers_label.pack(pady=5)

        self.connect_shared_button = ctk.CTkButton(
            shared_servers_frame,
            text="Connect to Shared Servers",
            command=self.connect_to_shared_servers,
            width=200,
            height=40
        )
        self.connect_shared_button.pack(pady=10)

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

    def connect_to_shared_servers(self):
        """Connect to all shared servers"""
        self.app.connect_to_shared_servers()

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

        # Update shared servers label if connected to central server
        if self.app.central_client.authenticated:
            self.update_shared_servers_label()

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

    def update_shared_servers_label(self):
        """Update shared servers label with count of available shared servers"""
        if not self.app.central_client.authenticated:
            return

        # Refresh server lists
        self.app.central_client.refresh_server_lists()

        # Update label
        count = len(self.app.central_client.shared_servers)
        if count > 0:
            self.shared_servers_label.configure(
                text=f"{count} shared servers available"
            )
        else:
            self.shared_servers_label.configure(
                text="No shared servers available"
            )

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