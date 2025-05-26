import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import logging

from nc_client.ui.toast import ToastNotification
from nc_client.ui.monitoring_tab import MonitoringTab
from nc_client.ui.power_tab import PowerTab
from nc_client.ui.rdp_tab import RDPTab
from nc_client.ui.connection_tab import ConnectionTab
from nc_client.ui.login_screen import LoginScreen
from nc_client.ui.central_server_tab import CentralServerTab

from nc_client.connection.manager import ConnectionManager
from nc_client.monitoring.system_monitor import SystemMonitor
from nc_client.power.controller import PowerManager
from nc_client.rdp.client import RDPClient

from nc_client.central_server.client import CentralServerClient


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.running = True
        self.active_tab = None
        self.active_connection = None

        self.title("NetControl")
        self.geometry("1200x800")

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Initialize components
        self.toast = ToastNotification(self)
        self.connection_manager = ConnectionManager(self)
        self.system_monitor = SystemMonitor(self)
        self.power_manager = PowerManager(self)
        self.rdp_client = RDPClient(self)
        self.central_client = CentralServerClient(self)

        # Show login screen first
        self.login_screen = LoginScreen(self, self.on_login_success)
        self.login_screen.pack(fill=tk.BOTH, expand=True)

        # Main UI will be created after login
        self.main_container = None

        # Set window close handler
        self.protocol("WM_DELETE_WINDOW", self.on_closing)


    def on_login_success(self):
        """Called when login is successful"""
        # Hide login screen
        self.login_screen.pack_forget()

        # Create main UI
        self.create_main_ui()

        # Start monitoring threads
        self.system_monitor.initialize_monitoring()

        # Start connection monitoring
        if hasattr(self.connection_manager, 'initialize_connection_monitoring'):
            self.connection_manager.initialize_connection_monitoring()

    def create_main_ui(self):
        """Create the main GUI with connection management"""
        # Create main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create sidebar
        self.sidebar = ctk.CTkFrame(self.main_container, width=250)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Create connection tab in sidebar
        self.connection_tab = ConnectionTab(self.sidebar, self)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.monitoring_tab = MonitoringTab(self, self.notebook, self)
        self.power_tab = PowerTab(self, self.notebook, self)
        self.rdp_tab = RDPTab(self, self.notebook, self)
        self.central_server_tab = CentralServerTab(self, self.notebook, self)

        # Add tab change handler
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_change)

    def on_tab_change(self, event=None):
        try:
            current_tab = self.notebook.select()
            prev_tab = self.active_tab
            self.active_tab = self.notebook.tab(current_tab, "text")

            print(f"Tab changed from {prev_tab} to {self.active_tab}")

            # Handle monitoring tab exit
            if prev_tab == "Monitoring":
                self.system_monitor.monitoring_active = False
                print(f"Monitoring deactivated: {self.system_monitor.monitoring_active}")

            # Handle monitoring tab entry
            if self.active_tab == "Monitoring":
                self.system_monitor.monitoring_active = True
                print(f"Monitoring activated: {self.system_monitor.monitoring_active}")

                # Update progress bar references
                if hasattr(self.monitoring_tab, 'cpu_progress'):
                    self.system_monitor.progress_bars['cpu'] = self.monitoring_tab.cpu_progress
                if hasattr(self.monitoring_tab, 'mem_progress'):
                    self.system_monitor.progress_bars['mem'] = self.monitoring_tab.mem_progress

                # Force a refresh
                self.after(100, self.system_monitor.refresh_monitoring)

            # Handle RDP tab activation/deactivation
            if self.active_tab == "Remote Desktop":
                self.rdp_client.rdp_tab_active = True
                print("RDP tab activated")
            else:
                self.rdp_client.rdp_tab_active = False
                print("RDP tab deactivated")

            # Update the UI based on the new tab
            self.update_idletasks()

        except Exception as e:
            print(f"Error during tab change: {str(e)}")

    def on_computer_select(self, connection_id):
        """Handle computer selection"""
        if connection_id:
            # Check if active connection is changing
            if self.active_connection != connection_id:
                self.active_connection = connection_id
                # Refresh monitoring for new connection
                self.system_monitor.refresh_monitoring()
        else:
            self.active_connection = None

    def connect_to_central_server(self, host, port, username, password):
        """Connect to the central server"""
        self.central_client.host = host
        self.central_client.port = port

        # Connect to the server
        if not self.central_client.connect():
            self.toast.show_toast("Could not connect to central server", "error")
            return False

        # Login
        success, message = self.central_client.login(username, password)
        if success:
            self.toast.show_toast(f"Connected to central server as {username}", "success")
            return True
        else:
            self.toast.show_toast(message, "error")
            return False

    def register_connection(self, connection_id):
        """Register a connection with the central server"""
        if not hasattr(self, 'central_client') or not self.central_client.authenticated:
            return

        connection = self.connection_manager.connections.get(connection_id)
        if not connection:
            return

        host, port = connection.get('host'), connection.get('port')
        success, message = self.central_client.register_server(host, port)

        if not success:
            self.toast.show_toast(f"Failed to register with central server: {message}", "warning")

    def unregister_connection(self, connection_id):
        """Unregister a connection from the central server"""
        if not self.central_client.authenticated:
            return

        connection = self.connection_manager.connections.get(connection_id)
        if not connection:
            return

        host, port = connection.get('host'), connection.get('port')
        self.central_client.unregister_server(host, port)

    def toggle_connection_sharing(self, connection_id):
        """Toggle connection sharing for a connection"""
        if not self.central_client.authenticated:
            return

        connection = self.connection_manager.connections.get(connection_id)
        if not connection:
            return

        host, port = connection.get('host'), connection.get('port')

        # Check current sharing status
        is_shared = self.central_client.is_sharing_connection(host, port)

        # Toggle sharing
        success, message = self.central_client.set_sharing(host, port, not is_shared)
        if success:
            state = "enabled" if not is_shared else "disabled"
            self.toast.show_toast(f"Connection sharing {state}", "success")
        else:
            self.toast.show_toast(message, "error")

    def connect_to_shared_servers(self):
        """Connect to all shared servers"""
        if not self.central_client.authenticated:
            self.toast.show_toast("Not connected to central server", "warning")
            return

        success, message = self.central_client.connect_to_shared_servers()
        self.toast.show_toast(message, "success" if success else "error")

    def restart_application(self):
        """Original restart method - now simplified to return to login screen"""
        # Destroy the main UI
        if self.main_container:
            self.main_container.destroy()
            self.main_container = None

        # Disconnect from central server
        self.central_client.disconnect()

        # Recreate login screen
        self.login_screen = LoginScreen(self, self.on_login_success)
        self.login_screen.pack(fill=tk.BOTH, expand=True)

    def on_closing(self):
        """Handle window closing event"""
        try:
            # Set flag to stop monitoring threads
            self.running = False

            # Close all connections
            self.connection_manager.close_all_connections()

            logging.info("Application shutting down")
            self.quit()

        except Exception as e:
            logging.error(f"Error during shutdown: {str(e)}")
            self.quit()