from tkinter import messagebox
import logging
from datetime import datetime


class PowerManager:
    def __init__(self, parent_app):
        self.parent_app = parent_app
        # Keep a reference to the connection manager for sending commands
        self.connection_manager = parent_app.connection_manager
        # Reference to the power status label (will be set by PowerTab)
        self.power_status = None

    def set_power_status(self, status_label):
        """Set reference to power status label from PowerTab"""
        self.power_status = status_label

    def update_power_status(self, message, color="white"):
        """Update power status label with proper error handling"""
        try:
            if hasattr(self, 'power_status') and self.power_status and self.power_status.winfo_exists():
                self.power_status.configure(text=message, text_color=color)
        except Exception as e:
            logging.error(f"Error updating power status: {str(e)}")

    def power_action_with_confirmation(self, action, confirm_msg, power_mode):
        """Execute power action with confirmation for single or multiple computers"""
        try:
            if power_mode == "all":
                if not self.connection_manager.connections:
                    self.update_power_status("No computers connected", "red")
                    return

                if messagebox.askyesno("Confirm Action", f"{confirm_msg} (All Computers)"):
                    failed_computers = []
                    successful_computers = []

                    for conn_id in list(self.connection_manager.connections.keys()):  # Create a copy of keys
                        connection = self.connection_manager.connections.get(conn_id)
                        if not connection:
                            continue

                        host = connection.get('host', 'Unknown')

                        try:
                            # Update status to show action in progress
                            self.parent_app.connection_tab.computer_list.set(conn_id, "status", f"Sending {action}...")

                            # Send command with timeout handling
                            response = self.connection_manager.send_command(conn_id, 'power_management', {
                                'action': action
                            })

                            if response and response.get('status') == 'success':
                                successful_computers.append(host)
                                self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Connected")
                            else:
                                failed_computers.append(host)
                                # Mark connection as inactive to trigger reconnection
                                connection['connection_active'] = False
                                self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Reconnecting...")
                                # Schedule immediate reconnection
                                self.connection_manager.schedule_reconnection(conn_id)

                        except Exception as e:
                            failed_computers.append(host)
                            # Mark connection as inactive to trigger reconnection
                            connection['connection_active'] = False
                            self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Reconnecting...")
                            # Schedule immediate reconnection
                            self.connection_manager.schedule_reconnection(conn_id)

                            # Log the error
                            logging.error(f"Power action error for {host}: {str(e)}")

                    # Update power status based on results
                    if not failed_computers and successful_computers:
                        self.update_power_status(f"{action.capitalize()} initiated for all computers", "green")
                        self.parent_app.toast.show_toast(f"{action.capitalize()} successfully sent to all computers",
                                                         "success")
                    elif failed_computers and successful_computers:
                        self.update_power_status(
                            f"{action.capitalize()} succeeded for {len(successful_computers)} computers, "
                            f"failed for {len(failed_computers)} computers",
                            "orange"
                        )
                        self.parent_app.toast.show_toast(
                            f"Failed for: {', '.join(failed_computers[:3])}"
                            f"{' and others' if len(failed_computers) > 3 else ''}. Reconnecting...",
                            "warning"
                        )
                    else:
                        self.update_power_status(f"{action.capitalize()} failed for all computers", "red")
                        self.parent_app.toast.show_toast("Attempting to reconnect to all computers...", "error")

            else:
                # Single computer mode
                if not self.parent_app.active_connection:
                    self.update_power_status("Please select a computer first", "red")
                    return

                connection = self.connection_manager.connections.get(self.parent_app.active_connection)
                if not connection:
                    self.update_power_status("Connection not found", "red")
                    return

                host = connection.get('host', 'Unknown')

                if messagebox.askyesno("Confirm Action", confirm_msg):
                    try:
                        # Update status to show action in progress
                        self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection, "status",
                                                                         f"Sending {action}...")

                        # Send command with timeout handling
                        response = self.connection_manager.send_command(self.parent_app.active_connection,
                                                                        'power_management', {
                                                                            'action': action
                                                                        })

                        if response and response.get('status') == 'success':
                            self.update_power_status(f"{action.capitalize()} command sent successfully", "green")
                            self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection,
                                                                             "status", "Connected")
                        else:
                            self.update_power_status(f"Failed to execute {action}", "red")
                            # Mark connection as inactive to trigger reconnection
                            connection['connection_active'] = False
                            self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection,
                                                                             "status", "Reconnecting...")
                            self.parent_app.toast.show_toast(f"Attempting to reconnect to {host}...", "warning")
                            # Schedule immediate reconnection
                            self.connection_manager.schedule_reconnection(self.parent_app.active_connection)

                    except Exception as e:
                        self.update_power_status(f"Failed to execute {action}: {str(e)}", "red")
                        # Mark connection as inactive to trigger reconnection
                        connection['connection_active'] = False
                        self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection, "status",
                                                                         "Reconnecting...")
                        self.parent_app.toast.show_toast(f"Attempting to reconnect to {host}...", "warning")
                        # Schedule immediate reconnection
                        self.connection_manager.schedule_reconnection(self.parent_app.active_connection)

                        # Log the error
                        logging.error(f"Power action error for {host}: {str(e)}")

        except Exception as e:
            self.update_power_status(f"Error: {str(e)}", "red")
            logging.error(f"Power action error: {str(e)}")

    def schedule_shutdown(self, time_str, power_mode):
        """Schedule a shutdown for the selected computer(s)"""
        try:
            if not time_str:
                self.update_power_status("Please enter time in HH:MM format", "red")
                return

            try:
                # Parse the time
                hours, minutes = map(int, time_str.split(':'))
                if not (0 <= hours <= 23 and 0 <= minutes <= 59):
                    raise ValueError("Invalid time values")

                # Calculate seconds until shutdown
                current_time = datetime.now()
                target_time = current_time.replace(hour=hours, minute=minutes, second=0, microsecond=0)

                # If the time has already passed today, schedule for tomorrow
                if target_time <= current_time:
                    target_time = target_time.replace(day=current_time.day + 1)

                seconds_until_shutdown = int((target_time - current_time).total_seconds())

                if power_mode == "all":
                    if messagebox.askyesno("Confirm Action", "Schedule shutdown for all computers?"):
                        failed_computers = []
                        successful_computers = []

                        for conn_id in list(self.connection_manager.connections.keys()):
                            connection = self.connection_manager.connections.get(conn_id)
                            if not connection:
                                continue

                            host = connection.get('host', 'Unknown')

                            try:
                                # Update status to show action in progress
                                self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Scheduling...")

                                response = self.connection_manager.send_command(conn_id, 'power_management', {
                                    'action': 'shutdown',
                                    'seconds': seconds_until_shutdown
                                })

                                if response and response.get('status') == 'success':
                                    successful_computers.append(host)
                                    self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Connected")
                                else:
                                    failed_computers.append(host)
                                    # Mark for reconnection
                                    connection['connection_active'] = False
                                    self.parent_app.connection_tab.computer_list.set(conn_id, "status",
                                                                                     "Reconnecting...")
                                    # Schedule immediate reconnection
                                    self.connection_manager.schedule_reconnection(conn_id)

                            except Exception as e:
                                failed_computers.append(host)
                                # Mark for reconnection
                                connection['connection_active'] = False
                                self.parent_app.connection_tab.computer_list.set(conn_id, "status", "Reconnecting...")
                                # Schedule immediate reconnection
                                self.connection_manager.schedule_reconnection(conn_id)

                                # Log the error
                                logging.error(f"Schedule shutdown error for {host}: {str(e)}")

                        # Update power status based on results
                        if not failed_computers and successful_computers:
                            self.update_power_status("Shutdown scheduled for all computers", "green")
                            self.parent_app.toast.show_toast(f"Shutdown scheduled for all computers at {time_str}",
                                                             "success")
                        elif failed_computers and successful_computers:
                            self.update_power_status(
                                f"Scheduling succeeded for {len(successful_computers)} computers, "
                                f"failed for {len(failed_computers)} computers",
                                "orange"
                            )
                            self.parent_app.toast.show_toast(
                                f"Failed for: {', '.join(failed_computers[:3])}"
                                f"{' and others' if len(failed_computers) > 3 else ''}. Reconnecting...",
                                "warning"
                            )
                        else:
                            self.update_power_status("Scheduling failed for all computers", "red")
                            self.parent_app.toast.show_toast("Attempting to reconnect to all computers...", "error")
                else:
                    if not self.parent_app.active_connection:
                        self.update_power_status("Please select a computer first", "red")
                        return

                    connection = self.connection_manager.connections.get(self.parent_app.active_connection)
                    if not connection:
                        self.update_power_status("Connection not found", "red")
                        return

                    host = connection.get('host', 'Unknown')

                    try:
                        # Update status to show action in progress
                        self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection, "status",
                                                                         "Scheduling...")

                        response = self.connection_manager.send_command(self.parent_app.active_connection,
                                                                        'power_management', {
                                                                            'action': 'shutdown',
                                                                            'seconds': seconds_until_shutdown
                                                                        })

                        if response and response.get('status') == 'success':
                            self.update_power_status(
                                f"Shutdown scheduled successfully for {time_str}",
                                "green"
                            )
                            self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection,
                                                                             "status", "Connected")
                        else:
                            self.update_power_status("Failed to schedule shutdown", "red")
                            # Mark connection as inactive to trigger reconnection
                            connection['connection_active'] = False
                            self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection,
                                                                             "status", "Reconnecting...")
                            self.parent_app.toast.show_toast(f"Attempting to reconnect to {host}...", "warning")
                            # Schedule immediate reconnection
                            self.connection_manager.schedule_reconnection(self.parent_app.active_connection)

                    except Exception as e:
                        self.update_power_status(f"Failed to schedule shutdown: {str(e)}", "red")
                        # Mark connection as inactive to trigger reconnection
                        connection['connection_active'] = False
                        self.parent_app.connection_tab.computer_list.set(self.parent_app.active_connection, "status",
                                                                         "Reconnecting...")
                        self.parent_app.toast.show_toast(f"Attempting to reconnect to {host}...", "warning")
                        # Schedule immediate reconnection
                        self.connection_manager.schedule_reconnection(self.parent_app.active_connection)

                        # Log the error
                        logging.error(f"Schedule shutdown error for {host}: {str(e)}")

            except ValueError:
                self.update_power_status("Invalid time format. Use HH:MM", "red")
        except Exception as e:
            self.update_power_status(f"Error: {str(e)}", "red")
            logging.error(f"Schedule shutdown error: {str(e)}")