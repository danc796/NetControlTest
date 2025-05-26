import time
import logging
import threading
import customtkinter as ctk
import tkinter as tk

class SystemMonitor:
    def __init__(self, parent_app):
        self.parent_app = parent_app
        self.monitoring_active = False
        self.last_cpu_percent = None
        self.last_memory_percent = None
        self.last_disk_usage = {}
        self.progress_bars = {}

    def initialize_monitoring(self):
        """Initialize monitoring threads safely"""
        if hasattr(self, 'monitoring_thread'):
            return  # Don't create multiple threads

        # Start hardware monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self.monitor_resources,
            daemon=True
        )
        self.monitoring_thread.start()
        logging.info("Hardware monitoring thread started")

    def monitor_resources(self):
        """Monitor system resources with shutdown check"""
        logging.info("Starting resource monitoring")
        while getattr(self.parent_app, 'running', True):  # Safe attribute access
            try:
                if self.parent_app.active_connection and self.monitoring_active:
                    # Don't check for specific attributes, just call refresh
                    print("Refreshing monitoring...")
                    self.refresh_monitoring()
                # Always sleep to prevent excessive CPU usage
                time.sleep(2)  # Reduced update frequency
            except Exception as e:
                logging.error(f"Monitor resources error: {str(e)}")
                time.sleep(2)  # Wait before trying again

        logging.info("Resource monitoring stopped")

    def refresh_monitoring(self):
        """Refresh monitoring data with improved error handling and value preservation"""
        # FIX: Access active_connection from parent_app instead of self
        if not self.parent_app.active_connection:
            return

        try:
            # FIX: Access connection_manager through parent_app
            response = self.parent_app.connection_manager.send_command(
                self.parent_app.active_connection,
                'hardware_monitor',
                {}
            )

            # Print for debugging
            print(f"Refresh monitoring response: {response}")

            # Early return if no response - don't reset values
            if not response:
                print("No response from server")
                return

            # Validate response format
            if not isinstance(response, dict):
                print("Invalid response format from server")
                return

            if response.get('status') != 'success':
                print(f"Error from server: {response.get('message', 'Unknown error')}")
                return

            data = response.get('data')
            if not isinstance(data, dict):
                print("Invalid data format from server")
                return

            # Print for debugging
            print(f"Hardware data: {data}")

            # Update hardware info with validation
            self.update_hardware_info(data)

        except Exception as e:
            print(f"Refresh monitoring error: {str(e)}")

    def update_hardware_info(self, data):
        """Update hardware monitoring displays with widget validation and value preservation"""
        if not self.monitoring_active:
            print("Not updating hardware info - monitoring inactive")
            return

        try:
            # Update CPU usage with validation
            if 'cpu' in self.progress_bars and self.progress_bars['cpu'].winfo_exists():
                cpu_percent = data.get('cpu_percent')
                print(f"CPU percent: {cpu_percent}")

                # Only update if value is not None and greater than 0
                if cpu_percent is not None and isinstance(cpu_percent, (int, float)):
                    self.progress_bars['cpu'].set(cpu_percent / 100.0)

                    # Use parent_app.monitoring_tab to access the labels
                    if hasattr(self.parent_app, 'monitoring_tab') and hasattr(self.parent_app.monitoring_tab,
                                                                              'cpu_label'):
                        try:
                            if self.parent_app.monitoring_tab.cpu_label.winfo_exists():
                                self.parent_app.monitoring_tab.cpu_label.configure(text=f"{cpu_percent:.1f}%")
                        except Exception as label_error:
                            print(f"Error updating CPU label: {label_error}")

            # Update memory usage with validation
            if 'mem' in self.progress_bars and self.progress_bars['mem'].winfo_exists():
                memory_data = data.get('memory_usage', {})
                if isinstance(memory_data, dict):
                    memory_percent = memory_data.get('percent')
                    print(f"Memory percent: {memory_percent}")

                    # Only update if value is not None and greater than 0
                    if memory_percent is not None and isinstance(memory_percent, (int, float)):
                        self.progress_bars['mem'].set(memory_percent / 100.0)

                        # Use parent_app.monitoring_tab to access the labels
                        if hasattr(self.parent_app, 'monitoring_tab') and hasattr(self.parent_app.monitoring_tab,
                                                                                  'mem_label'):
                            try:
                                if self.parent_app.monitoring_tab.mem_label.winfo_exists():
                                    self.parent_app.monitoring_tab.mem_label.configure(text=f"{memory_percent:.1f}%")
                            except Exception as label_error:
                                print(f"Error updating memory label: {label_error}")

            # Only update disk info if we're on the monitoring tab and there's valid data
            if (self.monitoring_active and
                    hasattr(self.parent_app, 'monitoring_tab') and
                    hasattr(self.parent_app.monitoring_tab, 'disk_frame') and
                    self.parent_app.monitoring_tab.disk_frame.winfo_exists() and
                    'disk_usage' in data and data['disk_usage']):

                # Don't clear existing disk information if there's no valid data
                disk_usage = data.get('disk_usage', {})
                if disk_usage and isinstance(disk_usage, dict) and any(disk_usage.values()):
                    # Only then update disk info
                    self.update_disk_info(disk_usage)

        except Exception as e:
            print(f"Error updating hardware info: {str(e)}")
            import traceback
            traceback.print_exc()

    def update_disk_info(self, disk_usage):
        """Separate method for updating disk information with reduced flicker"""
        try:
            if not isinstance(disk_usage, dict) or not self.monitoring_active:
                return

            # Access disk_frame through the monitoring_tab reference
            if not hasattr(self.parent_app, 'monitoring_tab') or not hasattr(self.parent_app.monitoring_tab,
                                                                             'disk_frame'):
                print("Disk frame not accessible")
                return

            disk_frame = self.parent_app.monitoring_tab.disk_frame
            if not disk_frame.winfo_exists():
                return

            # Check if we already have disks displayed and new data is similar
            existing_disks = [w for w in disk_frame.winfo_children() if isinstance(w, ctk.CTkFrame)]

            # Only recreate UI if data structure has changed significantly
            if len(existing_disks) > 1:  # Header + at least one disk row
                drives = disk_usage.keys()

                # If we have roughly the same number of drives, update in place
                if len(drives) == len(existing_disks) - 1:  # -1 for header
                    self.update_disk_values(disk_usage, existing_disks)
                    return

            # Clear existing disk information
            for widget in disk_frame.winfo_children():
                widget.destroy()

            # Create header
            header_frame = ctk.CTkFrame(disk_frame)
            header_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

            headers = ["Drive", "Capacity", "Used Space", "Free Space", "Usage"]
            widths = [100, 150, 150, 150, 100]

            for header, width in zip(headers, widths):
                ctk.CTkLabel(header_frame, text=header, width=width).pack(side=tk.LEFT, padx=5)

            for mount, usage in disk_usage.items():
                if not isinstance(usage, dict):
                    continue

                try:
                    disk_frame_item = ctk.CTkFrame(disk_frame)
                    disk_frame_item.pack(fill=tk.X, padx=5, pady=2)

                    total = usage.get('total', 0)
                    used = usage.get('used', 0)
                    percent = usage.get('percent', 0)

                    if not all(isinstance(x, (int, float)) for x in [total, used, percent]):
                        continue

                    # Drive letter/name
                    ctk.CTkLabel(disk_frame_item, text=str(mount), width=100).pack(side=tk.LEFT, padx=5)

                    # Total capacity
                    total_gb = total / (1024 ** 3)
                    ctk.CTkLabel(disk_frame_item, text=f"{total_gb:.1f} GB", width=150).pack(side=tk.LEFT, padx=5)

                    # Used space
                    used_gb = used / (1024 ** 3)
                    ctk.CTkLabel(disk_frame_item, text=f"{used_gb:.1f} GB", width=150).pack(side=tk.LEFT, padx=5)

                    # Free space
                    free_gb = (total - used) / (1024 ** 3)
                    ctk.CTkLabel(disk_frame_item, text=f"{free_gb:.1f} GB", width=150).pack(side=tk.LEFT, padx=5)

                    # Usage percentage
                    percent_frame = ctk.CTkFrame(disk_frame_item)
                    percent_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

                    if self.monitoring_active and disk_frame.winfo_exists():
                        progress = ctk.CTkProgressBar(percent_frame)
                        progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
                        progress.set(percent / 100.0)

                        # Color based on usage
                        if percent >= 90:
                            progress.configure(progress_color="red")
                        elif percent >= 75:
                            progress.configure(progress_color="orange")
                        else:
                            progress.configure(progress_color="green")

                        ctk.CTkLabel(percent_frame, text=f"{percent:.1f}%", width=50).pack(side=tk.LEFT, padx=5)

                except Exception as disk_error:
                    print(f"Error displaying disk {mount}: {str(disk_error)}")
                    continue

        except Exception as e:
            print(f"Error updating disk info: {str(e)}")

    def update_disk_values(self, disk_usage, existing_frames):
        """Update disk values in-place without destroying and recreating widgets"""
        try:
            # Skip header frame (first frame)
            header_frame = existing_frames[0]
            disk_frames = existing_frames[1:]

            # Update each disk frame with new values if match is found
            for i, (mount, usage) in enumerate(disk_usage.items()):
                if not isinstance(usage, dict) or i >= len(disk_frames):
                    continue

                disk_frame = disk_frames[i]
                labels = [w for w in disk_frame.winfo_children() if isinstance(w, ctk.CTkLabel)]

                # If structure doesn't match, skip this update
                if len(labels) < 2:
                    continue

                try:
                    total = usage.get('total', 0)
                    used = usage.get('used', 0)
                    percent = usage.get('percent', 0)

                    if not all(isinstance(x, (int, float)) for x in [total, used, percent]):
                        continue

                    # Drive name should stay the same
                    # [0] = Drive name label

                    # Update values only
                    # [1] = Total capacity
                    total_gb = total / (1024 ** 3)
                    if len(labels) > 1:
                        labels[1].configure(text=f"{total_gb:.1f} GB")

                    # [2] = Used space
                    used_gb = used / (1024 ** 3)
                    if len(labels) > 2:
                        labels[2].configure(text=f"{used_gb:.1f} GB")

                    # [3] = Free space
                    free_gb = (total - used) / (1024 ** 3)
                    if len(labels) > 3:
                        labels[3].configure(text=f"{free_gb:.1f} GB")

                    # Update percentage frames
                    percent_frames = [w for w in disk_frame.winfo_children()
                                      if isinstance(w, ctk.CTkFrame) and w != header_frame]

                    if percent_frames:
                        percent_frame = percent_frames[0]

                        # Get progress bar
                        progress_bars = [w for w in percent_frame.winfo_children()
                                         if isinstance(w, ctk.CTkProgressBar)]
                        if progress_bars:
                            progress = progress_bars[0]
                            progress.set(percent / 100.0)

                            # Update color based on usage
                            if percent >= 90:
                                progress.configure(progress_color="red")
                            elif percent >= 75:
                                progress.configure(progress_color="orange")
                            else:
                                progress.configure(progress_color="green")

                        # Update percentage label
                        percent_labels = [w for w in percent_frame.winfo_children()
                                          if isinstance(w, ctk.CTkLabel)]
                        if percent_labels:
                            percent_labels[0].configure(text=f"{percent:.1f}%")

                except Exception as disk_error:
                    print(f"Error updating disk values for {mount}: {str(disk_error)}")

        except Exception as e:
            print(f"Error in update_disk_values: {str(e)}")