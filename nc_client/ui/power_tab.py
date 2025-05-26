import tkinter as tk
import customtkinter as ctk


class PowerTab:
    def __init__(self, parent, notebook, app):
        self.parent = parent
        self.notebook = notebook
        self.app = app

        # Create power management tab
        self.create_power_tab()

        # Set reference to status label in the PowerManager
        self.app.power_manager.set_power_status(self.power_status)

    def create_power_tab(self):
        """Create enhanced power management tab"""
        power_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(power_frame, text="Power")

        # Title and status
        title_frame = ctk.CTkFrame(power_frame)
        title_frame.pack(pady=20)

        ctk.CTkLabel(
            title_frame,
            text="Power Management",
            font=("Helvetica", 20)
        ).pack()

        self.power_status = ctk.CTkLabel(
            title_frame,
            text="Select computer(s) to manage power options",
            font=("Helvetica", 12)
        )
        self.power_status.pack(pady=10)

        # Action modes
        mode_frame = ctk.CTkFrame(power_frame)
        mode_frame.pack(pady=10)

        self.power_mode = tk.StringVar(value="single")

        single_radio = ctk.CTkRadioButton(
            mode_frame,
            text="Single Computer",
            variable=self.power_mode,
            value="single"
        )
        single_radio.pack(side=tk.LEFT, padx=10)

        all_radio = ctk.CTkRadioButton(
            mode_frame,
            text="All Computers",
            variable=self.power_mode,
            value="all"
        )
        all_radio.pack(side=tk.LEFT, padx=10)

        # Scheduled shutdown frame
        schedule_frame = ctk.CTkFrame(power_frame)
        schedule_frame.pack(pady=10, padx=20, fill=tk.X)

        ctk.CTkLabel(
            schedule_frame,
            text="Schedule Shutdown",
            font=("Helvetica", 14)
        ).pack(pady=5)

        # Center-aligned time input frame
        time_frame = ctk.CTkFrame(schedule_frame)
        time_frame.pack(pady=5)  # Removed fill=tk.X to allow centering

        # Time entry (HH:MM format) with label
        time_label = ctk.CTkLabel(
            time_frame,
            text="Enter time (HH:MM):",
            font=("Helvetica", 12)
        )
        time_label.pack(side=tk.LEFT, padx=5)

        self.schedule_time = ctk.CTkEntry(
            time_frame,
            placeholder_text="HH:MM",
            width=100
        )
        self.schedule_time.pack(side=tk.LEFT, padx=5)

        schedule_btn = ctk.CTkButton(
            schedule_frame,
            text="Schedule Shutdown",
            command=self.schedule_shutdown,
            width=200,
            height=40
        )
        schedule_btn.pack(pady=5)

        cancel_schedule_btn = ctk.CTkButton(
            schedule_frame,
            text="Cancel Scheduled Shutdown",
            command=lambda: self.power_action_with_confirmation(
                "cancel_scheduled",
                "Cancel all scheduled shutdowns?"
            ),
            width=200,
            height=40
        )
        cancel_schedule_btn.pack(pady=5)

        # Immediate actions frame
        actions_frame = ctk.CTkFrame(power_frame)
        actions_frame.pack(pady=10)

        # Create immediate action buttons
        buttons_data = [
            ("Shutdown", "shutdown", "This will shut down the selected computer(s). Continue?", "#FF6B6B"),
            ("Restart", "restart", "This will restart the selected computer(s). Continue?", "#4D96FF"),
            ("Lock Screen", "lock", "This will lock the selected computer(s). Continue?", "#FFB562")
        ]

        for text, action, confirm_msg, hover_color in buttons_data:
            ctk.CTkButton(
                actions_frame,
                text=text,
                command=lambda a=action, m=confirm_msg: self.power_action_with_confirmation(a, m),
                width=200,
                height=40,
                hover_color=hover_color
            ).pack(pady=5)

    def schedule_shutdown(self):
        """Schedule shutdown - delegate to power manager"""
        time_str = self.schedule_time.get()
        self.app.power_manager.schedule_shutdown(time_str, self.power_mode.get())

    def power_action_with_confirmation(self, action, confirm_msg):
        """Execute power action with confirmation - delegate to power manager"""
        self.app.power_manager.power_action_with_confirmation(
            action, confirm_msg, self.power_mode.get()
        )