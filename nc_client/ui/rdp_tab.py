import tkinter as tk
import customtkinter as ctk


class RDPTab:
    def __init__(self, parent, notebook, app):
        self.parent = parent
        self.notebook = notebook
        self.app = app

        # Create remote desktop tab
        self.create_remote_desktop_tab()

        # Register this tab with the RDP client
        self.app.rdp_client.register_ui(self)

    def create_remote_desktop_tab(self):
        """Create a remote desktop tab with calibration feature"""
        remote_desktop_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(remote_desktop_frame, text="Remote Desktop")

        # Top controls frame
        top_frame = ctk.CTkFrame(remote_desktop_frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # Title and status
        title_frame = ctk.CTkFrame(top_frame)
        title_frame.pack(side=tk.LEFT, fill=tk.Y)

        ctk.CTkLabel(
            title_frame,
            text="Remote Desktop Control",
            font=("Helvetica", 16, "bold")
        ).pack(side=tk.TOP, anchor="w", padx=5)

        self.rdt_status = ctk.CTkLabel(
            title_frame,
            text="Select computer and activate the remote desktop",
            font=("Helvetica", 12)
        )
        self.rdt_status.pack(side=tk.TOP, anchor="w", padx=5, pady=2)

        # Create main display frame that takes most of the space
        main_display_container = ctk.CTkFrame(remote_desktop_frame)
        main_display_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create the RDP display frame
        self.rdp_display_frame = ctk.CTkFrame(main_display_container, fg_color="#242424")
        self.rdp_display_frame.pack(fill=tk.BOTH, expand=True)

        # Create a canvas for the RDP display
        self.rdp_canvas = tk.Canvas(
            self.rdp_display_frame,
            bg="black",
            highlightthickness=0,
            borderwidth=0
        )
        self.rdp_canvas.pack(fill=tk.BOTH, expand=True)

        # Create a message for when no RDP is active
        self.rdp_message = ctk.CTkLabel(
            self.rdp_canvas,
            text="Remote Desktop Viewer\nClick 'Start Remote Desktop' to connect",
            font=("Helvetica", 16),
            text_color="white"
        )
        self.rdp_message.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Create offset adjustment controls (hidden by default)
        self.offset_frame = ctk.CTkFrame(remote_desktop_frame)

        # X offset control
        x_frame = ctk.CTkFrame(self.offset_frame)
        x_frame.pack(side=tk.LEFT, padx=10)

        ctk.CTkLabel(x_frame, text="X Offset:").pack(side=tk.LEFT)

        self.x_offset = tk.IntVar(value=0)
        x_slider = ctk.CTkSlider(
            x_frame,
            from_=-50,
            to=50,
            variable=self.x_offset,
            width=150
        )
        x_slider.pack(side=tk.LEFT, padx=5)

        ctk.CTkLabel(x_frame, textvariable=self.x_offset).pack(side=tk.LEFT)

        # Y offset control
        y_frame = ctk.CTkFrame(self.offset_frame)
        y_frame.pack(side=tk.LEFT, padx=10)

        ctk.CTkLabel(y_frame, text="Y Offset:").pack(side=tk.LEFT)

        self.y_offset = tk.IntVar(value=0)
        y_slider = ctk.CTkSlider(
            y_frame,
            from_=-50,
            to=50,
            variable=self.y_offset,
            width=150
        )
        y_slider.pack(side=tk.LEFT, padx=5)

        ctk.CTkLabel(y_frame, textvariable=self.y_offset).pack(side=tk.LEFT)

        # Reset button
        reset_btn = ctk.CTkButton(
            self.offset_frame,
            text="Reset Offsets",
            command=lambda: (self.x_offset.set(0), self.y_offset.set(0))
        )
        reset_btn.pack(side=tk.LEFT, padx=10)

        # Create a persistent control panel
        self.rdp_control_panel = ctk.CTkFrame(remote_desktop_frame, height=50)
        self.rdp_control_panel.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)
        self.rdp_control_panel.pack_propagate(False)

        # Control buttons
        self.rdp_button = ctk.CTkButton(
            self.rdp_control_panel,
            text="Start Remote Desktop",
            command=self.toggle_rdp,
            width=150,
            height=30
        )
        self.rdp_button.pack(side=tk.LEFT, padx=5, pady=10)

        self.rdp_close_button = ctk.CTkButton(
            self.rdp_control_panel,
            text="Close RDP",
            command=self.stop_rdp,
            width=100,
            height=30,
            fg_color="#FF5555",
            hover_color="#FF0000",
            state="disabled"
        )
        self.rdp_close_button.pack(side=tk.LEFT, padx=5, pady=10)

        # Status indicator
        self.rdp_status_indicator = ctk.CTkLabel(
            self.rdp_control_panel,
            text="Not connected",
            font=("Helvetica", 12),
            text_color="#888888"
        )
        self.rdp_status_indicator.pack(side=tk.RIGHT, padx=10, pady=10)


    def toggle_rdp(self):
        """Toggle RDP session - delegate to RDP client"""
        self.app.rdp_client.toggle_rdp()

    def stop_rdp(self):
        """Stop RDP session - delegate to RDP client"""
        self.app.rdp_client.stop_rdp()