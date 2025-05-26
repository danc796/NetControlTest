import customtkinter as ctk


class ToastNotification:
    def __init__(self, parent):
        self.parent = parent
        self.notifications = []
        self.showing = False

    def show_toast(self, message, category="info"):
        """Show a toast notification with auto-dismiss"""
        # Configure colors based on category
        colors = {
            "success": "#28a745",  # Green
            "error": "#dc3545",  # Red
            "info": "#007bff",  # Blue
            "warning": "#ffc107"  # Yellow
        }
        bg_color = colors.get(category, "#6c757d")  # Default gray

        # Create a notification window
        toast = ctk.CTkFrame(self.parent)
        toast.configure(fg_color=bg_color)

        # Add a message
        label = ctk.CTkLabel(
            toast,
            text=message,
            text_color="white",
            font=("Helvetica", 12)
        )
        label.pack(padx=20, pady=10)

        # Position in bottom right
        screen_width = self.parent.winfo_width()
        screen_height = self.parent.winfo_height()

        # Add to notifications queue
        self.notifications.append({
            'widget': toast,
            'start_time': self.parent.after(0, lambda: None)  # Current time
        })

        # Show notification if not already showing
        if not self.showing:
            self._show_next_notification()

    def _show_next_notification(self):
        """Show the next notification in queue"""
        if not self.notifications:
            self.showing = False
            return

        self.showing = True
        notification = self.notifications[0]
        toast = notification['widget']

        # Position toast
        toast.place(
            relx=1,
            rely=1,
            anchor="se",
            x=-20,
            y=-20
        )

        # Schedule removal
        self.parent.after(3000, lambda: self._remove_notification(notification))

    def _remove_notification(self, notification):
        """Remove a notification and show next if any"""
        if notification in self.notifications:
            self.notifications.remove(notification)
            notification['widget'].destroy()

            # Show the next notification if any
            self._show_next_notification()