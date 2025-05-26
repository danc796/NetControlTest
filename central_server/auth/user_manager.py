"""
User Manager for the Central Management Server.
Handles user authentication, creation, and management.
"""

import logging
import hashlib


class UserManager:
    def __init__(self, database_manager):
        """Initialize the user manager with a database manager"""
        self.db = database_manager

    def authenticate_user(self, username, password):
        """Authenticate a user with username and password"""
        user = self.db.authenticate_user(username, password)
        if user:
            return True, user
        return False, None

    def create_user(self, username, password, is_admin=False):
        """Create a new user"""
        if not username or not password:
            return False, "Username and password are required"

        # Password validation
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"

        # Create the user
        success, message = self.db.create_user(username, password, 1 if is_admin else 0)
        return success, message

    def get_all_users(self):
        """Get list of all users"""
        return self.db.get_all_users()

    def change_password(self, user_id, old_password, new_password):
        """Change a user's password"""
        try:
            # Validate new password
            if len(new_password) < 6:
                return False, "New password must be at least 6 characters long"

            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Verify old password
            old_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
            cursor.execute(
                "SELECT user_id FROM users WHERE user_id = ? AND password_hash = ?",
                (user_id, old_password_hash)
            )
            result = cursor.fetchone()

            if not result:
                conn.close()
                return False, "Current password is incorrect"

            # Update password
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (new_password_hash, user_id)
            )

            conn.commit()
            conn.close()

            return True, "Password changed successfully"

        except Exception as e:
            logging.error(f"Error changing password: {e}")
            return False, str(e)

    def delete_user(self, username):
        """Delete a user"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                conn.close()
                return False, "User not found"

            # Check if it's the admin user (cannot delete the original admin)
            cursor.execute(
                "SELECT user_id FROM users WHERE username = ? AND user_id = 1",
                (username,)
            )
            if cursor.fetchone():
                conn.close()
                return False, "Cannot delete the main admin user"

            # Delete the user
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))

            # Clean up any active connections or sharing
            if conn.total_changes > 0:
                # Attempt to clean up user data
                try:
                    self.db.clean_disconnected_user(username)
                except Exception as cleanup_error:
                    logging.error(f"Error cleaning up after user deletion: {cleanup_error}")

            conn.commit()
            conn.close()

            return True, f"User '{username}' deleted successfully"

        except Exception as e:
            logging.error(f"Error deleting user: {e}")
            return False, str(e)

    def promote_to_admin(self, username):
        """Promote a user to admin status"""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute("SELECT user_id, is_admin FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                conn.close()
                return False, "User not found"

            # Check if already an admin
            if user['is_admin'] == 1:
                conn.close()
                return False, f"User '{username}' is already an admin"

            # Promote to admin
            cursor.execute(
                "UPDATE users SET is_admin = 1 WHERE username = ?",
                (username,)
            )

            conn.commit()
            conn.close()

            return True, f"User '{username}' promoted to admin successfully"

        except Exception as e:
            logging.error(f"Error promoting user to admin: {e}")
            return False, str(e)

    def create_user_as_admin(self, admin_user_id, new_username, new_password, is_new_admin=False):
        """Create a new user when requested by an admin"""
        # Verify the requesting user is an admin
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT is_admin FROM users WHERE user_id = ?", (admin_user_id,))
            user = cursor.fetchone()

            if not user or not user['is_admin']:
                conn.close()
                return False, "Unauthorized: Admin privileges required"

            # Now create the new user
            if not new_username or not new_password:
                return False, "Username and password are required"

            # Password validation
            if len(new_password) < 6:
                return False, "Password must be at least 6 characters long"

            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = ?", (new_username,))
            if cursor.fetchone():
                conn.close()
                return False, "Username already exists"

            # Create the user
            password_hash = hashlib.sha256(new_password.encode()).hexdigest()

            cursor.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                (new_username, password_hash, 1 if is_new_admin else 0)
            )

            conn.commit()
            conn.close()

            return True, f"User '{new_username}' created successfully"

        except Exception as e:
            logging.error(f"Error creating user as admin: {e}")
            return False, str(e)