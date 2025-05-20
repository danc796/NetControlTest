import platform
import os
import logging

def handle_power_action(action, seconds=None):
    """Handle power management commands with enhanced functionality"""
    try:
        if platform.system() == 'Windows':
            return handle_windows_power_action(action, seconds)
        else:
            return handle_unix_power_action(action, seconds)
    except Exception as e:
        logging.error(f"Power management error: {e}")
        return {
            'status': 'error',
            'message': f'Failed to execute power action: {e}'
        }

def handle_windows_power_action(action, seconds=None):
    """Handle power actions on Windows systems"""
    try:
        if action == 'shutdown':
            if seconds is not None:
                if seconds > 0:
                    os.system(f'shutdown /s /t {seconds}')
                else:
                    raise ValueError("Invalid shutdown time")
            else:
                os.system('shutdown /s /t 1')

        elif action == 'restart':
            os.system('shutdown /r /t 1')

        elif action == 'lock':
            os.system('rundll32.exe user32.dll,LockWorkStation')

        elif action == 'cancel_scheduled':
            os.system('shutdown /a')
        else:
            return {
                'status': 'error',
                'message': f'Unknown power action: {action}'
            }

        return {
            'status': 'success',
            'message': f'Power management action {action} initiated successfully'
        }
    except Exception as e:
        logging.error(f"Windows power action error: {e}")
        return {
            'status': 'error',
            'message': f'Failed to execute power action: {e}'
        }

def handle_unix_power_action(action, seconds=None):
    """Handle power actions on Unix-like systems"""
    try:
        if action == 'shutdown':
            if seconds is not None:
                os.system(f'shutdown -h +{seconds // 60}')  # Convert seconds to minutes for Linux
            else:
                os.system('shutdown -h now')
        elif action == 'restart':
            os.system('shutdown -r now')
        elif action == 'lock':
            os.system('loginctl lock-session')
        elif action == 'cancel_scheduled':
            os.system('shutdown -c')
        else:
            return {
                'status': 'error',
                'message': f'Unknown power action: {action}'
            }

        return {
            'status': 'success',
            'message': f'Power management action {action} initiated successfully'
        }
    except Exception as e:
        logging.error(f"Unix power action error: {e}")
        return {
            'status': 'error',
            'message': f'Failed to execute power action: {e}'
        }