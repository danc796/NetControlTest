import argparse
import logging


from nc_client.ui.main_window import MainWindow
from nc_client.utils.logging import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="NetControl Client")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point with enhanced restart capability"""
    # Parse arguments
    args = parse_arguments()

    # Setup logging with appropriate level
    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(log_level)

    # Log application start
    logging.info("NetControl Client starting...")

    # Initialize and start the main window
    app = MainWindow()

    try:
        app.mainloop()
    except Exception as e:
        logging.critical(f"Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        logging.info("NetControl Client shutdown")


if __name__ == "__main__":
    main()