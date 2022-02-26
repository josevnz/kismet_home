#!/usr/bin/env python
"""
# kismet_home_alerts.py
# Author
Jose Vicente Nunez Zuleta (kodegeek.com@protonmail.com)
"""
import logging
import sys

from rich.progress import TimeElapsedColumn, Progress, TextColumn
import argparse

from kismet_home import CONSOLE

if __name__ == '__main__':



    arg_parser = argparse.ArgumentParser(
        description="",
        prog=__file__
    )
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help="Enable debug mode"
    )

    args = arg_parser.parse_args()

    current_app_progress = Progress(
        TimeElapsedColumn(),
        TextColumn("{task.description}"),
    )
    scanning_task = current_app_progress.add_task("[yellow]Waiting[/yellow] for scan results... :hourglass:")

    try:
        pass
    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        CONSOLE.log("Scan interrupted, exiting...")
    sys.exit(0)
