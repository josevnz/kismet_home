#!/usr/bin/env python
"""
# kismet_home_setup.py - Interactive configuration tool for kismet_home scripts

# Author
Jose Vicente Nunez Zuleta (kodegeek.com@protonmail.com)
"""
import logging
import sys
import argparse

from kismet_home import CONSOLE
from kismet_home.config import Writer

if __name__ == '__main__':

    arg_parser = argparse.ArgumentParser(
        description="Configure kistmet_home helper",
        prog=__file__
    )
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        default=False,
        help="Enable debug mode"
    )

    args = arg_parser.parse_args()
    server_keys = {}
    try:
        server_keys['url'] = input("Please enter the URL of your Kismet server: ")
        server_keys['api_key'] = input("Please enter your API key: ")
        conf_writer = Writer(server_keys=server_keys)
        conf_writer.save()
    except ValueError:
        logging.exception("There was an error")
        sys.exit(100)
    except KeyboardInterrupt:
        CONSOLE.log("Scan interrupted, exiting...")
    sys.exit(0)
