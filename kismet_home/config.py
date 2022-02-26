"""
Simple configuration management for kismet_home settings
"""
import os.path
from configparser import ConfigParser
from pathlib import Path
from typing import Dict

from kismet_home import CONSOLE

DEFAULT_INI = os.path.expanduser('~/.config/kodegeek/kismet_home/config.ini')
VALID_KEYS = {'api_key', 'url'}


class Reader:

    def __init__(self, config_file: str = DEFAULT_INI):
        """
        Constructor
        :param config_file: Optional override of the ini configuration file
        """
        self.config = ConfigParser()
        if not self.config.read(config_file):
            raise ValueError(f"Could not read {config_file}")

    def get_api_key(self):
        """
        Get back the API key used to connect to Kismet
        :return:
        """
        return self.config.get('server', 'api_key')

    def get_url(self):
        """
        Get back URL of Kismet server
        :return:
        """
        return self.config.get('server', 'url')


class Writer:

    def __init__(
            self,
            *,
            server_keys: Dict[str, str]
    ):
        if not server_keys:
            raise ValueError("Configuration is incomplete!, aborting!")
        self.config = ConfigParser()
        self.config.add_section('server')
        valid_keys_cnt = 0
        for key in server_keys:
            value = server_keys[key]
            if key not in VALID_KEYS:
                CONSOLE.log(f"Ignoring invalid key: {key} = {value}")
                continue
            self.config.set('server', key, value)
            CONSOLE.log(f"Added: server: {key} = {value}")
        for valid_key in VALID_KEYS:
            if not self.config.get('server', valid_key):
                raise ValueError(f"Missing required key: {valid_key}")

    def save(
            self,
            *,
            config_file: str = DEFAULT_INI
    ):
        basedir = Path(config_file).parent
        basedir.mkdir(exist_ok=True, parents=True)
        with open(config_file, 'w') as config:
            self.config.write(config, space_around_delimiters=True)
        CONSOLE.log(f"Configuration file {config_file} written")
