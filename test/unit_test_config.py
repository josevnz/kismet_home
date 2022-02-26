from pathlib import Path
from unittest import TestCase
from kismet_home.config import Reader, Writer

BASEDIR = Path(__file__).parent


class TestReader(TestCase):

    def test_read_config(self):
        conf_file = str(BASEDIR.joinpath("config.ini"))
        config_reader = Reader(conf_file)
        api_key = config_reader.get_api_key()
        self.assertIsNotNone(api_key)
        self.assertEqual("E41CAD466552810392D538FF8D43E2C5", api_key)
        url = config_reader.get_url()
        self.assertIsNotNone(url)
        self.assertEqual("http://raspberrypi.home:2501/", url)

        try:
            Reader("badddconfigfile")
            self.fail("Was expecting an error!")
        except ValueError:
            pass

    def test_write_config(self):
        server_keys = {
            'api_key': 'RANDOMKEY12345',
            'url': 'http://localhost:12345',
            'invalid_key': 'whocares'
        }
        temp_config_file = Path("/tmp/kismet_home_temp_config.ini")
        conf_writer = Writer(server_keys=server_keys)
        conf_writer.save(config_file=str(temp_config_file))
        temp_config_file.unlink()
