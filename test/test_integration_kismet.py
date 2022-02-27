"""
Integration tests. Requires a working Kismet and an valid API key
It is recommended that you generate the configuration file using 'kismet_home_config.py'
"""
import os

from unittest import TestCase
from kismet_home import CONSOLE
from kismet_home.config import Reader
from kismet_home.kismet import KismetWorker, KismetAdmin


class TestKismetWorker(TestCase):
    config_reader = Reader()

    def test_check_session(self):
        kw = KismetWorker(
            api_key=TestKismetWorker.config_reader.get_api_key(),
            url=TestKismetWorker.config_reader.get_url()
        )
        kw.check_session()

    def test_check_system_status(self):
        kw = KismetWorker(
            api_key=TestKismetWorker.config_reader.get_api_key(),
            url=TestKismetWorker.config_reader.get_url()
        )
        status = kw.check_system_status()
        self.assertIsNotNone(status)
        self.assertIn('kismet.system.memory.rss', status)

    def test_get_alert_definitions(self):
        kw = KismetWorker(
            api_key=TestKismetWorker.config_reader.get_api_key(),
            url=TestKismetWorker.config_reader.get_url()
        )
        defintions = kw.get_alert_definitions()
        self.assertIsNotNone(defintions)
        self.assertIn('kismet.alert.definition.description', defintions[0])

    def test_get_all_alerts(self):
        """
        We need to generate a fake alert in order to have something to show
        That requires and admin session.
        """
        if 'ADMIN_SESSION_API' not in os.environ:
            CONSOLE.log("'ADMIN_SESSION_API' environment variable not defined. Skipping this test")
            return
        ka = KismetAdmin(
            api_key=os.environ['ADMIN_SESSION_API'],
            url=TestKismetWorker.config_reader.get_url()
        )
        ka.raise_alert(
            name=None,
            message="Fake alert for integration test!"
        )

        kw = KismetWorker(
            api_key=TestKismetWorker.config_reader.get_api_key(),
            url=TestKismetWorker.config_reader.get_url()
        )
        all_alerts = kw.get_all_alerts()
        self.assertIsNotNone(all_alerts)
