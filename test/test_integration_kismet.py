"""
Integration tests. Requires a working Kismet and an valid API key
It is recommended that you generate the configuration file using 'kismet_home_config.py'
"""
import json
import os
from datetime import datetime
from pathlib import Path

from unittest import TestCase
from kismet_home import CONSOLE
from kismet_home.config import Reader
from kismet_home.kismet import KismetWorker, KismetAdmin, KismetResultsParser

BASEDIR = Path(__file__).parent


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

    def test_parse_alert_definitions(self):
        with open(BASEDIR.joinpath('alert_definitions.json'), 'r') as json_file:
            data = json.load(json_file)
        alert_definitions = KismetResultsParser.parse_alert_definitions(
            alert_definitions=data
        )
        self.assertIsNotNone(alert_definitions)
        for definitions in alert_definitions:
            self.assertIn('description', definitions)
            self.assertIsNotNone(definitions['description'])

    def test_process_alerts(self):
        with open(BASEDIR.joinpath('alerts_example.json'), 'r') as json_file:
            data = json.load(json_file)
        alerts, severities, types = KismetResultsParser.process_alerts(
            alerts=data
        )
        self.assertIsNotNone(alerts)
        for alert in alerts:
            self.assertIn('text', alert)
            self.assertIsNotNone(alert['text'])
        self.assertIsNotNone(severities)
        for severity in severities:
            self.assertIsNotNone(severities[severity])
        self.assertIsNotNone(types)
        for stype in types:
            self.assertIsNotNone(types[stype])

    def test_pretty_timestamp(self):
        timestamps = {
            1645833048.375856: datetime(2022, 2, 25, 18, 50, 48, 375856),
            1645739791.814681: datetime(2022, 2, 24, 16, 56, 31, 814681)
        }
        for timestamp in timestamps:
            dt = KismetResultsParser.pretty_timestamp(timestamp)
            self.assertEqual(timestamps[timestamp], dt)

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
            name='OTHER',
            message="Fake alert for integration test!"
        )

        kw = KismetWorker(
            api_key=TestKismetWorker.config_reader.get_api_key(),
            url=TestKismetWorker.config_reader.get_url()
        )
        all_alerts = kw.get_all_alerts()
        self.assertIsNotNone(all_alerts)
