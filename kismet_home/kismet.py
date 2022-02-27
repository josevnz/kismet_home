"""
Code related to interaction with Kismet REST-API server
"""
import json
from datetime import datetime
from typing import Any, Dict, Set, List, Union
import requests


class KismetBase:

    def __init__(self, *, api_key: str, url: str):
        """
        Parametric constructor
        :param api_key: The Kismet generated API key
        :param url: URL where the Kismet server is running
        """
        self.api_key = api_key
        if url[-1] != '/':
            self.url = f"{url}/"
        else:
            self.url = url
        self.cookies = {'KISMET': self.api_key}

    def __str__(self):
        return f"url={self.url}, api_key=XXX"


class KismetWorker(KismetBase):

    def check_session(self) -> None:
        """
        Confirm if the session is valid for a given API key
        :return: None, throws an exception if the session is invalid
        """
        endpoint = f"{self.url}session/check_session"
        r = requests.get(endpoint, cookies=self.cookies)
        r.raise_for_status()

    def check_system_status(self) -> Dict[str, Any]:
        """
        Overall status of the Kismet server
        :return: Nested dictionary describing different aspect of the Kismet system
        """
        endpoint = f"{self.url}system/status.json"
        r = requests.get(endpoint, cookies=self.cookies)
        r.raise_for_status()
        return json.loads(r.text)

    def get_all_alerts(self) -> Dict[str, Any]:
        """
        You can get a description how the alert system is set up as shown here: /alerts/definitions.prettyjson
        This method returns the last N alerts registered by the system. Severity and meaning of the alert is explained
        here: https://www.kismetwireless.net/docs/devel/webui_rest/alerts/
        :return:
        """
        endpoint = f"{self.url}alerts/all_alerts.json"
        r = requests.get(endpoint, cookies=self.cookies)
        r.raise_for_status()
        return json.loads(r.text)

    def get_alert_by_hash(self, identifier: str) -> Dict[str, Any]:
        """
        Get details of a single alert by its identifier (hash)
        :return:
        """
        parsed = int(identifier)
        if parsed < 0:
            raise ValueError(f"Invalid ID provided: {identifier}")
        endpoint = f"{self.url}alerts/by-id/{identifier}/alert.json"
        r = requests.get(endpoint, cookies=self.cookies)
        r.raise_for_status()
        return json.loads(r.text)

    def get_alert_definitions(self) -> Dict[Union[str, int], Any]:
        """
        Get the defined alert types
        :return:
        """
        endpoint = f"{self.url}alerts/definitions.json"
        r = requests.get(endpoint, cookies=self.cookies)
        r.raise_for_status()
        return json.loads(r.text)


class KismetAdmin(KismetBase):

    def raise_alert(
            self,
            *,
            name: str,
            message: str
    ) -> None:
        """
        Send an alert to Kismet
        :param name: A well-defined name or id for the alert. MUST exist
        :param message: Message to send
        :return: None. Will raise an error if the alert could not be sent
        """
        endpoint = f"{self.url}/alerts/raise_alerts.cmd"

        r = requests.post(endpoint, json=None, cookies=self.cookies)
        r.raise_for_status()


class KismetResultsParser:
    SEVERITY = {
        0: {
            'name': 'INFO',
            'description': 'Informational alerts, such as datasource  errors, Kismet state changes, etc'
        },
        5: {
            'name': 'LOW',
            'description': 'Low - risk events such as probe fingerprints'
        },
        10: {
            'name': 'MEDIUM',
            'description': 'Medium - risk events such as denial of service attempts'
        },
        15: {
            'name': 'HIGH',
            'description': 'High - risk events such as fingerprinted watched devices, denial of service attacks, '
                           'and similar '
        },
        20: {
            'name': 'CRITICAL',
            'description': 'Critical errors such as fingerprinted known exploits'
        }
    }

    TYPES = {
        'DENIAL': 'Possible denial of service attack',
        'EXPLOIT': 'Known fingerprinted exploit attempt against a vulnerability',
        'OTHER': 'General category for alerts which don’t fit in any existing bucket',
        'PROBE': 'Probe by known tools',
        'SPOOF': 'Attempt to spoof an existing device',
        'SYSTEM': 'System events, such as log changes, datasource errors, etc.'
    }

    @staticmethod
    def parse_alert_definitions(
            *,
            alert_definitions: List[Dict[str, str]],
            keys_of_interest: Set[str] = None
    ) -> List[Dict[str, str]]:
        """
        Remove unwanted keys from full alert definition dump, to make it easier to read onscreen
        :param alert_definitions: Original Kismet alert definitions
        :param keys_of_interest: Kismet keys of interest
        :return: List of dictionaries with trimmed keys, description, severity and header for easy reading
        """
        if keys_of_interest is None:
            keys_of_interest = {
                'kismet.alert.definition.class',
                'kismet.alert.definition.description',
                'kismet.alert.definition.severity',
                'kismet.alert.definition.header'
            }
        parsed_alerts: List[Dict[str, str]] = []
        for definition in alert_definitions:
            new_definition = {}
            for def_key in definition:
                if def_key in keys_of_interest:
                    new_key = def_key.split('.')[-1]
                    new_definition[new_key] = definition[def_key]
            parsed_alerts.append(new_definition)
        return parsed_alerts

    @staticmethod
    def process_alerts(
            *,
            alerts: List[Dict[str, Union[str, int]]],

    ) -> Any:
        """
        Removed unwanted fields from alert details, also return extra data for severity and types of alerts
        :param alerts:
        :return:
        """
        processed_alerts = []
        found_types = {}
        found_severities = {}
        for alert in alerts:
            severity = alert['kismet.alert.severity']
            severity_name = KismetResultsParser.SEVERITY[severity]['name']
            severity_desc = KismetResultsParser.SEVERITY[severity]['description']
            found_severities[severity_name] = severity_desc
            text = alert['kismet.alert.text']
            aclass = alert['kismet.alert.class']
            found_types[aclass] = KismetResultsParser.TYPES[aclass]
            processed_alert = {
                'text': text,
                'class': aclass,
                'severity': severity_name,
                'hash': alert['kismet.alert.hash'],
                'dest_mac': alert['kismet.alert.dest_mac'],
                'source_mac': alert['kismet.alert.source_mac'],
                'timestamp': alert['kismet.alert.timestamp']
            }
            processed_alerts.append(processed_alert)
        return processed_alerts, found_severities, found_types

    @staticmethod
    def pretty_timestamp(timestamp: float) -> datetime:
        """
        Convert a Kismet timestamp (TIMESTAMP.UTIMESTAMP) into a pretty timestamp string
        :param timestamp:
        :return:
        """
        return datetime.fromtimestamp(timestamp)
