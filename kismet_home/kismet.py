"""
Code related to interaction with Kismet REST-API server
"""


class KismetWorker:

    def __init__(self, *, api_key: str, url: str):
        self.api_key = api_key
        self.url = url

    def __str__(self):
        return f"url={self.url}, api_key=XXX"
