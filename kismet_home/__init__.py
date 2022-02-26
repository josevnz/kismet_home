import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.pretty import install

install()
logging.basicConfig(
    level="NOTSET",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

CONSOLE = Console()
