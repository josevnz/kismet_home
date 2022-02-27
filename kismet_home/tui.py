from typing import List, Dict, Any

from rich.table import Table

from kismet_home.kismet import KismetResultsParser


def create_alert_definition_table(
        *,
        alert_definitions: List[Dict[str, Any]],
        level_filter: str = 0
) -> Table:
    """
    Create a table showing the alert definitions
    :param alert_definitions: Alert definitions from Kismet
    :param level_filter: User can override the level of the alerts shown. But default is 0 (INFO)
    :return: A Table with the alert definitions
    """
    definition_table = Table(title="Alert definitions")
    definition_table.add_column("Severity", justify="right", style="cyan", no_wrap=True)
    definition_table.add_column("Description", style="magenta")
    definition_table.add_column("Header", justify="right", style="yellow")
    definition_table.add_column("Class", justify="right", style="green")
    filter_level = KismetResultsParser.get_level_for_security(level_filter)
    filtered_definitions = 0
    for definition in alert_definitions:
        int_severity: int = definition['severity']
        if int_severity < filter_level:
            continue
        severity = KismetResultsParser.SEVERITY[int_severity]['name']
        if 0 <= int_severity < 5:
            severity = f"[bold blue]{severity}[/ bold blue]"
        if 5 <= int_severity < 10:
            severity = f"[bold yellow]{severity}[/ bold yellow]"
        if 10 <= int_severity < 15:
            severity = f"[bold orange]{severity}[/ bold orange]"
        else:
            severity = f"[bold red]{severity}[/ bold red]"
        filtered_definitions += 1
        definition_table.add_row(
            severity,
            definition['description'],
            definition['header'],
            definition['class']
        )
    definition_table.caption = f"Total definitions: {filtered_definitions}"
    return definition_table


def create_alert_table(
        *,
        alerts: List[Dict[str, Any]],
        level_filter: str = 0
):
    alerts_table = Table(title="Alert definitions")
    alerts_table.add_column("Timestamp", no_wrap=True)
    alerts_table.add_column("Severity", justify="right", style="cyan", no_wrap=True)
    alerts_table.add_column("Text", style="magenta")
    alerts_table.add_column("Source MAC", justify="right", style="yellow", no_wrap=True)
    alerts_table.add_column("Destination MAC", justify="right", style="yellow", no_wrap=True)
    alerts_table.add_column("Class", justify="right", style="green", no_wrap=True)
    filter_level = KismetResultsParser.get_level_for_security(level_filter)
    filtered_definitions = 0
    for alert in alerts:
        int_severity: int = KismetResultsParser.get_level_for_security(alert['severity'])
        if int_severity < filter_level:
            continue
        severity = KismetResultsParser.SEVERITY[int_severity]['name']
        if 0 <= int_severity < 5:
            severity = f"[bold blue]{severity}[/ bold blue]"
        if 5 <= int_severity < 10:
            severity = f"[bold yellow]{severity}[/ bold yellow]"
        if 10 <= int_severity < 15:
            severity = f"[bold orange]{severity}[/ bold orange]"
        else:
            severity = f"[bold red]{severity}[/ bold red]"
        filtered_definitions += 1
        alerts_table.add_row(
            str(KismetResultsParser.pretty_timestamp(alert['timestamp'])),
            severity,
            alert['text'],
            alert['source_mac'],
            alert['dest_mac'],
            alert['class']
        )
    alerts_table.caption = f"Total alerts: {filtered_definitions}"
    return alerts_table
