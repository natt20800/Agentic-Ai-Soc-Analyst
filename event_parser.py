# Event parser turns messy Windows Event Data into clean Python dictionaries for detection logic and AI can reliably use
# It turns raw event data from Event Collector into clean, consistent structure

import xml.etree.ElementTree as ET
from datetime import datetime

#   Parses one Event
def parse_one_event(event):
    parsed_event = {
        "event_id": event.get("Id"),
        "timestamp": normalize_timestamp(event.get("TimeCreated")),
        "computer": event.get("MachineName"),
        "log_name": event.get("LogName"),
        "provider": event.get("ProviderName"),
        "record_id": event.get("RecordId"),
        "level": event.get("Level"),
        "message": event.get("Message")
     }

    xml_string = event.get("Xml")
    event_data = {}

    if xml_string:

        try:
            root = ET.fromstring(xml_string)    #   Parse XML string into XML tree structure

            for data in root.iter():            #   Goes through every Xml element under root
                if data.tag.endswith("Data"):
                    field_name = data.get("Name")
                    field_value = data.text     #   Gets the text inside Xml element

                    if field_name:
                        event_data[field_name] = field_value
        except ET.ParseError:
            pass

    parsed_event["event_data"] = event_data     #   Keep all event-specific XML data

    #   Normalize important security fields
    parsed_event["username"] = event_data.get("TargetUserName")
    parsed_event["source_ip"] = event_data.get("IpAddress")
    parsed_event["source_port"] = event_data.get("IpPort")
    parsed_event["logon_type"] = event_data.get("LogonType")
    parsed_event["process_name"] = event_data.get("ProcessName")
    parsed_event["command_line"] = event_data.get("CommandLine")
    parsed_event["workstation"] = event_data.get("WorkstationName")
    parsed_event["status"] = event_data.get("Status")
    parsed_event["sub_status"] = event_data.get("SubStatus")

    return parsed_event


#   Parses Multiple Events
def parse_multiple_events(events):

    parsed_events = []

    for event in events:
        parsed_event = parse_one_event(event)
        parsed_events.append(parsed_event)

    return parsed_events

#   Converts TimeCreated into a readable form
def normalize_timestamp(timestamp):

    if not timestamp:
        return None

    try:
        timestamp = timestamp.replace("/Date(", "").replace("/","").replace(")","")
        timestamp = int(timestamp)
        timestamp = timestamp / 1000

        readable_timestamp = datetime.fromtimestamp(timestamp)
        readable_timestamp = readable_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return readable_timestamp
    except (ValueError, TypeError):
        return None