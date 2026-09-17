#   Event Collector retrieves the data from the Windows Server VM and bridges to Python SOC System

from winrm_client import run_powershell
import json

def collect_events (session, log_name = "security", event_ids = (4624,4625,), minutes_back = 30, max_events = 100):
    if not (log_name):
        raise ValueError("Log_name can not be empty")
    if minutes_back <= 0 or minutes_back > 60:  
        raise ValueError("minutes_back must be greater than 0 and less than 60")
    if max_events <= 0 or max_events > 100:
        raise ValueError("max_events must be greater than 0 and less than or equal to 100")

    filter_eventlog_parts = [ 
        f"LogName = '{log_name}'",
        f"StartTime = (Get-Date).AddMinutes(-{minutes_back})"
    ]

    #   Checks if Event ID has a Value
    if event_ids is not None:
        if isinstance(event_ids, int):
            event_ids = [event_ids]     #   if event_ids is just one integer, this turns into a list

        ids = ",".join(str(event_id) for event_id in event_ids)    #   Convert every Event ID into Text and Joins them together 

        filter_eventlog_parts.append(
                f"Id = @({ids})"
            )


    output_winevent = ["Id", 
                       "TimeCreated", 
                       "LogName",
                       "ProviderName",
                       "MachineName",
                       "RecordId",
                       "Level",
                       "LevelDisplayName",
                       "Message",
                       "UserId",
                       ]

    selected_properties = ", ".join(output_winevent)    #  contains only properties needed

    #   Includes Log Name, Start Time, Event ID into an executable script for Get-WinEvent for Powershell
    #   Includes selected_properties and asks Powershell to convert the properties into JSON Formatted Text
    filter_text = "\n".join(filter_eventlog_parts)
    get_winevent_pscommand = f"""
try {{
    $events = Get-WinEvent -FilterHashtable @{{
        {filter_text}
    }} -MaxEvents {max_events} -ErrorAction Stop

    $events |
        Select-Object {selected_properties}, @{{Name='Xml'; Expression={{$_.ToXml()}}}} |
        ConvertTo-Json
}}
catch {{
    if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") {{
        Write-Output "[]"
    }}
    else {{
        throw
    }}
}}
"""
    
    run_get_winevent = run_powershell(session, get_winevent_pscommand)

    if not run_get_winevent:
        return[]

    events = json.loads(run_get_winevent)

    if isinstance(events, dict):
        events = [events]

    return events







    
