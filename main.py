from detection_engine import run_detections
from ai_analyzer import analyze_findings
from winrm_client import create_session
from event_collector import collect_events
from event_parser import parse_multiple_events

def main():

    session = create_session()

    raw_events = collect_events(
        session,
        log_name="Security",
        event_ids=[4625, 4624],
        minutes_back=30,
        max_events=100
        )

    print("Raw events collected:", len(raw_events))

    parsed_events = parse_multiple_events(raw_events)

    print("Parsed events:", len(parsed_events))

    findings = run_detections(
        parsed_events,
        threshold=5,
        window_minutes=10
        )

    for event in parsed_events:
        if event.get("event_id") == 4625 and event.get("source_ip") == "127.0.0.1":
            print({
                "timestamp": event.get("timestamp"),
                "username": event.get("username"),
                "source_ip": event.get("source_ip"),
                "logon_type": event.get("logon_type"),
                "workstation": event.get("workstation"),
                "status": event.get("status"),
                "sub_status": event.get("sub_status")
                })

    print("Findings detected:", len(findings))

    analysis_request = {
        "findings": findings
    }


    analysis = analyze_findings(analysis_request)

    print("AI Analysis:")
    print(analysis)



if __name__ == "__main__":
    main()  


