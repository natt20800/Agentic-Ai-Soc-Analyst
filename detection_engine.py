from datetime import datetime, timedelta


# Filters events by Event ID
def filter_events_by_id(events, event_id):
    filtered_events = []

    for event in events:
        if event.get("event_id") == event_id:
            filtered_events.append(event)

    return filtered_events


# Counts how many specific Event IDs are in the list of events
def count_event_id(events, event_id):
    count = 0

    for event in events:
        if event.get("event_id") == event_id:
            count += 1

    return count


# Groups all usernames by Event ID
def group_username_by_event_id(events, event_id):
    users = {}

    for event in events:
        if event.get("event_id") == event_id:
            username = event.get("username")

            if username is not None:
                if username in users:
                    users[username] += 1
                else:
                    users[username] = 1

    return users


# Groups all source IPs by Event ID
def group_source_ip_by_event_id(events, event_id):
    source_ips = {}

    for event in events:
        if event.get("event_id") == event_id:
            source_ip = event.get("source_ip")

            if source_ip not in (None, "", "-"):
                if source_ip in source_ips:
                    source_ips[source_ip] += 1
                else:
                    source_ips[source_ip] = 1

    return source_ips


# Detects repeated failed logon attempts by username
def detect_repeated_failed_logons(events, threshold=5):
    findings = []

    # 4625 = Failed logon
    grouped_events = group_username_by_event_id(events, 4625)

    for username, count in grouped_events.items():

        if count >= threshold:
            findings.append({
                "detection": "repeated_failed_logons",
                "username": username,
                "failed_attempts": count,
                "threshold": threshold,
                "event_id": 4625
            })

    return findings


# Detects repeated failed logon attempts by source IP
def detect_repeated_failed_logons_by_source_ip(events, threshold=5):
    findings = []

    # 4625 = Failed logon
    grouped_events = group_source_ip_by_event_id(events, 4625)

    for source_ip, count in grouped_events.items():

        if count >= threshold:
            findings.append({
                "detection": "repeated_failed_logons_from_source_ip",
                "source_ip": source_ip,
                "failed_attempts": count,
                "threshold": threshold,
                "event_id": 4625
            })

    return findings


# Detects repeated failed logons followed by a successful
# logon for the same username
def detect_failed_logon_followed_by_success(events, threshold=5, window_minutes = 10):
    findings = []

    failed_logons = {}
    successful_logons = {}

    # Separate failed and successful logons by username
    for event in events:
        event_id = event.get("event_id")
        username = event.get("username")
        timestamp = event.get("timestamp")

        # Cannot correlate the event without these fields
        if username is None or timestamp is None:
            continue

        # 4625 = Failed logon
        if event_id == 4625:

            if username not in failed_logons:
                failed_logons[username] = []

            failed_logons[username].append(timestamp)

        # 4624 = Successful logon
        elif event_id == 4624:

            if username not in successful_logons:
                successful_logons[username] = []

            successful_logons[username].append(timestamp)

    # Look through users who had failed logons
    for username, failure_times in failed_logons.items():

        # Skip the user if they never had a successful logon
        if username not in successful_logons:
            continue

        # Look at each successful logon for the same username in chronological order
        for success_timestamp in sorted(successful_logons[username]):

            success_time = datetime.strptime(
                success_timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

            window_start = success_time - timedelta(minutes=window_minutes)

            failures_before_success = []

            # Determine which failed logons happened before this success
            for failure_timestamp in failure_times:

                failure_time = datetime.strptime(
                    failure_timestamp,
                    "%Y-%m-%d %H:%M:%S"
                )

                if window_start <= failure_time < success_time:
                    failures_before_success.append(failure_time)

            # Check if the number of failures meets the threshold
            if len(failures_before_success) >= threshold:

                # Put failures in chronological order
                failures_before_success.sort()

                findings.append({
                    "detection": "failed_logons_followed_by_success",
                    "username": username,
                    "failed_attempts": len(failures_before_success),
                    "threshold": threshold,

                    "first_failure":
                        failures_before_success[0].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "last_failure":
                        failures_before_success[-1].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "successful_logon":
                        success_time.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "event_ids": [4625, 4624]
                })

                # Prevent multiple findings for the same username
                break

    return findings


# Runs all detection rules against the parsed events
def run_detections(events, threshold=5, window_minutes=10):
    findings = []

    # Run username-based failed logon detection
    findings.extend(
        detect_repeated_failed_logons(
            events,
            threshold,
        )
    )

    # Run source-IP-based failed logon detection
    findings.extend(
        detect_repeated_failed_logons_by_source_ip(
            events,
            threshold
        )
    )

    # Run failed-logon -> successful-logon correlation
    findings.extend(
        detect_failed_logon_followed_by_success(
            events,
            threshold,
            window_minutes
        )
    )

    return findings


if __name__ == "__main__":

    test_events = [
        {
            "event_id": 4625,
            "username": "bob",
            "source_ip": "-",
            "timestamp": "2026-09-11 10:01:00"
        },
        {
            "event_id": 4625,
            "username": "bob",
            "source_ip": "-",
            "timestamp": "2026-09-11 10:02:00"
        },
        {
            "event_id": 4625,
            "username": "bob",
            "source_ip": "-",
            "timestamp": "2026-09-11 10:03:00"
        },
        {
            "event_id": 4625,
            "username": "bob",
            "source_ip": "-",
            "timestamp": "2026-09-11 10:04:00"
        },
        {
            "event_id": 4625,
            "username": "bob",
            "source_ip": "-",
            "timestamp": "2026-09-11 10:05:00"
        }
    ]

    result = detect_repeated_failed_logons_by_source_ip(
        test_events,
        threshold=5
    )

    print(result)

    
