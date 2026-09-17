from typing import TypedDict, Literal  # TypeDict describes what keys and value types a dictionary should have. It is used for type hinting in Python.

class ParsedEvent (TypedDict):
    event_id: int
    timestamp: str
    computer: str
    log_name: str
    provider: str   #   tells you which Windows provider generated the event

    record_id: int      #   is the unique number windows assigns to each event in the log
    level: int          #   is the numeric windows event level
    message: str        #   stores ful human readable text of the event

    event_data: dict[str,str | None]      #   is a dictionary of the event data fields and their values. Every value is a string or None. 
    username: str | None
    source_ip: str | None
    source_port: str | None
    logon_type: str | None
    process_name: str | None
    command_line: str | None
    workstation : str | None
    status: str | None
    sub_status: str | None


class DetectionFinding (TypedDict, total=False):       #    
    detection: str
    threshold: int 
    username: str 
    source_ip: str 
    failed_attempts: int 
    event_id: int 
    event_ids: list[int]
    first_failure: str
    last_failure: str
    successful_logon: str

#   what the AI return after analyzing the events and findings
class AIAnalysis(TypedDict, total=False):   
    summary: str
    severity: Literal["low", "medium", "high", "critical"]
    reasoning: str
    recommended_actions: list[str]
    confidence: float
    mitre_techniques: list[str]
    evidence: list[str]


#   The data that will be sent to AI for analysis, ai_analyzer.py
class AIAnalysisRequest(TypedDict):
    findings: list[DetectionFinding]
