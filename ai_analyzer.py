import json
import string
from openai import OpenAI
from schemas import AIAnalysisRequest, AIAnalysis, ParsedEvent

#   OpenAI automatically reads OPENAI_API_KEY from powershell
openai_client = OpenAI()

def analyze_findings(request: AIAnalysisRequest) -> AIAnalysis:

    #   Get detections findings from the request
    findings = request.get("findings", [])

    #   If there are no findings, return a default analysis indicating no security issues were detected
    if not findings:
        return {
            "summary": "No security findings were detected.",
            "severity": "low",
            "reasoning": "The detection engine did not return any findings.",
            "recommended_actions": [],
            "confidence": 100.0,
            "mitre_techniques": [],
            "evidence": []
        }

    #   Convert the findings to a JSON text
    findings_json = json.dumps(findings, indent=4)

    #   Create a prompt for the AI model to analyze the findings
    prompt = f"""
        You are a cybersecurity SOC analyst.

        Analyze only the security findings provided below. Do not invent evidence that
        is not contained in the findings.

        Your job is to:
        - Summarize the detected activity.
        - Assign a severity of low, medium, high, or critical.
        - Explain why the activity may be important or suspicious.
        - Recommend investigation steps for a human security analyst.
        - Give a confidence percentage from 0 to 100.
        - Identify relevant MITRE ATT&CK techniques when supported by the evidence.
        - List the specific evidence that supports your assessment.

        Do not perform remediation actions.
        Do not claim that malicious activity definitely occurred unless the evidence
        supports that conclusion.

        Return the analysis as JSON using exactly these fields:

        {{
            "summary": "string",
            "severity": "low | medium | high | critical",
            "reasoning": "string",
            "recommended_actions": ["string"],
            "confidence": 0,
            "mitre_techniques": ["string"],
            "evidence": ["string"]
        }}

        Security findings:

        {findings_json}

        """

    #  Define the expected schema for the AI response
    analysis_schema = {
        "type": "object",

        "properties": {
            "summary": {
                "type": "string"
            },
        
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"]   #   AI is only allowed to return one of those four values for severity
            },

            "reasoning": {
                "type": "string"
            },

            "recommended_actions": {
                "type": "array",
                "items": {
                    "type": "string"
                }
            },

            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 100
            },

            "mitre_techniques": {
                "type": "array",
                "items": {
                    "type": "string"
                }
            },

            "evidence": {
                "type": "array",
                "items": {
                    "type": "string"
                }
            },
        },

        "required": [
            "summary",
            "severity",
            "reasoning",
            "recommended_actions",
            "confidence",
            "mitre_techniques",
            "evidence"
        ],
        "additionalProperties": False

    }
    

    #   Send the prompt to the AI model and get the response
    response = openai_client.responses.create(
    model = "gpt-5.6-luna",
    input=prompt,
    text={
        "format": {
            "type": "json_schema",
            "name": "soc_analysis",
            "schema": analysis_schema,
            "strict": True
        }
    }
    )

    #   Extract the text output from the AI response
    answer = response.output_text

    #   Convert AI resonse JSON text to a Python dictionary
    analysis = json.loads(answer)

    return analysis


if __name__ == "__main__":
    test_request = {
        "findings": [
            {
                "detection": "failed_logons_followed_by_success",
                "username": "bob",
                "failed_attempts": 5,
                "threshold": 5,
                "first_failure": "2026-08-29 10:01:00",
                "last_failure": "2026-08-29 10:05:00",
                "successful_logon": "2026-08-29 10:07:00",
                "event_ids": [4625, 4624]
            }
        ]
    }

    result = analyze_findings(test_request)

    print("\nAI Analysis:\n")

    print("Summary:", result["summary"])
    print("Severity:", result["severity"])
    print("Reasoning:", result["reasoning"])
    print("Recommended Actions:", result["recommended_actions"])
    print("Confidence:", f'{result["confidence"]}%')
    print("MITRE Techniques:", result["mitre_techniques"])
    print("Evidence:", result["evidence"])
