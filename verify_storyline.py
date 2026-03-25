
import pandas as pd
from dashboard.analysis_engine import build_attack_story

def test_storyline():
    events = [
        {"event_id": 1, "image": r"C:\Windows\System32\powershell.exe", "parent_image": r"C:\Windows\explorer.exe", "event_time": "2026-03-23T10:00:00Z"},
        {"event_id": 13, "image": r"C:\Windows\System32\powershell.exe", "reg_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware", "event_time": "2026-03-23T10:05:00Z"},
        {"event_id": 3, "image": r"C:\Windows\System32\powershell.exe", "destination_ip": "1.2.3.4", "destination_port": 4444, "event_time": "2026-03-23T10:10:00Z"}
    ]
    
    detections = [
        {"rule_id": "R1", "rule_name": "PowerShell Execution", "kill_chain_stage": "Execution", "mitre_id": "T1059.001", "confidence_score": 50, "match_reason": ["Powershell detected"]},
        {"rule_id": "FB-RUN", "rule_name": "Registry Run key persistence", "kill_chain_stage": "Persistence", "mitre_id": "T1547.001", "confidence_score": 75, "match_reason": ["Persistence key matched"]}
    ]
    
    story = build_attack_story(events, detections)
    
    print("STORY STEPS:")
    for i, step in enumerate(story["steps"]):
        print(f"{i+1}. {step}")
        
    print("\nSUMMARY:")
    print(story["summary"])
    
    print("\nKILL CHAIN:")
    print(story["kill_chain"])

if __name__ == "__main__":
    test_storyline()
