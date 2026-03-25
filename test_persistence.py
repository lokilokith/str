from dashboard.detection_engine import match_rules, find_detections
import pandas as pd

# 1. Test match_rules on a mock Sysmon Event ID 13 (Registry Set Value)
mock_event = {
    "event_id": "13",  # Note it's a string from parser
    "image": "C:\\Windows\\System32\\cmd.exe",
    "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MyMalware",
    "severity": "high",
}

print("Testing match_rules single event...")
alerts = match_rules(mock_event)
if not alerts:
    print("NO ALERTS MATCHED!")
for a in alerts:
    print(f"Matched rule: {a.get('rule_name')} (stage: {a.get('kill_chain_stage')})")


# 2. Test find_detections
print("\nTesting find_detections dataframe...")
df = pd.DataFrame([mock_event])
det_df = find_detections(df)
print(det_df[["rule_name", "kill_chain_stage"]].to_string() if not det_df.empty else "No detections!")
