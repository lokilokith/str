"""
test_resilience.py — SOC-Grade Resilience Validation
Tests:
  1. Multi-event attack chain (powershell -> reg add -> schtasks)
  2. Failure scenarios (missing reg_key, malformed event_id, empty cmd)
  3. Noise filtering (benign registry writes)
  4. Advanced persistence (IFEO, AppInit, Services)
"""

from dashboard.detection_engine import match_rules

_PASS = 0
_FAIL = 0

def check(label: str, condition: bool):
    global _PASS, _FAIL
    status = "PASS" if condition else "FAIL"
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
    print(f"  [{status}] {label}")


print("\n=== 1. MULTI-EVENT CHAIN: powershell -> reg Run key -> schtasks ===")
chain = [
    {"event_id": "1", "image": "powershell.exe", "command_line": "powershell -enc ABCD", "severity": "high"},
    {"event_id": "13", "image": "reg.exe", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil", "severity": "high"},
    {"event_id": "1", "image": "schtasks.exe", "command_line": "schtasks /create /tn ...", "severity": "medium"},
]
chain_persistence = False
for ev in chain:
    hits = match_rules(ev)
    for h in hits:
        if h.get("kill_chain_stage") == "Persistence":
            chain_persistence = True
check("Chain contains Persistence detection", chain_persistence)
check("Powershell matches execution rule", any(h for h in match_rules(chain[0])))
check("schtasks matches persistence rule", any(h.get("kill_chain_stage") == "Persistence" for h in match_rules(chain[2])))


print("\n=== 2. FAILURE SCENARIOS (edge cases that should not crash) ===")
edge_cases = [
    {"event_id": None,  "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"},
    {"event_id": "NaN", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"},
    {"event_id": "",    "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"},
    {"event_id": ["13"], "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"},
    {"event_id": "13",  "reg_key": None},
    {"event_id": "13",  "command_line": None, "reg_key": "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\evilsvc"},
]
for i, ev in enumerate(edge_cases):
    try:
        hits = match_rules(ev)
        check(f"Edge case {i+1} doesn't crash", True)
    except Exception as e:
        check(f"Edge case {i+1} doesn't crash", False)

# event_id as list should still detect
hits = match_rules(edge_cases[3])
check("event_id=['13'] still produces hits", any(h.get("kill_chain_stage") == "Persistence" for h in hits))


print("\n=== 3. NOISE FILTERING (benign writes must NOT trigger fallback) ===")
benign = [
    {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{ABC}\\InprocServer32"},
    {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\TypeLib\\{XYZ}"},
    {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Interface\\{123}"},
]
for i, ev in enumerate(benign):
    hits = match_rules(ev)
    persist_hits = [h for h in hits if h.get("kill_chain_stage") == "Persistence"]
    check(f"Benign key {i+1} suppressed (no false positive)", len(persist_hits) == 0)


print("\n=== 4. ADVANCED PERSISTENCE PATHS ===")
advanced = [
    ("IFEO", {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe", "severity": "high"}),
    ("AppInit_DLLs", {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", "severity": "high"}),
    ("Services", {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\evilsvc\\ImagePath", "severity": "medium"}),
    ("Winlogon", {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", "severity": "high"}),
    ("Boot execute", {"event_id": "13", "reg_key": "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", "severity": "high"}),
]
for name, ev in advanced:
    hits = match_rules(ev)
    persist_hits = [h for h in hits if h.get("kill_chain_stage") == "Persistence"]
    check(f"{name} persistence detected (confidence={max((h.get('confidence_score',0) for h in persist_hits), default='N/A')})", len(persist_hits) > 0)


print(f"\n=== RESULTS: {_PASS} PASSED / {_FAIL} FAILED ===")
if _FAIL == 0:
    print("ALL TESTS PASSED — SYSTEM IS SOC-GRADE RESILIENT")
else:
    print(f"WARNING: {_FAIL} tests failed. Review output above.")
