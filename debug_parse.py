import win32evtlog
import xml.etree.ElementTree as ET
from dashboard.event_parser import parse_event

CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection

try:
    print("Opening Sysmon...")
    query_handle = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
    events = win32evtlog.EvtNext(query_handle, 1, Timeout=1000)
    
    for e in events:
        xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
        print("--- RAW XML ---")
        print(xml_str[:500] + "...\n")
        
        xml_root = ET.fromstring(xml_str)
        print("--- ROOT TAG ---")
        print(xml_root.tag)
        
        print("--- PARSER RESULT ---")
        parsed = parse_event(xml_root)
        print(parsed)
        
except Exception as e:
    import traceback
    traceback.print_exc()
