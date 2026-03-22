import win32evtlog
import xml.etree.ElementTree as ET
import queue

event_queue = queue.Queue()

CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

try:
    print("Opening Sysmon...")
    query_handle = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
    win32evtlog.EvtSeek(query_handle, 0, win32evtlog.EvtSeekRelativeToLast)
    
    print("Listening for events... (run something!)")
    while True:
        events = win32evtlog.EvtNext(query_handle, 10, Timeout=2000)
        if events:
            for e in events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid_node = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                event_id = eid_node.text if eid_node is not None else None
                print(f"Captured Live Event ID: {event_id}")
                
except Exception as e:
    import traceback
    traceback.print_exc()
