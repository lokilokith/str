import win32evtlog
import time
import xml.etree.ElementTree as ET

CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtSubscribeToFutureEvents

print("Subscribing to future events...")
try:
    sub_handle = win32evtlog.EvtSubscribe(
        CHANNEL_NAME,
        flags,
        None, # Bookmark
        None, # Query
        None, # Callback (None means Pull Mode)
        None  # Context
    )

    print("Listening... Run notepad or ping!")
    for _ in range(15):
        try:
            events = win32evtlog.EvtNext(sub_handle, 5, Timeout=1000)
            if events:
                for e in events:
                    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    print(f"Captured {len(events)} events just now!")
                    break
        except Exception as e:
            # 259 is timeout
            if hasattr(e, 'winerror') and e.winerror == 259:
                pass
            else:
                print(e)
        time.sleep(1)
        
except Exception as e:
    print(e)
