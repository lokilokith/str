import win32evtlog
import time

CHANNEL_NAME = "Microsoft-Windows-Sysmon/Operational"
flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

print("Testing dynamic EvtQuery with Bookmark polling...")
bookmark_handle = None

# First query to get the bookmark at the end
q = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
win32evtlog.EvtSeek(q, 0, win32evtlog.EvtSeekRelativeToLast)
events = win32evtlog.EvtNext(q, 1)
if events:
    bookmark_handle = win32evtlog.EvtCreateBookmark(None)
    win32evtlog.EvtUpdateBookmark(bookmark_handle, events[0])
    print(f"Bookmarked the very last event in the log.")
q.Close()
    
# Now simulate the loop
for i in range(15):
    q = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
    if bookmark_handle:
        try:
            win32evtlog.EvtSeek(q, 1, win32evtlog.EvtSeekRelativeToBookmark, Bookmark=bookmark_handle)
        except Exception as e:
            if hasattr(e, 'winerror') and e.winerror == 15011: # bookmark not found or 87 (param invalid if at end)
                pass # Just wait
    
    # Read anything new
    parsed = 0
    while True:
        try:
            events = win32evtlog.EvtNext(q, 10, Timeout=100)
            if not events:
                break
            for e in events:
                win32evtlog.EvtUpdateBookmark(bookmark_handle, e)
                parsed += 1
        except Exception as e:
            break
            
    if parsed > 0:
        print(f"[{i}] Read {parsed} NEW events!")
    q.Close()
    time.sleep(1)
print("Done!")
