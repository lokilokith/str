import win32evtlog
import time

CHANNEL_NAME = "Application"
flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

print("Testing dynamic EvtQuery with Bookmark polling on Application log...")
bookmark_handle = None

try:
    temp_q = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
    win32evtlog.EvtSeek(temp_q, 0, win32evtlog.EvtSeekRelativeToLast)
    evts = win32evtlog.EvtNext(temp_q, 1)
    if evts:
        bookmark_handle = win32evtlog.EvtCreateBookmark(None)
        win32evtlog.EvtUpdateBookmark(bookmark_handle, evts[0])
        print(f"Bookmarked the very last event in the log.")
    temp_q.Close()
except Exception as e:
    print(f"Initial setup failed: {e}")

# Now simulate the loop
for i in range(5):
    q = win32evtlog.EvtQuery(CHANNEL_NAME, flags, "*")
    if bookmark_handle:
        try:
            win32evtlog.EvtSeek(q, 1, win32evtlog.EvtSeekRelativeToBookmark, Bookmark=bookmark_handle)
        except Exception as e:
            print(f"Seek failed!: {e}")
            # If we fall through here, let's see what EvtNext returns!
            
    events = win32evtlog.EvtNext(q, 5, Timeout=100)
    if events:
        print(f"[{i}] Retrieved {len(events)} events anyway! This means we started from the BEGINNING if seek failed!")
    else:
        print(f"[{i}] Retrieved 0 events. Seek worked and blocked us at the end perfectly.")
    q.Close()
    time.sleep(1)
