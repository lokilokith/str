# dashboard/progress.py
import threading

_state = {}
_lock = threading.Lock()

def set_run_progress(run_id: str, state: str, progress: int = 0, message: str = "", actual_run_id: str = None, error: str = None):
    with _lock:
        _state[run_id] = {
            "state": state,
            "progress": progress,
            "message": message,
            "run_id": actual_run_id,
            "error": error,
            "updated_at": __import__('time').time()
        }

def get_run_progress(run_id: str):
    with _lock:
        return _state.get(run_id, {"state": "unknown"})
