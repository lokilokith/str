from dashboard.db import get_engine
from sqlalchemy import text

for mode in ['cases', 'live']:
    engine = get_engine(mode)
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE events DROP PRIMARY KEY, ADD PRIMARY KEY (event_uid, run_id)"))
            print(f"Altered events table in {mode}")
    except Exception as e:
        print(e)
