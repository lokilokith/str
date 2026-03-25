import logging
import os
import sys
from sqlalchemy import text
from dashboard.db import get_engine

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("migrate")

# (Table, Column, Definition)
MIGRATIONS = [
    # Detections: Scoring & Integrity
    ("detections", "id_burst", "VARCHAR(64) DEFAULT NULL AFTER run_id"),
    ("detections", "analysis_integrity", "TEXT DEFAULT NULL"),
    ("detections", "primary_reason", "TEXT DEFAULT NULL"),
    ("detections", "confidence_band", "VARCHAR(32) DEFAULT NULL"),
    ("detections", "trend_indicator", "VARCHAR(32) DEFAULT NULL"),
    
    # Behavior Baseline: Attribution & Confidence
    ("behavior_baseline", "id_burst", "VARCHAR(64) DEFAULT NULL"),
    ("behavior_baseline", "analyst_confidence", "FLOAT DEFAULT 1.0"),
    ("behavior_baseline", "last_seen_at", "DATETIME(6) DEFAULT NULL"),
    
    # Correlation Campaigns: Progress & Health
    ("correlation_campaigns", "attack_progress", "FLOAT DEFAULT 0.0"),
    ("correlation_campaigns", "system_health", "FLOAT DEFAULT 100.0"),
    
    # Correlations: Pivoting
    ("correlations", "id_burst", "VARCHAR(64) DEFAULT NULL AFTER run_id"),
]

def migrate():
    for mode in ["live", "cases"]:
        log.info(f"Checking schema for database: {mode}")
        engine = get_engine(mode)
        
        with engine.connect() as conn:
            for table, column, definition in MIGRATIONS:
                # Check if column exists
                query = text("""
                    SELECT COUNT(*) 
                    FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = :table 
                    AND COLUMN_NAME = :column
                """)
                res = conn.execute(query, {"table": table, "column": column}).scalar()
                
                if res == 0:
                    log.info(f"[{mode}] Adding column {column} to {table}...")
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))
                        conn.commit()
                        log.info(f"[{mode}] Successfully added {column} to {table}.")
                    except Exception as e:
                        log.error(f"[{mode}] Failed to add {column} to {table}: {e}")
                else:
                    log.debug(f"[{mode}] Column {column} already exists in {table}.")

    log.info("Migration complete.")

if __name__ == "__main__":
    migrate()
