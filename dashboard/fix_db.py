import logging
import sys
import os

# Add parent directory to path to import dashboard modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dashboard.db import get_db_connection, get_cursor
except ImportError:
    print("Error: Could not import dashboard.db. Ensure you are running from the project root or dashboard directory.")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("fix_db")

def fix_correlations_table(db_name):
    """Adds missing columns to the correlations table in the specified database."""
    log.info(f"Checking schema for database: {db_name}")
    
    target_columns = {
        "kill_chain_stage": "VARCHAR(64)",
        "from_stage": "VARCHAR(64)",
        "to_stage": "VARCHAR(64)",
        "id_burst": "VARCHAR(64)"
    }
    
    try:
        with get_db_connection(db_name) as conn:
            with get_cursor(conn) as cur:
                # 1. Get existing columns
                cur.execute(f"""
                    SELECT COLUMN_NAME 
                    FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = 'correlations'
                """)
                existing_columns = {row['COLUMN_NAME'] for row in cur.fetchall()}
                
                # 2. Add missing columns
                for col, col_type in target_columns.items():
                    if col not in existing_columns:
                        log.info(f"Adding column '{col}' to '{db_name}.correlations'...")
                        cur.execute(f"ALTER TABLE correlations ADD COLUMN {col} {col_type}")
                    else:
                        log.info(f"Column '{col}' already exists in '{db_name}.correlations'.")
                
                conn.commit()
                log.info(f"Successfully updated schema for '{db_name}'.")
                
    except Exception as e:
        log.error(f"Failed to fix database '{db_name}': {e}")

if __name__ == "__main__":
    log.info("Starting production-grade schema migration...")
    
    # Update both live and cases databases
    fix_correlations_table("live")
    fix_correlations_table("cases")
    
    log.info("Migration complete.")
