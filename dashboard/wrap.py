import re
import sys

filepath = r"l:/DOWNLOADS/sentineltrace-main/sentineltrace-main/dashboard/analysis_engine.py"

with open(filepath, "r", encoding="utf-8") as f:
    lines = f.readlines()

start_idx = -1
for i, line in enumerate(lines):
    if line.startswith("def run_full_analysis(run_id: str)"):
        start_idx = i
        break

if start_idx == -1:
    print("Could not find run_full_analysis")
    sys.exit(1)

# we need to find `conn = get_db_connection()` which is around line 3068
conn_idx = -1
end_idx = -1
for i in range(start_idx, len(lines)):
    if "conn = get_db_connection()" in lines[i] and not lines[i].strip().startswith("#"):
        conn_idx = i
        break

if conn_idx == -1:
    print("Could not find conn = get_db_connection()")
    sys.exit(1)

# Now find the last line of the function (return context)
for i in range(conn_idx, len(lines)):
    if lines[i].startswith("    return context"):
        end_idx = i
        break

if end_idx == -1:
    print("Could not find return context")
    sys.exit(1)

# Instead of indenting everything, how about we just do:
# lines[conn_idx] = "    with DB_WRITE_LOCK:\n        conn = get_db_connection()\n"
# and then indent all lines between conn_idx+1 and end_idx-1 inclusively, with 4 spaces?
# But wait, wait. The user snippet doesn't wrap EVERYTHING. Actually, maybe I can just do:
#     with DB_WRITE_LOCK:
#         conn = get_db_connection()
# but wait! We can just indent everything.

lines[conn_idx] = "    with DB_WRITE_LOCK:\n        conn = get_db_connection()\n"
for i in range(conn_idx + 1, end_idx):
    # Only indent lines that are not exactly empty
    if lines[i].strip() == "":
        continue
    # Ensure we don't double indent if already indented somehow
    lines[i] = "    " + lines[i]

with open(filepath, "w", encoding="utf-8") as f:
    f.writelines(lines)

print("Successfully wrapped run_full_analysis in DB_WRITE_LOCK")
