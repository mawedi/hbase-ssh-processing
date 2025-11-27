import re
import happybase
from datetime import datetime

# ---------------------------
# HBase Connection
# ---------------------------
connection = happybase.Connection('127.0.0.1', 16011)   # change if needed
table = connection.table('ssh_logs')

# ---------------------------
# Log Parsing Regex
# ---------------------------
LOG_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$'
)

IP_PATTERN = re.compile(r'from\s+([\d\.]+)')
USER_PATTERN = re.compile(r'(invalid user|for user|for)\s+(\S+)')
PORT_PATTERN = re.compile(r'port\s+(\d+)')


def parse_log_line(line: str):
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    month, day, time, host, message = match.group(
        "month", "day", "time", "host", "message"
    )

    # Construct timestamp (year optional)
    timestamp_str = f"2025 {month} {day} {time}"
    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

    # Extract details
    ip = None
    user = None
    port = None

    ip_match = IP_PATTERN.search(message)
    if ip_match:
        ip = ip_match.group(1)

    user_match = USER_PATTERN.search(message)
    if user_match:
        user = user_match.group(2)

    port_match = PORT_PATTERN.search(message)
    if port_match:
        port = port_match.group(1)

    return {
        "timestamp": timestamp.isoformat(),
        "host": host,
        "message": message,
        "ip": ip,
        "user": user,
        "port": port
    }


def save_to_hbase(parsed):
    row_key = f"{parsed['timestamp']}-{parsed.get('ip', 'unknown')}"
    table.put(row_key, {
        b'info:hostname': parsed['host'].encode(),
        b'info:event': parsed['message'].encode(),
        b'info:user': (parsed['user'] or '').encode(),
        b'info:ip': (parsed['ip'] or '').encode(),
        b'info:port': (parsed['port'] or '').encode(),
        b'info:raw': parsed['message'].encode(),
    })


def process_log_file(path):
    with open(path, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                save_to_hbase(parsed)
                print(f"Saved: {parsed}")


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    process_log_file("data/ssh.log")   # change to your file
