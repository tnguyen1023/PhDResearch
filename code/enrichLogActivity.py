def infer_activity(log):
    # Network log
    if 'protocol' in log and 'action' in log:
        action = log.get('action', 'UNKNOWN').upper()
        protocol = log.get('protocol', 'UNKNOWN').upper()
        if action == 'ALLOW':
            return f"{protocol} connection allowed"
        elif action == 'DENY':
            return f"{protocol} connection blocked"
        elif log.get('scan_detected', False):
            return "Port scan detected"
        return "Unknown network activity"
    # Host log
    elif 'host' in log and 'event' in log:
        event = log.get('event', '').lower()
        if event == 'login':
            return "Host login event"
        elif event == 'logout':
            return "Host logout event"
        elif event == 'malware_detected':
            return "Malware detected on host"
        return "Unknown host activity"
    # Port log
    elif 'port' in log:
        port = log.get('port')
        if log.get('open', False):
            return f"Port {port} opened"
        elif log.get('closed', False):
            return f"Port {port} closed"
        return f"Port {port} activity"
    else:
        return "Unknown activity"

def add_activities(logs):
    for log in logs:
        log['activity'] = infer_activity(log)
    return logs

# Example usage:
logs = [
    {"protocol": "TCP", "action": "ALLOW", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
    {"host": "server1", "event": "login", "user": "admin"},
    {"port": 22, "open": True, "host": "server2"},
    {"protocol": "UDP", "action": "DENY", "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"},
    {"host": "server3", "event": "malware_detected"},
    {"port": 80, "closed": True, "host": "server4"}
]

logs_with_activities = add_activities(logs)
for log in logs_with_activities:
    print(log)
