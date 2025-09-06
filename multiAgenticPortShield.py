import multiprocessing
import psutil
import time

def port_monitor(port_queue):
    prev_ports = set()
    while True:
        current_ports = set(conn.laddr.port for conn in psutil.net_connections() if conn.status == 'LISTEN')
        new_ports = current_ports - prev_ports
        closed_ports = prev_ports - current_ports
        if new_ports or closed_ports:
            port_queue.put({'new': list(new_ports), 'closed': list(closed_ports)})
        prev_ports = current_ports
        time.sleep(2)

def detection_agent(port_queue, action_queue):
    port_activity = {}
    while True:
        event = port_queue.get()
        for port in event['new']:
            port_activity[port] = port_activity.get(port, 0) + 1
            if port_activity[port] > 3:
                action_queue.put(('block', port))
        for port in event['closed']:
            action_queue.put(('log', f'Port {port} closed'))

def response_agent(action_queue):
    while True:
        action, data = action_queue.get()
        if action == 'block':
            print(f'Blocking port: {data} (simulated)')
        elif action == 'log':
            print(f'Log: {data}')

if __name__ == '__main__':
    multiprocessing.set_start_method('fork')  # For macOS compatibility
    port_queue = multiprocessing.Queue()
    action_queue = multiprocessing.Queue()
    monitor = multiprocessing.Process(target=port_monitor, args=(port_queue,))
    detector = multiprocessing.Process(target=detection_agent, args=(port_queue, action_queue))
    responder = multiprocessing.Process(target=response_agent, args=(action_queue,))

    monitor.start()
    detector.start()
    responder.start()
