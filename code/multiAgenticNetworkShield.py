import multiprocessing
from scapy.all import sniff, IP, TCP

def packet_sniffer(packet_queue):
    def callback(pkt):
        if pkt.haslayer(IP):
            packet_queue.put(pkt)
    sniff(prn=callback, store=0)

def detection_agent(packet_queue, action_queue):
    while True:
        pkt = packet_queue.get()
        if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            src = pkt[IP].src
            action_queue.put(("block", src))
        action_queue.put(("log", f"Packet from {pkt[IP].src}"))

def response_agent(action_queue):
    while True:
        action, data = action_queue.get()
        if action == "block":
            print(f"Blocking IP: {data} (simulate firewall rule)")
        elif action == "log":
            print(f"Log: {data}")

if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    packet_queue = multiprocessing.Queue()
    action_queue = multiprocessing.Queue()
    sniffer = multiprocessing.Process(target=packet_sniffer, args=(packet_queue,))
    detector = multiprocessing.Process(target=detection_agent, args=(packet_queue, action_queue))
    responder = multiprocessing.Process(target=response_agent, args=(action_queue,))

    sniffer.start()
    detector.start()
    responder.start()
