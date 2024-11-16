import threading
import queue
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from scapy.all import IP, TCP, UDP, ICMP, sr1

@dataclass
class ScanResult:
    port: int
    protocol: str
    state: str
    service: str

def is_valid_ipv4(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        parts = ip.split(".")
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return False
        return True
    return False

def format_output(port, protocol, state, service):
    if state == "open":
        port_str = f"{port}/{protocol}"
        return f"{port_str:<15} {state:<18} {service}"
    return None

def parse_services_file(file_path):
    ports_services = {}
    ports_list = []
    
    try:
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist")
            return ports_list, ports_services
              
        with open(file_path, 'r') as file:
            content = file.readlines()
            
            for line_num, line in enumerate(content, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                parts = line.split(',')
                
                if len(parts) != 3:
                    continue
                    
                port_str, protocol, service = parts
                port_str = port_str.strip()
                protocol = protocol.strip().upper()
                service = service.strip()
                
                if not port_str.isdigit():
                    continue
                    
                port = int(port_str)
                if '/' in protocol:
                    protocols = protocol.split('/')
                    for p in protocols:
                        p = p.strip()
                        ports_services[(port, p)] = service
                        ports_list.append((port, p))
                else:
                    ports_services[(port, protocol)] = service
                    ports_list.append((port, protocol))
                    
    except Exception as e:
        print(f"Error reading services file: {e}")
        return ports_list, ports_services
    
    return ports_list, ports_services

def scan_udp(target_ip, port, ports_services):
    try:
        responses = []
        for i in range(2):
            packet = IP(dst=target_ip)/UDP(dport=port)
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                responses.append(response)
        
        service = ports_services.get((port, "UDP"), "unknown")
        
        if not responses:
            result = ScanResult(port, "udp", "open|filtered", service)
            return result
            
        for response in responses:
            if response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
                    result = ScanResult(port, "udp", "closed", service)
                    return result
                elif response.getlayer(ICMP).type == 3:
                    result = ScanResult(port, "udp", "filtered", service)
                    return result
            
        result = ScanResult(port, "udp", "open", service)
        return result
            
    except Exception as e:
        return None

def scan_port_combined(target_ip, port, ports_services) -> Optional[ScanResult]:
    try:
        syn_responses = []
        for _ in range(2):
            syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            syn_response = sr1(syn_packet, timeout=1, verbose=False)
            if syn_response:
                syn_responses.append(syn_response)
        
        ack_responses = []
        for _ in range(2):
            ack_packet = IP(dst=target_ip)/TCP(dport=port, flags="A")
            ack_response = sr1(ack_packet, timeout=1, verbose=False)
            if ack_response:
                ack_responses.append(ack_response)
        
        service = ports_services.get((port, "TCP"), "unknown")
        
        if syn_responses:
            for syn_response in syn_responses:
                if syn_response.haslayer(TCP):
                    if syn_response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                        return ScanResult(port, "tcp", "open", service)
                    elif syn_response.getlayer(TCP).flags == 0x14:  # RST
                        return ScanResult(port, "tcp", "closed", service)
        
        return ScanResult(port, "tcp", "filtered", service)
            
    except Exception as e:
        return None

def port_scan(target_ip, ports_services):
    print("\nScanning for open ports...")
    
    port_queue = queue.Queue()
    results_queue = queue.Queue()
    scan_results = []

    for port, protocol in ports_services.keys():
        port_queue.put((port, protocol))

    def worker():
        while not port_queue.empty():
            port, protocol = port_queue.get()
            if protocol == "TCP":
                result = scan_port_combined(target_ip, port, ports_services)
                if result and result.state == "open":
                    results_queue.put(result)
                    print(format_output(result.port, result.protocol, result.state, result.service))
            elif protocol == "UDP":
                result = scan_udp(target_ip, port, ports_services)
                if result and result.state == "open":
                    results_queue.put(result)
                    print(format_output(result.port, result.protocol, result.state, result.service))
            port_queue.task_done()

    num_threads = 10
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    while not results_queue.empty():
        scan_results.append(results_queue.get())

    return scan_results