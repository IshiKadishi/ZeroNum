import threading
import queue
import argparse
import os
import sys
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
    # Format: PORT            STATE              SERVICE
    port_str = f"{port}/{protocol}"
    return f"{port_str:<15} {state:<18} {service}"

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
        # Send multiple UDP probes
        responses = []
        for i in range(2):
            packet = IP(dst=target_ip)/UDP(dport=port)
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                responses.append(response)
        
        service = ports_services.get((port, "UDP"), "unknown")
        
        if not responses:
            print(format_output(port, "udp", "open|filtered", service))
            return
            
        for response in responses:
            if response.haslayer(ICMP):
                if response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
                    # Port unreachable - closed
                    print(format_output(port, "udp", "closed", service))
                    return
                elif response.getlayer(ICMP).type == 3:
                    # Other ICMP unreachable - filtered
                    print(format_output(port, "udp", "filtered", service))
                    return
            
        # If we got responses but no ICMP errors
        print(format_output(port, "udp", "open", service))
            
    except Exception as e:
        pass

def scan_tcp_port_combined(target_ip, port, ports_services) -> Optional[ScanResult]:
    try:
        # SYN Scan with retry
        syn_responses = []
        for _ in range(2):
            syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            syn_response = sr1(syn_packet, timeout=1, verbose=False)
            if syn_response:
                syn_responses.append(syn_response)
        
        # ACK Scan with retry
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
                        if any(ack_resp.haslayer(TCP) and ack_resp.getlayer(TCP).flags == 0x14 for ack_resp in ack_responses):
                            # Send RST to close
                            sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=False)
                            return ScanResult(port, "tcp", "open", service)
                    elif syn_response.getlayer(TCP).flags == 0x14:  # RST
                        if any(ack_resp.haslayer(TCP) and ack_resp.getlayer(TCP).flags == 0x14 for ack_resp in ack_responses):
                            return ScanResult(port, "tcp", "closed", service)
                            
        return ScanResult(port, "tcp", "filtered", service)
            
    except Exception as e:
        return None

def port_scan(target_ip, ports_services):
    print("\nStarting scan...")
    print("PORT            STATE              SERVICE")
    print("----            -----              -------")
    
    port_queue = queue.Queue()
    results_queue = queue.Queue()
    scan_results = []
    current_results = []  # Temporary list for sorting during scan

    for port, protocol in sorted(ports_services.keys(), key=lambda x: x[0]):  # Sort input ports
        port_queue.put((port, protocol))

    def worker():
        while not port_queue.empty():
            port, protocol = port_queue.get()
            if protocol == "TCP":
                result = scan_tcp_port_combined(target_ip, port, ports_services)
                if result:
                    results_queue.put(result)
            elif protocol == "UDP":
                result = scan_udp(target_ip, port, ports_services)
                if result:
                    results_queue.put(result)
            port_queue.task_done()

    # Start scanning threads
    num_threads = 100
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    # Print results in order while scanning
    while threading.active_count() > 1 or not results_queue.empty():
        try:
            result = results_queue.get_nowait()
            current_results.append(result)
            # Sort and print current results
            current_results.sort(key=lambda x: x.port)
            os.system('clear')  # Clear terminal
            print("\nStarting scan...")
            print("PORT            STATE              SERVICE")
            print("----            -----              -------")
            for r in current_results:
                print(format_output(r.port, r.protocol, r.state, r.service))
        except queue.Empty:
            continue

    # Store final sorted results
    scan_results = sorted(current_results, key=lambda x: x.port)

    # Print sorted summary
    print("\nScan Summary:")
    open_ports = sorted([r for r in scan_results if r.state == "open"], 
                       key=lambda x: x.port)
    filtered_ports = sorted([r for r in scan_results if r.state == "filtered"], 
                          key=lambda x: x.port)
    
    print(f"\nOpen ports: {len(open_ports)}")
    for result in open_ports:
        print(f"  {result.port}/{result.protocol} - {result.service}")
    
    print(f"\nFiltered ports: {len(filtered_ports)}")
    for result in filtered_ports:
        print(f"  {result.port}/{result.protocol} - {result.service}")

    return scan_results

def banner():
    print(r"""
    ============================
         ZeroNum Enumeration
    ============================
    """)

if __name__ == "__main__":
    banner()
    
    parser = argparse.ArgumentParser(description="ZeroNum - Enumeration Tool")
    parser.add_argument('target', help="Target IPv4 address")
    parser.add_argument('--services', default='services.txt', 
                       help="Path to services file (default: services.txt)")
    
    args = parser.parse_args()
    target_ip = args.target
    services_file = args.services
    
    if not is_valid_ipv4(target_ip):
        print(f"Error: '{target_ip}' is not a valid IPv4 address.")
        sys.exit(1)
    
    ports_list, ports_services = parse_services_file(services_file)
    port_scan(target_ip, ports_services)