#!/usr/bin/env python3
"""
Advanced Port Scanner
Multi-threaded port scanner with service detection and banner grabbing
"""

import socket
import threading
import argparse
import json
import time
from datetime import datetime
from queue import Queue
from typing import List, Dict
import sys

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""


class PortScanner:
    """Advanced Port Scanner with threading"""
    
    # Common ports and their services
    COMMON_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"
    }
    
    def __init__(self, target: str, ports: List[int] = None, threads: int = 100, timeout: int = 1):
        """
        Initialize Port Scanner
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
        """
        self.target = target
        self.ports = ports or list(range(1, 1001))  # Default: scan first 1000 ports
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.port_queue = Queue()
        self.lock = threading.Lock()
        
        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{Fore.RED}[!] Unable to resolve hostname: {target}")
            sys.exit(1)
    
    def scan_port(self, port: int) -> Dict:
        """
        Scan a single port
        
        Args:
            port: Port number to scan
            
        Returns:
            Dictionary with scan results
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                # Port is open
                service = self.COMMON_PORTS.get(port, "Unknown")
                banner = self.grab_banner(sock, port)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
                with self.lock:
                    self.open_ports.append(port_info)
                    print(f"{Fore.GREEN}[+] Port {port:5d} | OPEN | {service:15s} | {banner[:50]}")
                
                sock.close()
                return port_info
            else:
                sock.close()
                return {'port': port, 'state': 'closed'}
                
        except socket.timeout:
            return {'port': port, 'state': 'filtered'}
        except Exception as e:
            return {'port': port, 'state': 'error', 'error': str(e)}
    
    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Attempt to grab service banner
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Service banner or empty string
        """
        try:
            sock.settimeout(2)
            
            # Send appropriate probe based on port
            if port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            elif port in [80, 8080]:  # HTTP
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0].strip()
            elif port == 443:  # HTTPS
                banner = "HTTPS (SSL/TLS)"
            else:
                # Generic probe
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            return banner if banner else "No banner"
        except:
            return "No banner"
    
    def worker(self):
        """Worker thread for scanning ports"""
        while not self.port_queue.empty():
            port = self.port_queue.get()
            self.scan_port(port)
            self.port_queue.task_done()
    
    def scan(self) -> List[Dict]:
        """
        Start the port scan
        
        Returns:
            List of open ports with details
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}PORT SCANNER - Advanced Network Security Tool")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}[*] Target: {self.target} ({self.target_ip})")
        print(f"{Fore.YELLOW}[*] Ports: {len(self.ports)} ports")
        print(f"{Fore.YELLOW}[*] Threads: {self.threads}")
        print(f"{Fore.YELLOW}[*] Timeout: {self.timeout}s")
        print(f"{Fore.YELLOW}[*] Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Add ports to queue
        for port in self.ports:
            self.port_queue.put(port)
        
        # Start timer
        start_time = time.time()
        
        # Create and start threads
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        self.port_queue.join()
        
        # Calculate scan time
        scan_time = time.time() - start_time
        
        # Print summary
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] Scan completed in {scan_time:.2f} seconds")
        print(f"{Fore.GREEN}[✓] Total ports scanned: {len(self.ports)}")
        print(f"{Fore.GREEN}[✓] Open ports found: {len(self.open_ports)}")
        
        if self.open_ports:
            print(f"\n{Fore.YELLOW}Open Ports:")
            for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                print(f"  {Fore.GREEN}{port_info['port']:5d} | {port_info['service']:15s} | {port_info['banner'][:50]}")
        
        print(f"{Fore.CYAN}{'='*70}\n")
        
        return self.open_ports
    
    def save_results(self, output_file: str = "scan_results.json"):
        """
        Save scan results to JSON file
        
        Args:
            output_file: Output file path
        """
        results = {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_time': datetime.now().isoformat(),
            'total_ports_scanned': len(self.ports),
            'open_ports_count': len(self.open_ports),
            'open_ports': self.open_ports
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Results saved to: {output_file}")


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse port range string to list of ports
    
    Args:
        port_range: Port range (e.g., "1-100", "80,443,8080", "1-100,443")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner with Service Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --target 192.168.1.1
  %(prog)s --target scanme.nmap.org --ports 1-1000
  %(prog)s --target example.com --ports 80,443,8080 --threads 50
  %(prog)s --target 10.0.0.1 --full --output results.json
        '''
    )
    
    parser.add_argument('--target', '-t', required=True, help='Target IP or hostname')
    parser.add_argument('--ports', '-p', default='1-1000', help='Port range (e.g., 1-1000, 80,443)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1, help='Connection timeout (default: 1s)')
    parser.add_argument('--full', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    # Parse ports
    if args.full:
        ports = list(range(1, 65536))
        print(f"{Fore.YELLOW}[!] Full scan mode: scanning all 65535 ports")
    else:
        ports = parse_port_range(args.ports)
    
    # Create scanner
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout
    )
    
    # Run scan
    try:
        scanner.scan()
        
        # Save results if output file specified
        if args.output:
            scanner.save_results(args.output)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
