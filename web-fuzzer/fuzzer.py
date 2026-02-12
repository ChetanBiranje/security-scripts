#!/usr/bin/env python3
"""
Web Fuzzer
Directory and parameter fuzzing tool for web applications
"""

import requests
import argparse
import threading
from queue import Queue
from urllib.parse import urljoin, urlparse
import time
from typing import List, Dict
import sys

try:
    from colorama import Fore, Style, init
    from tqdm import tqdm
    init(autoreset=True)
    COLORS = True
    PROGRESS_BAR = True
except ImportError:
    COLORS = False
    PROGRESS_BAR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ""


class WebFuzzer:
    """Web Application Fuzzer"""
    
    def __init__(self, url: str, wordlist: str, threads: int = 10, timeout: int = 10):
        """
        Initialize Web Fuzzer
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip('/')
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.session = requests.Session()
        
        # Custom headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def load_wordlist(self) -> List[str]:
        """
        Load wordlist from file
        
        Returns:
            List of words
        """
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist not found: {self.wordlist}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading wordlist: {e}")
            sys.exit(1)
    
    def fuzz_directory(self, directory: str) -> Dict:
        """
        Fuzz a directory
        
        Args:
            directory: Directory name to test
            
        Returns:
            Dictionary with results if found
        """
        # Build target URL
        target_url = urljoin(self.url + '/', directory)
        
        try:
            response = self.session.get(
                target_url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Check if directory exists
            if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403]:
                result = {
                    'url': target_url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'redirect': response.headers.get('Location', '')
                }
                
                with self.lock:
                    self.found.append(result)
                    color = Fore.GREEN if response.status_code == 200 else Fore.YELLOW
                    print(f"{color}[{response.status_code}] {target_url:60s} Size: {len(response.content):8d}")
                
                return result
            
            return None
            
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            return None
    
    def fuzz_parameter(self, param_name: str, payload: str) -> Dict:
        """
        Fuzz a parameter with payload
        
        Args:
            param_name: Parameter name
            payload: Payload to test
            
        Returns:
            Dictionary with results if interesting response
        """
        try:
            # Test parameter
            params = {param_name: payload}
            response = self.session.get(
                self.url,
                params=params,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # Check for interesting responses
            interesting_indicators = [
                'error', 'exception', 'warning', 'sql', 'mysql', 
                'oracle', 'jdbc', 'postgresql', 'syntax', 'fatal'
            ]
            
            response_text = response.text.lower()
            is_interesting = any(indicator in response_text for indicator in interesting_indicators)
            
            if is_interesting or response.status_code >= 500:
                result = {
                    'url': response.url,
                    'parameter': param_name,
                    'payload': payload,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'interesting': True
                }
                
                with self.lock:
                    self.found.append(result)
                    print(f"{Fore.RED}[!] Interesting response: {param_name}={payload} - Status: {response.status_code}")
                
                return result
            
            return None
            
        except:
            return None
    
    def worker_directory(self):
        """Worker thread for directory fuzzing"""
        while not self.queue.empty():
            directory = self.queue.get()
            self.fuzz_directory(directory)
            self.queue.task_done()
    
    def worker_parameter(self, param_name: str):
        """Worker thread for parameter fuzzing"""
        while not self.queue.empty():
            payload = self.queue.get()
            self.fuzz_parameter(param_name, payload)
            self.queue.task_done()
    
    def fuzz_directories(self) -> List[Dict]:
        """
        Start directory fuzzing
        
        Returns:
            List of found directories
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}WEB FUZZER - Directory Enumeration")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}[*] Target URL: {self.url}")
        print(f"{Fore.YELLOW}[*] Wordlist: {self.wordlist}")
        print(f"{Fore.YELLOW}[*] Threads: {self.threads}\n")
        
        # Load wordlist
        words = self.load_wordlist()
        print(f"{Fore.GREEN}[+] Loaded {len(words)} words from wordlist\n")
        
        # Add words to queue
        for word in words:
            self.queue.put(word)
        
        # Start timer
        start_time = time.time()
        
        # Create and start threads
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker_directory)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        self.queue.join()
        
        # Calculate time
        scan_time = time.time() - start_time
        
        # Print summary
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}FUZZING SUMMARY")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] Fuzzing completed in {scan_time:.2f} seconds")
        print(f"{Fore.GREEN}[✓] Tested {len(words)} directories")
        print(f"{Fore.GREEN}[✓] Found {len(self.found)} results")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        return self.found
    
    def fuzz_parameters(self, param_name: str, payloads_file: str) -> List[Dict]:
        """
        Start parameter fuzzing
        
        Args:
            param_name: Parameter name to fuzz
            payloads_file: File containing payloads
            
        Returns:
            List of interesting results
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}WEB FUZZER - Parameter Fuzzing")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}[*] Target URL: {self.url}")
        print(f"{Fore.YELLOW}[*] Parameter: {param_name}")
        print(f"{Fore.YELLOW}[*] Payloads: {payloads_file}\n")
        
        # Load payloads
        try:
            with open(payloads_file, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except:
            print(f"{Fore.RED}[!] Error loading payloads file")
            return []
        
        print(f"{Fore.GREEN}[+] Loaded {len(payloads)} payloads\n")
        
        # Add payloads to queue
        for payload in payloads:
            self.queue.put(payload)
        
        # Start timer
        start_time = time.time()
        
        # Create and start threads
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=lambda: self.worker_parameter(param_name))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        self.queue.join()
        
        # Calculate time
        scan_time = time.time() - start_time
        
        # Print summary
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] Fuzzing completed in {scan_time:.2f} seconds")
        print(f"{Fore.GREEN}[✓] Tested {len(payloads)} payloads")
        print(f"{Fore.GREEN}[✓] Found {len(self.found)} interesting responses")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        return self.found


def create_default_wordlist():
    """Create a default wordlist if none exists"""
    wordlist = """admin
login
dashboard
api
config
backup
test
dev
staging
.git
.env
uploads
images
css
js
assets
static
wp-admin
phpmyadmin
"""
    with open('default_wordlist.txt', 'w') as f:
        f.write(wordlist)
    return 'default_wordlist.txt'


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description='Web Application Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Directory fuzzing
  %(prog)s --url https://example.com --wordlist dirs.txt
  
  # Parameter fuzzing
  %(prog)s --url https://example.com/search --param q --wordlist payloads.txt
  
  # Custom threads and timeout
  %(prog)s --url https://example.com --wordlist dirs.txt --threads 20 --timeout 5
        '''
    )
    
    parser.add_argument('--url', '-u', required=True, help='Target URL')
    parser.add_argument('--wordlist', '-w', help='Wordlist file')
    parser.add_argument('--param', '-p', help='Parameter name (for parameter fuzzing)')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    
    args = parser.parse_args()
    
    # Create default wordlist if none provided
    if not args.wordlist:
        print(f"{Fore.YELLOW}[!] No wordlist specified, creating default wordlist...")
        args.wordlist = create_default_wordlist()
        print(f"{Fore.GREEN}[+] Created: {args.wordlist}")
    
    # Create fuzzer
    fuzzer = WebFuzzer(
        url=args.url,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        if args.param:
            # Parameter fuzzing mode
            fuzzer.fuzz_parameters(args.param, args.wordlist)
        else:
            # Directory fuzzing mode
            fuzzer.fuzz_directories()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Fuzzing interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
