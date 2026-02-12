#!/usr/bin/env python3
"""
Subdomain Enumerator
Discover subdomains using DNS bruteforce and other techniques
"""

import dns.resolver
import argparse
import threading
from queue import Queue
from typing import List, Set
import sys

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ""


class SubdomainEnumerator:
    """Subdomain Discovery Tool"""
    
    def __init__(self, domain: str, wordlist: str = None, threads: int = 10):
        """
        Initialize Subdomain Enumerator
        
        Args:
            domain: Target domain
            wordlist: Path to wordlist
            threads: Number of threads
        """
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.found_subdomains = set()
        self.queue = Queue()
        self.lock = threading.Lock()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def check_subdomain(self, subdomain: str) -> bool:
        """
        Check if subdomain exists
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            True if subdomain exists
        """
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Try A record
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            with self.lock:
                self.found_subdomains.add((full_domain, ', '.join(ips)))
                print(f"{Fore.GREEN}[+] {full_domain:40s} → {', '.join(ips)}")
            
            return True
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return False
        except dns.exception.Timeout:
            return False
        except Exception as e:
            return False
    
    def worker(self):
        """Worker thread for checking subdomains"""
        while not self.queue.empty():
            subdomain = self.queue.get()
            self.check_subdomain(subdomain)
            self.queue.task_done()
    
    def load_wordlist(self) -> List[str]:
        """Load subdomain wordlist"""
        if self.wordlist:
            try:
                with open(self.wordlist, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.RED}[!] Wordlist not found: {self.wordlist}")
                sys.exit(1)
        else:
            # Default wordlist
            return [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
                'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
                'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
                'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
                'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
                'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
                'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
                'images', 'img', 'www1', 'intranet', 'portal', 'video',
                'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
                'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
                'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads',
                'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
                'apps', 'download', 'remote', 'db', 'forums', 'store',
                'relay', 'files', 'newsletter', 'app', 'live', 'owa'
            ]
    
    def enumerate(self) -> Set:
        """
        Start subdomain enumeration
        
        Returns:
            Set of found subdomains
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}SUBDOMAIN ENUMERATOR")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}[*] Target Domain: {self.domain}")
        print(f"{Fore.YELLOW}[*] Threads: {self.threads}\n")
        
        # Load wordlist
        subdomains = self.load_wordlist()
        print(f"{Fore.GREEN}[+] Loaded {len(subdomains)} subdomains to test\n")
        
        # Add to queue
        for subdomain in subdomains:
            self.queue.put(subdomain)
        
        # Start threads
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        self.queue.join()
        
        # Print summary
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] Enumeration complete")
        print(f"{Fore.GREEN}[✓] Found {len(self.found_subdomains)} subdomains")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        return self.found_subdomains
    
    def save_results(self, output_file: str):
        """Save results to file"""
        with open(output_file, 'w') as f:
            for subdomain, ips in sorted(self.found_subdomains):
                f.write(f"{subdomain} → {ips}\n")
        
        print(f"{Fore.GREEN}[+] Results saved to: {output_file}")


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(description='Subdomain Enumeration Tool')
    parser.add_argument('--domain', '-d', required=True, help='Target domain')
    parser.add_argument('--wordlist', '-w', help='Subdomain wordlist')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--output', '-o', help='Output file')
    
    args = parser.parse_args()
    
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads
    )
    
    try:
        enumerator.enumerate()
        
        if args.output:
            enumerator.save_results(args.output)
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
