#!/usr/bin/env python3
"""
Password Analyzer
Password strength checker, generator, and dictionary attack tool
"""

import hashlib
import argparse
import string
import random
import re
from typing import Dict, List
import sys

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ""


class PasswordAnalyzer:
    """Password Security Analyzer"""
    
    # Common weak passwords
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', '111111', 'iloveyou', 'master', 'sunshine',
        'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
        '654321', 'superman', 'qazwsx', 'michael', 'Football'
    ]
    
    def __init__(self):
        """Initialize Password Analyzer"""
        pass
    
    def check_strength(self, password: str) -> Dict:
        """
        Analyze password strength
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength analysis
        """
        analysis = {
            'password': password,
            'length': len(password),
            'score': 0,
            'strength': '',
            'checks': {},
            'suggestions': []
        }
        
        # Length check
        if len(password) < 8:
            analysis['checks']['length'] = False
            analysis['suggestions'].append('Use at least 8 characters')
        elif len(password) < 12:
            analysis['checks']['length'] = True
            analysis['score'] += 1
            analysis['suggestions'].append('Consider using 12+ characters for better security')
        else:
            analysis['checks']['length'] = True
            analysis['score'] += 2
        
        # Uppercase check
        if re.search(r'[A-Z]', password):
            analysis['checks']['uppercase'] = True
            analysis['score'] += 1
        else:
            analysis['checks']['uppercase'] = False
            analysis['suggestions'].append('Add uppercase letters (A-Z)')
        
        # Lowercase check
        if re.search(r'[a-z]', password):
            analysis['checks']['lowercase'] = True
            analysis['score'] += 1
        else:
            analysis['checks']['lowercase'] = False
            analysis['suggestions'].append('Add lowercase letters (a-z)')
        
        # Digit check
        if re.search(r'\d', password):
            analysis['checks']['digits'] = True
            analysis['score'] += 1
        else:
            analysis['checks']['digits'] = False
            analysis['suggestions'].append('Add numbers (0-9)')
        
        # Special character check
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            analysis['checks']['special'] = True
            analysis['score'] += 2
        else:
            analysis['checks']['special'] = False
            analysis['suggestions'].append('Add special characters (!@#$%^&*)')
        
        # Common password check
        if password.lower() in [p.lower() for p in self.COMMON_PASSWORDS]:
            analysis['checks']['common'] = True
            analysis['score'] -= 3
            analysis['suggestions'].append('⚠️  This is a commonly used password!')
        else:
            analysis['checks']['common'] = False
        
        # Sequential characters check
        if self._has_sequential(password):
            analysis['checks']['sequential'] = True
            analysis['score'] -= 1
            analysis['suggestions'].append('Avoid sequential characters (abc, 123)')
        else:
            analysis['checks']['sequential'] = False
        
        # Repeated characters check
        if self._has_repeated(password):
            analysis['checks']['repeated'] = True
            analysis['score'] -= 1
            analysis['suggestions'].append('Avoid repeated characters (aaa, 111)')
        else:
            analysis['checks']['repeated'] = False
        
        # Calculate final strength
        if analysis['score'] <= 2:
            analysis['strength'] = 'VERY WEAK'
            analysis['color'] = Fore.RED
        elif analysis['score'] <= 4:
            analysis['strength'] = 'WEAK'
            analysis['color'] = Fore.YELLOW
        elif analysis['score'] <= 6:
            analysis['strength'] = 'MODERATE'
            analysis['color'] = Fore.YELLOW
        elif analysis['score'] <= 8:
            analysis['strength'] = 'STRONG'
            analysis['color'] = Fore.GREEN
        else:
            analysis['strength'] = 'VERY STRONG'
            analysis['color'] = Fore.GREEN
        
        return analysis
    
    def _has_sequential(self, password: str) -> bool:
        """Check for sequential characters"""
        sequences = ['abc', '123', 'xyz', '789', 'qwe', 'asd', 'zxc']
        password_lower = password.lower()
        return any(seq in password_lower or seq[::-1] in password_lower for seq in sequences)
    
    def _has_repeated(self, password: str) -> bool:
        """Check for repeated characters"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False
    
    def generate_password(self, length: int = 16, use_special: bool = True) -> str:
        """
        Generate a secure random password
        
        Args:
            length: Password length
            use_special: Include special characters
            
        Returns:
            Generated password
        """
        chars = string.ascii_letters + string.digits
        if use_special:
            chars += string.punctuation
        
        # Ensure password has at least one of each type
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
        ]
        
        if use_special:
            password.append(random.choice(string.punctuation))
        
        # Fill the rest randomly
        password += [random.choice(chars) for _ in range(length - len(password))]
        
        # Shuffle
        random.shuffle(password)
        
        return ''.join(password)
    
    def crack_hash(self, hash_value: str, wordlist: str, hash_type: str = 'md5') -> Dict:
        """
        Attempt to crack password hash using dictionary attack
        
        Args:
            hash_value: Hash to crack
            wordlist: Path to wordlist file
            hash_type: Hash type (md5, sha1, sha256, sha512)
            
        Returns:
            Dictionary with crack results
        """
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}PASSWORD HASH CRACKER")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}[*] Hash: {hash_value}")
        print(f"{Fore.YELLOW}[*] Type: {hash_type.upper()}")
        print(f"{Fore.YELLOW}[*] Wordlist: {wordlist}\n")
        
        # Select hash function
        hash_funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        hash_func = hash_funcs.get(hash_type.lower())
        if not hash_func:
            print(f"{Fore.RED}[!] Unsupported hash type: {hash_type}")
            return {'found': False}
        
        # Load wordlist
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist not found: {wordlist}")
            return {'found': False}
        
        print(f"{Fore.GREEN}[+] Loaded {len(words)} words\n")
        print(f"{Fore.YELLOW}[*] Cracking...\n")
        
        # Try each word
        for i, word in enumerate(words, 1):
            # Hash the word
            word_hash = hash_func(word.encode()).hexdigest()
            
            # Check if it matches
            if word_hash == hash_value.lower():
                print(f"\n{Fore.GREEN}[✓] PASSWORD FOUND!")
                print(f"{Fore.GREEN}[✓] Hash: {hash_value}")
                print(f"{Fore.GREEN}[✓] Password: {word}")
                print(f"{Fore.GREEN}[✓] Attempts: {i}\n")
                
                return {
                    'found': True,
                    'password': word,
                    'attempts': i
                }
            
            # Progress indicator
            if i % 1000 == 0:
                print(f"{Fore.CYAN}[*] Tried {i:,} words...", end='\r')
        
        print(f"\n{Fore.RED}[✗] Password not found in wordlist")
        print(f"{Fore.RED}[✗] Tried {len(words):,} words\n")
        
        return {
            'found': False,
            'attempts': len(words)
        }
    
    def print_analysis(self, analysis: Dict):
        """Print password strength analysis"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}PASSWORD STRENGTH ANALYSIS")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        # Basic info
        print(f"{Fore.YELLOW}Password Length: {analysis['length']} characters")
        print(f"{Fore.YELLOW}Strength Score: {analysis['score']}/10")
        print(f"{analysis['color']}Overall Strength: {analysis['strength']}\n")
        
        # Checks
        print(f"{Fore.CYAN}Security Checks:")
        
        checks = {
            'length': 'Minimum length (8+ characters)',
            'uppercase': 'Contains uppercase letters',
            'lowercase': 'Contains lowercase letters',
            'digits': 'Contains numbers',
            'special': 'Contains special characters',
            'common': 'Is NOT a common password',
            'sequential': 'Has NO sequential characters',
            'repeated': 'Has NO repeated characters'
        }
        
        for check, description in checks.items():
            if check in analysis['checks']:
                status = '✓' if analysis['checks'][check] else '✗'
                color = Fore.GREEN if analysis['checks'][check] else Fore.RED
                
                # Invert for negative checks
                if check in ['common', 'sequential', 'repeated']:
                    status = '✗' if analysis['checks'][check] else '✓'
                    color = Fore.RED if analysis['checks'][check] else Fore.GREEN
                
                print(f"  {color}[{status}] {description}")
        
        # Suggestions
        if analysis['suggestions']:
            print(f"\n{Fore.YELLOW}Suggestions for Improvement:")
            for suggestion in analysis['suggestions']:
                print(f"  • {suggestion}")
        
        print(f"\n{Fore.CYAN}{'='*70}\n")


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description='Password Security Analyzer and Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Check password strength
  %(prog)s --password "MyP@ssw0rd123"
  
  # Generate secure password
  %(prog)s --generate --length 16
  
  # Crack password hash
  %(prog)s --hash "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist rockyou.txt --type md5
        '''
    )
    
    parser.add_argument('--password', '-p', help='Password to analyze')
    parser.add_argument('--generate', '-g', action='store_true', help='Generate secure password')
    parser.add_argument('--length', '-l', type=int, default=16, help='Generated password length (default: 16)')
    parser.add_argument('--hash', help='Hash to crack')
    parser.add_argument('--wordlist', '-w', help='Wordlist for cracking')
    parser.add_argument('--type', '-t', default='md5', choices=['md5', 'sha1', 'sha256', 'sha512'], 
                       help='Hash type (default: md5)')
    
    args = parser.parse_args()
    
    analyzer = PasswordAnalyzer()
    
    if args.generate:
        # Generate password
        password = analyzer.generate_password(length=args.length)
        print(f"\n{Fore.GREEN}Generated Password: {password}")
        
        # Also analyze it
        analysis = analyzer.check_strength(password)
        analyzer.print_analysis(analysis)
    
    elif args.password:
        # Analyze password
        analysis = analyzer.check_strength(args.password)
        analyzer.print_analysis(analysis)
    
    elif args.hash and args.wordlist:
        # Crack hash
        result = analyzer.crack_hash(args.hash, args.wordlist, args.type)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
