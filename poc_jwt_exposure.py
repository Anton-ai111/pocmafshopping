#!/usr/bin/env python3
"""
Proof of Concept: JWT Token Exposure in HTML Source
Target: www.premogiftcards.com
Severity: Medium
"""

import requests
import base64
import json
import jwt
from datetime import datetime
import os

class JWTExposurePoC:
    def __init__(self):
        self.target_url = "https://www.premogiftcards.com"
        self.evidence_dir = "evidence/jwt_exposure"
        os.makedirs(self.evidence_dir, exist_ok=True)
    
    def fetch_page_and_extract_tokens(self):
        """Fetch webpage and extract JWT tokens from cookies and HTML"""
        print(f"[*] Fetching page from: {self.target_url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(self.target_url, headers=headers)
        
        if response.status_code == 200:
            print(f"[+] Success! Received {len(response.text)} characters")
            
            # Save raw HTML
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_file = f"{self.evidence_dir}/page_source_{timestamp}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            print(f"[+] Page source saved to: {html_file}")
            
            # Extract tokens from cookies
            cookies = response.cookies
            jwt_tokens = {}
            
            for cookie in cookies:
                if 'token' in cookie.name.lower() or 'access' in cookie.name.lower():
                    jwt_tokens[cookie.name] = cookie.value
                    print(f"[+] Found token in cookie: {cookie.name}")
            
            # Extract from Set-Cookie headers
            if 'set-cookie' in response.headers:
                set_cookie = response.headers['set-cookie']
                if 'X_ACCESS_TOKEN' in set_cookie:
                    # Extract token from Set-Cookie header
                    token_start = set_cookie.find('X_ACCESS_TOKEN=') + len('X_ACCESS_TOKEN=')
                    token_end = set_cookie.find(';', token_start)
                    token = set_cookie[token_start:token_end]
                    jwt_tokens['X_ACCESS_TOKEN'] = token
                    print("[+] Found X_ACCESS_TOKEN in Set-Cookie header")
            
            # Also search in HTML body
            import re
            html_tokens = re.findall(r'eyJ[^"\s]+', response.text)
            for token in html_tokens:
                if len(token) > 100:  # Likely a JWT
                    jwt_tokens['html_embedded'] = token
                    print("[+] Found JWT token embedded in HTML")
                    break
            
            return response.text, jwt_tokens, html_file
        
        else:
            print(f"[-] Failed to fetch page. Status: {response.status_code}")
            return None, None, None
    
    def decode_jwt(self, token):
        """Decode JWT token without verification"""
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            header = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8'))
            payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
            
            decoded = {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
            
            return decoded
        
        except Exception as e:
            print(f"[-] Failed to decode JWT: {e}")
            return None
    
    def analyze_jwt(self, decoded_token):
        """Analyze JWT for security issues"""
        issues = []
        payload = decoded_token['payload']
        header = decoded_token['header']
        
        print("[*] Analyzing JWT token...")
        
        # Check expiry
        if 'exp' in payload:
            exp_timestamp = payload['exp']
            exp_date = datetime.fromtimestamp(exp_timestamp)
            current_time = datetime.now().timestamp()
            
            if current_time > exp_timestamp:
                issues.append(f"Token expired on {exp_date}")
            else:
                issues.append(f"Token expires on {exp_date}")
        
        # Check algorithm
        if header.get('alg') == 'none':
            issues.append("JWT uses 'none' algorithm (vulnerable to algorithm confusion)")
        
        # Check for sensitive data
        sensitive_fields = ['password', 'secret', 'key', 'email', 'phone', 'address']
        for field in sensitive_fields:
            if field in str(payload).lower():
                issues.append(f"Potential sensitive field found: {field}")
        
        # Check scopes/privileges
        if 'scopes' in payload or 'roles' in payload or 'permissions' in payload:
            issues.append("Authorization scopes/roles exposed")
        
        # Check user identifier
        if 'sub' in payload:
            issues.append(f"User identifier exposed: sub={payload['sub']}")
        
        return issues
    
    def generate_report(self, html_file, jwt_tokens, decoded_tokens, issues):
        """Generate evidence report"""
        print("[*] Generating JWT exposure report...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save decoded tokens
        tokens_file = f"{self.evidence_dir}/decoded_tokens_{timestamp}.json"
        with open(tokens_file, 'w') as f:
            json.dump({
                'raw_tokens': jwt_tokens,
                'decoded_tokens': decoded_tokens,
                'security_issues': issues
            }, f, indent=2)
        
        # Generate human-readable report
        report_file = f"{self.evidence_dir}/jwt_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("JWT TOKEN EXPOSURE - PROOF OF CONCEPT REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Target URL: {self.target_url}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
            
            f.write("TOKENS FOUND:\n")
            f.write("-"*40 + "\n")
            for token_name, token_value in jwt_tokens.items():
                f.write(f"{token_name}: {token_value[:50]}...\n")
            
            f.write("\nDECODED JWT TOKENS:\n")
            f.write("-"*40 + "\n")
            for token_name, decoded in decoded_tokens.items():
                if decoded:
                    f.write(f"\n{token_name}:\n")
                    f.write(f"  Header: {json.dumps(decoded['header'], indent=2)}\n")
                    f.write(f"  Payload: {json.dumps(decoded['payload'], indent=2)}\n")
            
            f.write("\nSECURITY ISSUES IDENTIFIED:\n")
            f.write("-"*40 + "\n")
            if issues:
                for issue in issues:
                    f.write(f"• {issue}\n")
            else:
                f.write("No critical security issues identified in token structure.\n")
            
            f.write("\nIMPACT ANALYSIS:\n")
            f.write("-"*40 + "\n")
            f.write("1. Session Information Leakage: JWT tokens expose user session details\n")
            f.write("2. Session Fixation Risk: If token refresh logic is flawed\n")
            f.write("3. User Enumeration: User IDs and structure exposed\n")
            f.write("4. Authentication Bypass Research: Tokens available for analysis\n")
            
            f.write("\nRECOMMENDED REMEDIATION:\n")
            f.write("-"*40 + "\n")
            f.write("1. Store JWT tokens in HTTP-only cookies\n")
            f.write("2. Implement Secure and SameSite flags\n")
            f.write("3. Use short-lived access tokens with refresh tokens\n")
            f.write("4. Avoid embedding tokens in HTML/JavaScript\n")
            f.write("5. Implement proper token validation and refresh logic\n")
            
            f.write("\nEVIDENCE FILES:\n")
            f.write("-"*40 + "\n")
            f.write(f"1. Page Source: {html_file}\n")
            f.write(f"2. Decoded Tokens: {tokens_file}\n")
            f.write(f"3. This Report: {report_file}\n")
        
        print(f"[+] Report saved to: {report_file}")
        return report_file
    
    def run(self):
        """Main execution method"""
        print("="*80)
        print("JWT TOKEN EXPOSURE IN HTML SOURCE - PROOF OF CONCEPT")
        print("="*80)
        
        # Step 1: Fetch page and extract tokens
        html, jwt_tokens, html_file = self.fetch_page_and_extract_tokens()
        if not jwt_tokens:
            print("[-] No JWT tokens found")
            return
        
        # Step 2: Decode tokens
        decoded_tokens = {}
        security_issues = []
        
        for token_name, token_value in jwt_tokens.items():
            print(f"\n[*] Analyzing token: {token_name}")
            decoded = self.decode_jwt(token_value)
            if decoded:
                decoded_tokens[token_name] = decoded
                issues = self.analyze_jwt(decoded)
                security_issues.extend(issues)
                
                # Display token info
                print(f"  Algorithm: {decoded['header'].get('alg', 'unknown')}")
                if 'sub' in decoded['payload']:
                    print(f"  User ID: {decoded['payload']['sub']}")
                if 'exp' in decoded['payload']:
                    exp_date = datetime.fromtimestamp(decoded['payload']['exp'])
                    print(f"  Expires: {exp_date}")
        
        # Step 3: Generate report
        report_file = self.generate_report(html_file, jwt_tokens, decoded_tokens, security_issues)
        
        # Display summary
        print("\n" + "="*80)
        print("POC COMPLETED SUCCESSFULLY!")
        print("="*80)
        print(f"Tokens Found: {len(jwt_tokens)}")
        print(f"Security Issues Identified: {len(security_issues)}")
        print(f"\nEvidence saved to: {self.evidence_dir}/")
        print(f"Report: {report_file}")

if __name__ == "__main__":
    poc = JWTExposurePoC()
    poc.run()
