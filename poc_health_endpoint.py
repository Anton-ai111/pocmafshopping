#!/usr/bin/env python3
"""
Proof of Concept: Unauthenticated Health Endpoint Exposure
Target: api.mafshoppingmalls.com
Severity: Low/Informational
"""

import requests
import json
import time
from datetime import datetime
import os

class HealthEndpointPoC:
    def __init__(self):
        self.target_url = "https://api.mafshoppingmalls.com"
        self.evidence_dir = "evidence/health_endpoint"
        os.makedirs(self.evidence_dir, exist_ok=True)
        
        # Common health endpoints to test
        self.health_endpoints = [
            '/health',
            '/status',
            '/ping',
            '/ready',
            '/live',
            '/info',
            '/metrics',
            '/actuator/health',
            '/api/health',
            '/v1/health'
        ]
    
    def test_endpoints(self):
        """Test various health endpoints"""
        print(f"[*] Testing health endpoints on: {self.target_url}")
        
        results = {}
        
        for endpoint in self.health_endpoints:
            url = f"{self.target_url}{endpoint}"
            
            print(f"  Testing: {url}")
            
            try:
                response = requests.get(url, timeout=10)
                
                result = {
                    'url': url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text[:500] if response.text else '',
                    'size': len(response.content),
                    'timestamp': datetime.now().isoformat()
                }
                
                results[endpoint] = result
                
                if response.status_code == 200:
                    print(f"    [+] Accessible (200): {response.text[:100]}")
                elif response.status_code < 400:
                    print(f"    [+] Responded ({response.status_code})")
                else:
                    print(f"    [-] Failed ({response.status_code})")
            
            except requests.exceptions.RequestException as e:
                result = {
                    'url': url,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
                results[endpoint] = result
                print(f"    [-] Error: {e}")
            
            time.sleep(0.5)  # Be nice to the server
        
        return results
    
    def analyze_results(self, results):
        """Analyze test results for vulnerabilities"""
        print("[*] Analyzing results...")
        
        vulnerabilities = []
        accessible_endpoints = []
        
        for endpoint, result in results.items():
            if 'status_code' in result and result['status_code'] < 400:
                accessible_endpoints.append(endpoint)
                
                # Check for information disclosure
                body = result.get('body', '').lower()
                if any(keyword in body for keyword in ['healthy', 'status', 'version', 'database', 'up', 'running']):
                    vulnerabilities.append({
                        'endpoint': endpoint,
                        'type': 'Information Disclosure',
                        'details': 'Health/status information exposed',
                        'evidence': result['body'][:200]
                    })
        
        return accessible_endpoints, vulnerabilities
    
    def generate_report(self, results, accessible_endpoints, vulnerabilities):
        """Generate evidence report"""
        print("[*] Generating health endpoint report...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save raw results
        results_file = f"{self.evidence_dir}/test_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate human-readable report
        report_file = f"{self.evidence_dir}/health_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("UNAUTHENTICATED HEALTH ENDPOINT EXPOSURE - PROOF OF CONCEPT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Target Base URL: {self.target_url}\n")
            f.write(f"Test Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Endpoints Tested: {len(results)}\n\n")
            
            f.write("ACCESSIBLE ENDPOINTS:\n")
            f.write("-"*40 + "\n")
            if accessible_endpoints:
                for endpoint in accessible_endpoints:
                    result = results[endpoint]
                    f.write(f"\n{endpoint}:\n")
                    f.write(f"  URL: {result['url']}\n")
                    f.write(f"  Status: {result['status_code']}\n")
                    f.write(f"  Response: {result.get('body', 'No body')[:200]}\n")
            else:
                f.write("No endpoints publicly accessible\n")
            
            f.write("\nVULNERABILITIES IDENTIFIED:\n")
            f.write("-"*40 + "\n")
            if vulnerabilities:
                for vuln in vulnerabilities:
                    f.write(f"\n• {vuln['type']}\n")
                    f.write(f"  Endpoint: {vuln['endpoint']}\n")
                    f.write(f"  Details: {vuln['details']}\n")
                    f.write(f"  Evidence: {vuln['evidence']}\n")
            else:
                f.write("No critical vulnerabilities identified\n")
            
            f.write("\nIMPACT ANALYSIS:\n")
            f.write("-"*40 + "\n")
            f.write("1. Information Disclosure: Service status and health information exposed\n")
            f.write("2. Attack Surface Enumeration: Confirms active services and endpoints\n")
            f.write("3. Monitoring Bypass: Could be used to hide service issues from internal monitoring\n")
            f.write("4. Reconnaissance Aid: Provides information for further attacks\n")
            
            f.write("\nRECOMMENDED REMEDIATION:\n")
            f.write("-"*40 + "\n")
            f.write("1. Restrict health endpoints to internal networks\n")
            f.write("2. Implement authentication for monitoring endpoints\n")
            f.write("3. Use Network Security Groups (NSGs) to limit access\n")
            f.write("4. Separate internal monitoring from public-facing services\n")
            f.write("5. Implement IP whitelisting for health checks\n")
            
            f.write("\nEVIDENCE FILES:\n")
            f.write("-"*40 + "\n")
            f.write(f"1. Test Results: {results_file}\n")
            f.write(f"2. This Report: {report_file}\n")
        
        print(f"[+] Report saved to: {report_file}")
        return report_file
    
    def run(self):
        """Main execution method"""
        print("="*80)
        print("HEALTH ENDPOINT EXPOSURE - PROOF OF CONCEPT")
        print("="*80)
        
        # Step 1: Test endpoints
        results = self.test_endpoints()
        
        # Step 2: Analyze results
        accessible_endpoints, vulnerabilities = self.analyze_results(results)
        
        # Step 3: Generate report
        report_file = self.generate_report(results, accessible_endpoints, vulnerabilities)
        
        # Display summary
        print("\n" + "="*80)
        print("POC COMPLETED SUCCESSFULLY!")
        print("="*80)
        print(f"Endpoints Tested: {len(results)}")
        print(f"Accessible Endpoints: {len(accessible_endpoints)}")
        print(f"Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"\nEvidence saved to: {self.evidence_dir}/")
        print(f"Report: {report_file}")

if __name__ == "__main__":
    poc = HealthEndpointPoC()
    poc.run()
