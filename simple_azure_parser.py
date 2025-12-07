#!/usr/bin/env python3
import requests
import re
import json
from datetime import datetime

def parse_azure_blob():
    url = "https://premoprodstorage.blob.core.windows.net/assets/"
    params = {'restype': 'container', 'comp': 'list'}
    
    print("[*] Fetching Azure Blob Storage directory...")
    response = requests.get(url, params=params)
    
    if response.status_code != 200:
        print(f"[-] Failed: {response.status_code}")
        return
    
    content = response.text
    
    # Save raw response
    with open('azure_raw.xml', 'w') as f:
        f.write(content)
    
    print(f"[+] Raw response saved ({len(content)} bytes)")
    
    # Simple regex parsing - count blobs
    blobs = re.findall(r'<Blob>', content)
    print(f"[+] Found {len(blobs)} <Blob> tags")
    
    # Extract file names
    file_names = re.findall(r'<Name>(.*?)</Name>', content)
    print(f"[+] Found {len(file_names)} file names")
    
    # Display first 10 files
    print("\n[*] Sample files found:")
    for i, name in enumerate(file_names[:20]):
        print(f"  {i+1}. {name}")
    
    # Create summary
    summary = {
        'timestamp': datetime.now().isoformat(),
        'url': url,
        'total_files': len(file_names),
        'sample_files': file_names[:20],
        'file_count_by_type': {
            'pdf': len([f for f in file_names if '.pdf' in f.lower()]),
            'image': len([f for f in file_names if any(ext in f.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif'])]),
            'document': len([f for f in file_names if any(ext in f.lower() for ext in ['.doc', '.docx', '.txt'])]),
            'archive': len([f for f in file_names if any(ext in f.lower() for ext in ['.zip', '.tar', '.gz'])]),
        }
    }
    
    # Save summary
    with open('azure_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n[+] Summary saved to azure_summary.json")
    print(f"[+] Total files: {len(file_names)}")
    print(f"[+] PDF files: {summary['file_count_by_type']['pdf']}")
    print(f"[+] Image files: {summary['file_count_by_type']['image']}")

if __name__ == "__main__":
    parse_azure_blob()
