#!/usr/bin/env python3
"""
VirusTotal Complete File & IOC Scanner
Combines file scanning, hash checking, URL verification, and IP reputation
Author: D1sCript
GitHub: https://github.com/D1sCript/vt-complete-scanner
"""

import os
import sys
import csv
import hashlib
import argparse
import requests
from datetime import datetime
from pathlib import Path

# ⚠️ IMPORTANT: Insert your VirusTotal API key here!
API_KEY = "INSERT_YOUR_API_KEY_HERE"

# VirusTotal API endpoints
VT_FILE_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VT_IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses"

# Headers for API
HEADERS = {
    "x-apikey": API_KEY
}

class VTScanner:
    def __init__(self):
        self.results = []
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        
    def calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, SHA256 for a file"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except Exception as e:
            print(f"   ❌ Error calculating hashes for {file_path}: {e}")
            return None

    def check_file_hash(self, hash_value):
        """Check file hash on VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()['data']
                stats = data['attributes']['last_analysis_stats']
                return {
                    'type': 'HASH',
                    'value': hash_value,
                    'detections': stats['malicious'],
                    'total': sum(stats.values()),
                    'category': data['attributes'].get('type_tag', 'Unknown'),
                    'last_analysis': data['attributes'].get('last_analysis_date', 'Never'),
                    'risk': self.determine_risk(stats['malicious'])
                }
            else:
                return {
                    'type': 'HASH',
                    'value': hash_value,
                    'detections': 0,
                    'total': 0,
                    'category': 'Not Found',
                    'last_analysis': 'Never',
                    'risk': 'CLEAN'
                }
        except Exception as e:
            print(f"   ❌ Error checking hash {hash_value}: {e}")
            return None

    def check_url(self, url_value):
        """Check URL on VirusTotal"""
        try:
            url_id = self.url_to_id(url_value)
            response = self.session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                stats = data['attributes']['last_analysis_stats']
                return {
                    'type': 'URL',
                    'value': url_value,
                    'detections': stats['malicious'],
                    'total': sum(stats.values()),
                    'category': data['attributes'].get('categories', {}).get('Google Safebrowsing', 'Unknown'),
                    'last_analysis': data['attributes'].get('last_analysis_date', 'Never'),
                    'risk': self.determine_risk(stats['malicious'])
                }
            else:
                return {
                    'type': 'URL',
                    'value': url_value,
                    'detections': 0,
                    'total': 0,
                    'category': 'Not Found',
                    'last_analysis': 'Never',
                    'risk': 'CLEAN'
                }
        except Exception as e:
            print(f"   ❌ Error checking URL {url_value}: {e}")
            return None

    def check_ip(self, ip_value):
        """Check IP on VirusTotal"""
        try:
            response = self.session.get(f"{VT_IP_ENDPOINT}/{ip_value}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()['data']
                stats = data['attributes']['last_analysis_stats']
                return {
                    'type': 'IP',
                    'value': ip_value,
                    'detections': stats['malicious'],
                    'total': sum(stats.values()),
                    'category': data['attributes'].get('country', 'Unknown'),
                    'last_analysis': data['attributes'].get('last_analysis_date', 'Never'),
                    'risk': self.determine_risk(stats['malicious'])
                }
            else:
                return {
                    'type': 'IP',
                    'value': ip_value,
                    'detections': 0,
                    'total': 0,
                    'category': 'Unknown',
                    'last_analysis': 'Never',
                    'risk': 'CLEAN'
                }
        except Exception as e:
            print(f"   ❌ Error checking IP {ip_value}: {e}")
            return None

    def scan_folder(self, folder_path):
        """Recursively scan folder and check all files"""
        print(f"\n🔍 Scanning folder: {folder_path}")
        
        folder = Path(folder_path)
        if not folder.exists():
            print(f"❌ Folder not found: {folder_path}")
            return
        
        file_count = 0
        for file_path in folder.rglob('*'):
            if file_path.is_file():
                file_count += 1
                print(f"\n📄 [{file_count}] File: {file_path}")
                
                hashes = self.calculate_hashes(str(file_path))
                if hashes:
                    print(f"   MD5:    {hashes['md5']}")
                    print(f"   SHA256: {hashes['sha256']}")
                    
                    result = self.check_file_hash(hashes['sha256'])
                    if result:
                        self.display_result(result)
                        self.results.append(result)

    def scan_hashes(self, file_path):
        """Read hashes from file and check them"""
        try:
            with open(file_path, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
            
            print(f"\n🔍 Checking {len(hashes)} hashes...")
            for idx, hash_value in enumerate(hashes, 1):
                print(f"\n📋 [{idx}/{len(hashes)}] Hash: {hash_value}")
                result = self.check_file_hash(hash_value)
                if result:
                    self.display_result(result)
                    self.results.append(result)
        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")

    def scan_urls(self, file_path):
        """Read URLs from file and check them"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"\n🔍 Checking {len(urls)} URLs...")
            for idx, url in enumerate(urls, 1):
                print(f"\n🌐 [{idx}/{len(urls)}] URL: {url}")
                result = self.check_url(url)
                if result:
                    self.display_result(result)
                    self.results.append(result)
        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")

    def scan_ips(self, file_path):
        """Read IPs from file and check them"""
        try:
            with open(file_path, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"\n🔍 Checking {len(ips)} IPs...")
            for idx, ip in enumerate(ips, 1):
                print(f"\n🌍 [{idx}/{len(ips)}] IP: {ip}")
                result = self.check_ip(ip)
                if result:
                    self.display_result(result)
                    self.results.append(result)
        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")

    def display_result(self, result):
        """Display result with color coding"""
        risk = result['risk']
        
        if risk == 'MALICIOUS':
            icon = "🔴"
        elif risk == 'SUSPICIOUS':
            icon = "🟡"
        else:
            icon = "🟢"
        
        print(f"   {icon} Risk: {risk}")
        print(f"   Detections: {result['detections']}/{result['total']}")
        print(f"   Category: {result['category']}")
        print(f"   Last Analysis: {result['last_analysis']}")

    def determine_risk(self, malicious_count):
        """Determine risk level based on detections"""
        if malicious_count >= 10:
            return "MALICIOUS"
        elif malicious_count >= 3:
            return "SUSPICIOUS"
        else:
            return "CLEAN"

    def url_to_id(self, url):
        """Convert URL to VirusTotal ID"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

    def export_csv(self, output_file):
        """Export results to CSV"""
        if not self.results:
            print("❌ No results to export")
            return
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['Type', 'Value', 'Risk', 'Detections', 'Total', 'Category', 'Last Analysis'])
                writer.writeheader()
                
                for result in self.results:
                    writer.writerow({
                        'Type': result['type'],
                        'Value': result['value'],
                        'Risk': result['risk'],
                        'Detections': result['detections'],
                        'Total': result['total'],
                        'Category': result['category'],
                        'Last Analysis': result['last_analysis']
                    })
            
            print(f"\n✅ Results exported to: {output_file}")
        except Exception as e:
            print(f"❌ Error exporting results: {e}")

def main():
    if not API_KEY or API_KEY == "INSERT_YOUR_API_KEY_HERE":
        print("❌ VirusTotal API key not configured!")
        print("Please edit the script and replace API_KEY with your actual key")
        print("Get your free API key at: https://www.virustotal.com")
        sys.exit(1)
    
    # Argument parser
    parser = argparse.ArgumentParser(
        description='VirusTotal Complete Scanner - Check files, hashes, URLs, and IPs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE EXAMPLES:

1. Check IP addresses from file:
   python vt_scanner.py --check-ips ips.txt -o report.csv

2. Check file hashes from file:
   python vt_scanner.py --check-hashes hashes.txt -o report.csv

3. Check URLs from file:
   python vt_scanner.py --check-urls urls.txt -o report.csv

4. Scan folder recursively:
   python vt_scanner.py --scan-folder ./suspicious_files/ -o report.csv

5. Combined scan (all at once):
   python vt_scanner.py --scan-folder ./files/ --check-ips ips.txt --check-urls urls.txt -o full_report.csv

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INPUT FILE FORMAT:

IPs file (ips.txt):
    8.8.8.8
    1.1.1.1
    185.220.101.1

Hashes file (hashes.txt):
    5d41402abc4b2a76b9719d911017c592
    098f6bcd4621d373cade4e832627b4f6

URLs file (urls.txt):
    http://example.com
    https://suspicious-site.xyz

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RISK LEVELS:
  RED (🔴)     - MALICIOUS   - 10+ detections (immediate action required)
  YELLOW (🟡)  - SUSPICIOUS  - 3-9 detections (further investigation needed)
  GREEN (🟢)   - CLEAN       - 0-2 detections (likely safe)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SETUP:
  1. Get free API key: https://www.virustotal.com
  2. Replace API_KEY in this script with your actual key
  3. Install dependencies: pip install requests

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Author: D1sCript | GitHub: https://github.com/D1sCript/vt-complete-scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )
    
    parser.add_argument('--scan-folder', help='Recursively scan folder for files (hashes will be checked)')
    parser.add_argument('--check-hashes', help='Check hashes from file (one per line)')
    parser.add_argument('--check-urls', help='Check URLs from file (one per line)')
    parser.add_argument('--check-ips', help='Check IP addresses from file (one per line)')
    parser.add_argument('-o', '--output', help='Output CSV file with results')
    
    args = parser.parse_args()
    
    # Check if at least one action is specified
    if not any([args.scan_folder, args.check_hashes, args.check_urls, args.check_ips]):
        parser.print_help()
        sys.exit(1)
    
    scanner = VTScanner()
    
    print("=" * 70)
    print("VirusTotal Complete Scanner")
    print("=" * 70)
    
    # Execute selected operations
    if args.scan_folder:
        scanner.scan_folder(args.scan_folder)
    
    if args.check_hashes:
        scanner.scan_hashes(args.check_hashes)
    
    if args.check_urls:
        scanner.scan_urls(args.check_urls)
    
    if args.check_ips:
        scanner.scan_ips(args.check_ips)
    
    # Export if output file specified
    if args.output:
        scanner.export_csv(args.output)
    
    print("\n" + "=" * 70)
    print("Scan complete!")
    print("=" * 70)

if __name__ == "__main__":
    main()
