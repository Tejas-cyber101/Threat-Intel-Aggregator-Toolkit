import re
import json
import requests
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

class ProfessionalTIAggregator:
    def __init__(self):
        # [cite: 21, 32] Storage for normalized data
        self.indicators = []
        self.correlation_results = {}
        
        # [cite: 22, 53] Regex patterns for IOC parsing
        self.patterns = {
            'IP': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'Domain': r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b',
            'Hash_MD5': r'\b[a-fA-F0-9]{32}\b'
        }

    def fetch_feeds(self, feeds):
        """Step 1: Load Feeds [cite: 76, 90]"""
        for name, url in feeds.items():
            try:
                print(f"[*] Accessing Feed: {name}")
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                # Step 2 & 3: Parse and Normalize [cite: 92, 94]
                self.parse_and_normalize(name, response.text)
            except Exception as e:
                print(f"[!] Source Error ({name}): {e}")

    def parse_and_normalize(self, source, content):
        """[cite: 31, 67, 80] Cleaning and standardizing indicators"""
        for ioc_type, pattern in self.patterns.items():
            found = re.findall(pattern, content)
            for item in set(found): # Initial de-duplication
                self.indicators.append({
                    'value': item.lower(),
                    'type': ioc_type,
                    'source': source,
                    'timestamp': datetime.now().isoformat()
                })

    def run_correlation_engine(self):
        """Step 4: Correlation Engine [cite: 81, 96]"""
        counts = Counter(i['value'] for i in self.indicators)
        
        for i in self.indicators:
            val = i['value']
            if val not in self.correlation_results:
                freq = counts[val]
                # [cite: 36, 37] High risk if seen in multiple feeds
                severity = "High" if freq > 1 else "Medium"
                
                self.correlation_results[val] = {
                    'type': i['type'],
                    'severity': severity,
                    'hits': freq,
                    'sources': set()
                }
            self.correlation_results[val]['sources'].add(i['source'])

    def generate_deliverables(self):
        """Step 5 & 6: Blocklists, Reports, and Visuals [cite: 100, 121]"""
        # [cite: 40, 108] Generate Firewall Blocklist
        with open('blocklist_ips.txt', 'w') as f:
            for ioc, data in self.correlation_results.items():
                if data['type'] == 'IP' and data['severity'] == "High":
                    f.write(f"{ioc}\n")

        # [cite: 48, 109] Generate Final TI Report
        report = {
            "stats": {"unique_total": len(self.correlation_results)},
            "high_risk_alerts": [
                {"ioc": k, "type": v['type'], "sources": list(v['sources'])}
                for k, v in self.correlation_results.items() if v['severity'] == "High"
            ]
        }
        with open('final_threat_report.json', 'w') as f:
            json.dump(report, f, indent=4)

        #  Visual Dashboard for Presentation
        self.create_dashboard()

    def create_dashboard(self):
        """Generates a chart of IOC distribution for the presentation [cite: 127]"""
        types = [v['type'] for v in self.correlation_results.values()]
        type_counts = Counter(types)
        
        plt.figure(figsize=(10, 6))
        plt.bar(type_counts.keys(), type_counts.values(), color=['crimson', 'navy', 'forestgreen'])
        plt.title('Threat Intelligence Distribution (Aggregated)')
        plt.xlabel('IOC Type')
        plt.ylabel('Count')
        plt.savefig('ti_dashboard.png')
        print("[+] Dashboard saved as 'ti_dashboard.png'")

if __name__ == "__main__":
    # Real-world TI feeds 
    FEED_SOURCES = {
        "Emerging_Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "Binary_Defense": "https://www.binarydefense.com/banlist.txt",
        "Abuse_CH_Ransomware": "https://abuse.ch/downloads/ipblocklist.txt"
    }

    aggregator = ProfessionalTIAggregator()
    aggregator.fetch_feeds(FEED_SOURCES)
    aggregator.run_correlation_engine()
    aggregator.generate_deliverables()
