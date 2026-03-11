
"""
WHOIS Detective - Advanced Domain Investigation Tool

"""
import argparse
import json
import csv
import yaml
import sys
import os
import socket
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import hashlib
import concurrent.futures
from pathlib import Path
import dns.resolver
import requests
from urllib.parse import urlparse
import ipaddress


# CONFIGURATION MANAGER
# =====================

class ConfigManager:
    """Manage tool configuration and API keys"""
    
    DEFAULT_CONFIG = {
        'whois': {
            'timeout': 10,
            'max_retries': 3,
            'rate_limit_delay': 1.0,
            'default_format': 'human'
        },
        'investigation': {
            'max_related_domains': 50,
            'historical_days': 365,
            'concurrent_workers': 5
        },
        'output': {
            'default_dir': './whois_reports',
            'auto_timestamp': True,
            'save_raw_data': False
        },
        'apis': {
            'whoisxml': None,
            'securitytrails': None,
            'virustotal': None,
            'shodan': None
        },
        'privacy': {
            'use_tor': False,
            'proxy': None,
            'random_user_agent': True
        }
    }
    
    def __init__(self, config_path: str = '~/.whois_detective.yaml'):
        self.config_path = os.path.expanduser(config_path)
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                loaded = yaml.safe_load(f) or {}
        else:
            loaded = {}
        
        # Merge with defaults
        config = self.DEFAULT_CONFIG.copy()
        self.deep_update(config, loaded)
        return config
    
    def deep_update(self, base: Dict, update: Dict):
        """Recursively update nested dictionary"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self.deep_update(base[key], value)
            else:
                base[key] = value
    
    def save_config(self):
        """Save configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def get(self, key: str, default=None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()


# CORE WHOIS ENGINE
# =================

class WhoisEngine:
    """Core WHOIS lookup engine without external libraries"""
    
    # Enhanced TLD database
    TLD_SERVERS = {
        # Generic TLDs
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        
        # Country codes
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'jp': 'whois.jprs.jp',
        'cn': 'whois.cnnic.cn',
        'ru': 'whois.tcinet.ru',
        'br': 'whois.registro.br',
        'in': 'whois.registry.in',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
        'mx': 'whois.mx',
        
        # New gTLDs
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
        'blog': 'whois.nic.google',
        'shop': 'whois.nic.shop',
        'site': 'whois.nic.site',
        'online': 'whois.nic.online',
    }
    
    # Response field mappings for different registries
    FIELD_PATTERNS = {
        'common': {
            'domain_name': r'Domain Name:\s*(.+)',
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)|Created On:\s*(.+)',
            'expiration_date': r'Expir(ation|y) Date:\s*(.+)|Registry Expiry Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)|Last Updated On:\s*(.+)',
            'name_server': r'Name Server:\s*(.+)|nserver:\s*(.+)',
            'status': r'Status:\s*(.+)',
        },
        'verisign': {
            'domain_name': r'Domain Name:\s*(.+)',
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Registry Expiry Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'name_server': r'Name Server:\s*(.+)',
        },
        'denic': {
            'domain_name': r'domain:\s*(.+)',
            'changed': r'changed:\s*(.+)',
            'name_server': r'nserver:\s*(.+)',
        }
    }
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.cache = {}
        self.request_count = 0
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Implement rate limiting"""
        delay = self.config.get('whois.rate_limit_delay', 1.0)
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request_time = time.time()
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain input"""
        domain = domain.lower().strip()
        
        # Remove protocols and www
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        
        # Remove path and query strings
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]
        
        # Validate domain format
        if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$', domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        return domain
    
    def _get_whois_server(self, tld: str) -> str:
        """Determine WHOIS server for TLD"""
        if tld in self.TLD_SERVERS:
            return self.TLD_SERVERS[tld]
        
        # Try IANA for unknown TLDs
        return 'whois.iana.org'
    
    def _query_server(self, query: str, server: str, port: int = 43) -> str:
        """Execute raw WHOIS query"""
        self._rate_limit()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.get('whois.timeout', 10))
            sock.connect((server, port))
            
            # WHOIS protocol requires CRLF
            sock.send(f"{query}\r\n".encode('utf-8'))
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            
            raw_response = response.decode('utf-8', errors='ignore')
            self.request_count += 1
            
            # Check for referral
            if server == 'whois.iana.org':
                referral_match = re.search(r'whois:\s*(\S+)', raw_response, re.IGNORECASE)
                if referral_match:
                    referral_server = referral_match.group(1)
                    print(f"  ↳ Referred to {referral_server}")
                    return self._query_server(query, referral_server, port)
            
            return raw_response
            
        except socket.timeout:
            raise Exception(f"Timeout connecting to {server}")
        except ConnectionRefusedError:
            raise Exception(f"Connection refused by {server}")
        except Exception as e:
            raise Exception(f"WHOIS query failed: {str(e)}")
    
    def _parse_response(self, raw_response: str, tld: str) -> Dict:
        """Parse WHOIS response based on TLD patterns"""
        result = {'raw': raw_response, 'parsed': {}}
        lines = raw_response.split('\n')
        
        # Select patterns based on TLD
        patterns = self.FIELD_PATTERNS.get('common', {}).copy()
        if tld in ['de']:
            patterns.update(self.FIELD_PATTERNS.get('denic', {}))
        
        name_servers = []
        contacts = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('%', '#', '>>>')):
                continue
            
            # Try each pattern
            for field_name, pattern in patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Extract value from appropriate capture group
                    groups = [g for g in match.groups() if g]
                    if groups:
                        value = groups[0].strip()
                        
                        if field_name == 'name_server':
                            name_servers.append(value.lower())
                        elif field_name in ['registrant', 'admin', 'tech']:
                            contacts.append({field_name: value})
                        else:
                            result['parsed'][field_name] = value
                    break
            
            # Additional parsing for contact info
            contact_patterns = [
                (r'Registrant (?:Name|Organization):\s*(.+)', 'registrant'),
                (r'Admin (?:Name|Organization):\s*(.+)', 'admin'),
                (r'Tech (?:Name|Organization):\s*(.+)', 'tech'),
                (r'Registrant Email:\s*(.+)', 'registrant_email'),
                (r'Admin Email:\s*(.+)', 'admin_email'),
                (r'Tech Email:\s*(.+)', 'tech_email'),
            ]
            
            for pattern, field in contact_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    result['parsed'][field] = match.group(1).strip()
        
        # Deduplicate and sort name servers
        if name_servers:
            result['parsed']['name_servers'] = sorted(set(name_servers))
        
        # Extract additional metadata
        result['metadata'] = {
            'response_lines': len(lines),
            'has_redacted_data': any(x in raw_response.lower() for x in ['redacted', 'privacy', 'data masked']),
            'contains_contact_info': any(key in result['parsed'] for key in ['registrant', 'admin', 'tech']),
        }
        
        return result
    
    def lookup(self, domain: str, use_cache: bool = True) -> Dict:
        """Main WHOIS lookup method"""
        try:
            domain = self._clean_domain(domain)
            
            # Check cache
            cache_key = hashlib.md5(domain.encode()).hexdigest()
            if use_cache and cache_key in self.cache:
                print(f"  ↳ Using cached data for {domain}")
                return self.cache[cache_key]
            
            print(f"[*] Investigating: {domain}")
            
            # Extract TLD
            tld = domain.split('.')[-1]
            print(f"  ↳ TLD: .{tld}")
            
            # Get WHOIS server
            whois_server = self._get_whois_server(tld)
            print(f"  ↳ WHOIS Server: {whois_server}")
            
            # Perform query
            print(f"  ↳ Querying...", end='', flush=True)
            raw_response = self._query_server(domain, whois_server)
            print(f" ✓")
            
            # Parse response
            print(f"  ↳ Parsing response...", end='', flush=True)
            result = self._parse_response(raw_response, tld)
            print(f" ✓")
            
            # Add investigation metadata
            result['investigation'] = {
                'domain': domain,
                'tld': tld,
                'whois_server': whois_server,
                'query_timestamp': datetime.now().isoformat(),
                'tool_version': 'WHOIS Detective v1.0',
                'lookup_duration': f"{time.time() - self.last_request_time:.2f}s",
                'request_id': cache_key[:8],
            }
            
            # Cache result
            self.cache[cache_key] = result
            
            return result
            
        except Exception as e:
            return {
                'error': str(e),
                'domain': domain,
                'timestamp': datetime.now().isoformat()
            }


# INVESTIGATION TOOLS
# ===================

class InvestigationTools:
    """Advanced investigation tools for domain analysis"""
    
    def __init__(self, whois_engine: WhoisEngine):
        self.whois = whois_engine
    
    def bulk_investigate(self, domains_file: str, output_format: str = 'json') -> Dict:
        """Investigate multiple domains from file"""
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Investigating {len(domains)} domains...")
        
        results = {}
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.whois.config.get('investigation.concurrent_workers', 5)
        ) as executor:
            future_to_domain = {
                executor.submit(self.whois.lookup, domain): domain 
                for domain in domains
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                    print(f"  ✓ {domain}")
                except Exception as e:
                    results[domain] = {'error': str(e)}
                    print(f"  ✗ {domain}: {str(e)}")
        
        return results
    
    def find_related_domains(self, domain: str, max_results: int = 20) -> List[Dict]:
        """Find domains with similar WHOIS patterns"""
        primary_result = self.whois.lookup(domain)
        
        if 'error' in primary_result:
            return []
        
        # Extract patterns for matching
        patterns = self._extract_patterns(primary_result)
        related = []
        
        # This would integrate with external APIs in real implementation
        print(f"[*] Finding domains with similar patterns...")
        
        return related
    
    def historical_analysis(self, domain: str, days_back: int = 365) -> List[Dict]:
        """Analyze historical WHOIS records"""
        print(f"[*] Checking historical records for {domain} (last {days_back} days)")
        
        # This requires external API integration
        history = []
        
        # Placeholder for API integration
        print(f"  [!] Historical data requires API key (whoisxmlapi.com, securitytrails.com)")
        
        return history
    
    def footprint_analysis(self, domain: str) -> Dict:
        """Analyze digital footprint of domain"""
        print(f"[*] Analyzing digital footprint for {domain}")
        
        footprint = {
            'domain': domain,
            'whois': self.whois.lookup(domain),
            'dns': self._get_dns_records(domain),
            'http_headers': self._get_http_headers(domain),
            'associated_ips': self._find_associated_ips(domain),
            'ssl_certificate': self._get_ssl_info(domain),
        }
        
        return footprint
    
    def _extract_patterns(self, whois_data: Dict) -> Dict:
        """Extract patterns for domain correlation"""
        patterns = {}
        
        parsed = whois_data.get('parsed', {})
        
        # Email patterns
        emails = []
        for key in ['registrant_email', 'admin_email', 'tech_email']:
            if key in parsed and parsed[key]:
                emails.append(parsed[key])
        
        if emails:
            patterns['email_domains'] = list(set([email.split('@')[-1] for email in emails]))
        
        # Name server patterns
        if 'name_servers' in parsed:
            patterns['name_server_patterns'] = [
                ns.split('.')[-2] if '.' in ns else ns 
                for ns in parsed['name_servers']
            ]
        
        # Registrar patterns
        if 'registrar' in parsed:
            patterns['registrar'] = parsed['registrar']
        
        return patterns
    
    def _get_dns_records(self, domain: str) -> Dict:
        """Get various DNS records"""
        records = {}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                records['a'] = [str(r) for r in answers]
            except:
                records['a'] = []
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                records['mx'] = [str(r.exchange) for r in answers]
            except:
                records['mx'] = []
            
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                records['txt'] = [str(r) for r in answers]
            except:
                records['txt'] = []
            
        except Exception as e:
            records['error'] = str(e)
        
        return records
    
    def _get_http_headers(self, domain: str) -> Dict:
        """Get HTTP headers"""
        headers = {}
        
        try:
            url = f"http://{domain}"
            response = requests.get(url, timeout=5, allow_redirects=True)
            headers = dict(response.headers)
        except:
            pass
        
        return headers
    
    def _find_associated_ips(self, domain: str) -> List[str]:
        """Find IP addresses associated with domain"""
        ips = []
        
        try:
            # Get A records
            answers = dns.resolver.resolve(domain, 'A')
            ips.extend([str(r) for r in answers])
            
            # Check for CDN/cloud indicators
            for ip in ips:
                try:
                    # Reverse DNS
                    hostname = socket.gethostbyaddr(ip)[0]
                    if any(cdn in hostname.lower() for cdn in ['cloudflare', 'akamai', 'cloudfront', 'fastly']):
                        ips.append(f"{ip} (CDN: {hostname})")
                except:
                    pass
        except:
            pass
        
        return list(set(ips))
    
    def _get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information (placeholder)"""
        return {'note': 'SSL info requires additional libraries (pyOpenSSL)'}


# OUTPUT FORMATTERS
# ================

class OutputFormatter:
    """Format investigation results for different outputs"""
    
    @staticmethod
    def to_json(data: Dict, indent: int = 2) -> str:
        """Convert to JSON format"""
        return json.dumps(data, indent=indent, default=str)
    
    @staticmethod
    def to_csv(data: Dict, filename: str):
        """Convert to CSV format"""
        if isinstance(data, dict) and 'parsed' in data:
            # Single result
            rows = [data]
        elif isinstance(data, dict):
            # Multiple results
            rows = list(data.values())
        else:
            rows = data
        
        if not rows:
            return
        
        # Extract all possible fields
        all_fields = set()
        for row in rows:
            if 'parsed' in row:
                all_fields.update(row['parsed'].keys())
        
        fieldnames = ['domain'] + list(all_fields)
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in rows:
                if 'investigation' in row:
                    domain = row['investigation'].get('domain', 'unknown')
                else:
                    domain = 'unknown'
                
                output_row = {'domain': domain}
                if 'parsed' in row:
                    output_row.update(row['parsed'])
                
                writer.writerow(output_row)
    
    @staticmethod
    def to_markdown(data: Dict) -> str:
        """Convert to markdown report"""
        if 'error' in data:
            return f"# WHOIS Lookup Error\n\n**Domain:** {data.get('domain', 'Unknown')}\n\n**Error:** {data['error']}"
        
        parsed = data.get('parsed', {})
        investigation = data.get('investigation', {})
        
        md = f"""# WHOIS Investigation Report

## Domain: {investigation.get('domain', 'Unknown')}

### Registration Information

| Field | Value |
|-------|-------|
| **Domain** | {parsed.get('domain_name', 'N/A')} |
| **Registrar** | {parsed.get('registrar', 'N/A')} |
| **Created** | {parsed.get('creation_date', 'N/A')} |
| **Expires** | {parsed.get('expiration_date', 'N/A')} |
| **Updated** | {parsed.get('updated_date', 'N/A')} |
| **Status** | {parsed.get('status', 'N/A')} |

"""
        
        # Name servers
        if 'name_servers' in parsed:
            md += "\n### Name Servers\n\n"
            for ns in parsed['name_servers']:
                md += f"* `{ns}`\n"
        
        # Contact information
        contacts = []
        for key in ['registrant', 'admin', 'tech', 'registrant_email', 'admin_email', 'tech_email']:
            if key in parsed:
                contacts.append((key.replace('_', ' ').title(), parsed[key]))
        
        if contacts:
            md += "\n### Contact Information\n\n"
            for label, value in contacts:
                md += f"* **{label}:** {value}\n"
        
        # Metadata
        md += f"\n### Investigation Metadata\n\n"
        md += f"* **Investigation ID:** {investigation.get('request_id', 'N/A')}\n"
        md += f"* **Query Time:** {investigation.get('query_timestamp', 'N/A')}\n"
        md += f"* **WHOIS Server:** {investigation.get('whois_server', 'N/A')}\n"
        md += f"* **Tool:** {investigation.get('tool_version', 'N/A')}\n"
        
        return md
    
    @staticmethod
    def to_table(data: Dict) -> str:
        """Convert to ASCII table"""
        parsed = data.get('parsed', {})
        
        table = []
        table.append("=" * 60)
        table.append(f"WHOIS RESULTS: {data.get('investigation', {}).get('domain', 'Unknown')}")
        table.append("=" * 60)
        
        # Key fields
        key_fields = [
            ('Domain Name', 'domain_name'),
            ('Registrar', 'registrar'),
            ('Creation Date', 'creation_date'),
            ('Expiration Date', 'expiration_date'),
            ('Updated Date', 'updated_date'),
            ('Status', 'status'),
        ]
        
        for label, key in key_fields:
            if key in parsed:
                table.append(f"{label:20} : {parsed[key]}")
        
        # Name servers
        if 'name_servers' in parsed:
            table.append(f"\nName Servers ({len(parsed['name_servers'])}):")
            for ns in parsed['name_servers'][:5]:  # Show first 5
                table.append(f"  • {ns}")
            if len(parsed['name_servers']) > 5:
                table.append(f"  ... and {len(parsed['name_servers']) - 5} more")
        
        table.append("=" * 60)
        
        return "\n".join(table)


# MAIN CLI APPLICATION
# ===================

class WhoisDetectiveCLI:
    """Main CLI application"""
    
    def __init__(self):
        self.config = ConfigManager()
        self.whois_engine = WhoisEngine(self.config)
        self.investigation = InvestigationTools(self.whois_engine)
        self.formatter = OutputFormatter()
        
    def setup_argparse(self) -> argparse.ArgumentParser:
        """Setup command line argument parser"""
        parser = argparse.ArgumentParser(
            description='WHOIS Detective - Advanced Domain Investigation Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s whois example.com
  %(prog)s whois example.com --json --output result.json
  %(prog)s bulk domains.txt --format csv --output report.csv
  %(prog)s footprint example.com --full
  %(prog)s config --set api.whoisxml YOUR_API_KEY
            
Investigation Commands:
  whois        Basic WHOIS lookup
  bulk         Process multiple domains from file
  footprint    Full digital footprint analysis
  history      Historical WHOIS data (requires API)
  search       Search domains by keyword
  monitor      Monitor domain for changes
            
Utility Commands:
  config       Manage configuration and API keys
  export       Export data to different formats
  validate     Validate domain/TLD format
  stats        Generate statistics from results
            """
        )
        
        # Subparsers for different commands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # WHOIS command
        whois_parser = subparsers.add_parser('whois', help='WHOIS lookup')
        whois_parser.add_argument('domain', help='Domain to investigate')
        whois_parser.add_argument('--json', action='store_true', help='Output in JSON format')
        whois_parser.add_argument('--csv', action='store_true', help='Output in CSV format')
        whois_parser.add_argument('--md', '--markdown', action='store_true', help='Output in Markdown format')
        whois_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output with raw data')
        whois_parser.add_argument('--output', '-o', help='Output file path')
        whois_parser.add_argument('--no-cache', action='store_true', help='Disable caching')
        
        # Bulk command
        bulk_parser = subparsers.add_parser('bulk', help='Bulk domain investigation')
        bulk_parser.add_argument('file', help='File containing domains (one per line)')
        bulk_parser.add_argument('--format', choices=['json', 'csv', 'md'], default='json', help='Output format')
        bulk_parser.add_argument('--output', '-o', help='Output file path')
        bulk_parser.add_argument('--workers', '-w', type=int, default=5, help='Number of concurrent workers')
        
        # Footprint command
        footprint_parser = subparsers.add_parser('footprint', help='Digital footprint analysis')
        footprint_parser.add_argument('domain', help='Domain to analyze')
        footprint_parser.add_argument('--full', action='store_true', help='Full analysis with external APIs')
        footprint_parser.add_argument('--output', '-o', help='Output file path')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help='Set configuration value')
        config_parser.add_argument('--get', metavar='KEY', help='Get configuration value')
        config_parser.add_argument('--list', action='store_true', help='List all configuration')
        config_parser.add_argument('--reset', action='store_true', help='Reset to defaults')
        
        # Export command
        export_parser = subparsers.add_parser('export', help='Export data')
        export_parser.add_argument('file', help='Input file to export')
        export_parser.add_argument('--format', choices=['json', 'csv', 'md', 'html'], default='json', help='Export format')
        export_parser.add_argument('--output', '-o', help='Output file path')
        
        # Validate command
        validate_parser = subparsers.add_parser('validate', help='Validate domain/TLD')
        validate_parser.add_argument('domain', help='Domain to validate')
        validate_parser.add_argument('--check-tld', action='store_true', help='Check TLD validity')
        
        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Generate statistics')
        stats_parser.add_argument('file', help='Results file to analyze')
        stats_parser.add_argument('--output', '-o', help='Output file path')
        
        return parser
    
    def run(self):
        """Main entry point"""
        parser = self.setup_argparse()
        
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)
        
        args = parser.parse_args()
        
        # Create output directory if needed
        output_dir = self.config.get('output.default_dir', './whois_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            if args.command == 'whois':
                self.handle_whois(args)
            elif args.command == 'bulk':
                self.handle_bulk(args)
            elif args.command == 'footprint':
                self.handle_footprint(args)
            elif args.command == 'config':
                self.handle_config(args)
            elif args.command == 'export':
                self.handle_export(args)
            elif args.command == 'validate':
                self.handle_validate(args)
            elif args.command == 'stats':
                self.handle_stats(args)
            else:
                parser.print_help()
                
        except KeyboardInterrupt:
            print("\n\n[!] Investigation interrupted by user")
            sys.exit(130)
        except Exception as e:
            print(f"\n[!] Error: {str(e)}")
            sys.exit(1)
    
    def handle_whois(self, args):
        """Handle WHOIS command"""
        result = self.whois_engine.lookup(args.domain, use_cache=not args.no_cache)
        
        # Determine output format
        if args.json:
            output = self.formatter.to_json(result)
        elif args.csv:
            output_file = args.output or f"{output_dir}/{args.domain.replace('.', '_')}.csv"
            self.formatter.to_csv(result, output_file)
            print(f"[+] Results saved to {output_file}")
            return
        elif args.md:
            output = self.formatter.to_markdown(result)
        else:
            output = self.formatter.to_table(result)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"[+] Results saved to {args.output}")
        else:
            print(output)
        
        # Show raw data if verbose
        if args.verbose and 'raw' in result:
            print(f"\n{'='*60}")
            print("RAW WHOIS RESPONSE:")
            print('='*60)
            print(result['raw'][:2000])  # First 2000 chars
    
    def handle_bulk(self, args):
        """Handle bulk investigation"""
        self.whois_engine.config.set('investigation.concurrent_workers', args.workers)
        
        results = self.investigation.bulk_investigate(args.file)
        
        # Generate output file name
        if args.output:
            output_file = args.output
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"{output_dir}/bulk_investigation_{timestamp}.{args.format}"
        
        # Save results
        if args.format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif args.format == 'csv':
            self.formatter.to_csv(results, output_file)
        elif args.format == 'md':
            with open(output_file, 'w') as f:
                f.write(f"# Bulk Domain Investigation Report\n\n")
                f.write(f"**Generated:** {datetime.now().isoformat()}\n")
                f.write(f"**Total Domains:** {len(results)}\n\n")
                
                for domain, result in results.items():
                    if 'error' in result:
                        f.write(f"## {domain} - ERROR\n\n")
                        f.write(f"Error: {result['error']}\n\n")
                    else:
                        f.write(self.formatter.to_markdown(result))
                        f.write("\n---\n\n")
        
        print(f"\n[+] Bulk investigation complete!")
        print(f"[+] Results saved to: {output_file}")
        
        # Show summary
        successful = sum(1 for r in results.values() if 'error' not in r)
        print(f"[+] Successful: {successful}/{len(results)}")
        print(f"[+] Failed: {len(results) - successful}")
    
    def handle_footprint(self, args):
        """Handle footprint analysis"""
        print(f"[*] Starting footprint analysis for {args.domain}")
        print(f"[*] This may take a few moments...\n")
        
        footprint = self.investigation.footprint_analysis(args.domain)
        
        # Generate output
        if args.output:
            output_file = args.output
        else:
            output_file = f"{output_dir}/footprint_{args.domain.replace('.', '_')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(footprint, f, indent=2, default=str)
        
        print(f"\n[+] Footprint analysis complete!")
        print(f"[+] Results saved to: {output_file}")
        
        # Show brief summary
        print(f"\n=== FOOTPRINT SUMMARY ===")
        print(f"Domain: {args.domain}")
        
        if 'whois' in footprint and 'parsed' in footprint['whois']:
            whois_data = footprint['whois']['parsed']
            print(f"Registrar: {whois_data.get('registrar', 'N/A')}")
            print(f"Created: {whois_data.get('creation_date', 'N/A')}")
        
        if 'dns' in footprint:
            dns_data = footprint['dns']
            print(f"A Records: {len(dns_data.get('a', []))}")
            print(f"MX Records: {len(dns_data.get('mx', []))}")
        
        if 'associated_ips' in footprint:
            print(f"Associated IPs: {len(footprint['associated_ips'])}")
    
    def handle_config(self, args):
        """Handle configuration commands"""
        if args.set:
            key, value = args.set
            self.config.set(key, value)
            print(f"[✓] Configuration updated: {key} = {value}")
        
        elif args.get:
            value = self.config.get(args.get)
            print(f"{args.get} = {value}")
        
        elif args.list:
            print(yaml.dump(self.config.config, default_flow_style=False))
        
        elif args.reset:
            self.config.config = self.config.DEFAULT_CONFIG.copy()
            self.config.save_config()
            print("[✓] Configuration reset to defaults")
        
        else:
            # Show current config location
            print(f"Configuration file: {self.config.config_path}")
            print(f"\nCurrent settings:")
            for section, values in self.config.config.items():
                print(f"\n[{section.upper()}]")
                for key, value in values.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            print(f"  {key}.{subkey}: {subvalue}")
                    else:
                        print(f"  {key}: {value}")
    
    def handle_export(self, args):
        """Handle export command"""
        with open(args.file, 'r') as f:
            data = json.load(f)
        
        if args.output:
            output_file = args.output
        else:
            base = os.path.splitext(args.file)[0]
            output_file = f"{base}.{args.format}"
        
        if args.format == 'json':
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        elif args.format == 'csv':
            self.formatter.to_csv(data, output_file)
        elif args.format == 'md':
            content = self.formatter.to_markdown(data)
            with open(output_file, 'w') as f:
                f.write(content)
        
        print(f"[+] Exported to: {output_file}")
    
    def handle_validate(self, args):
        """Handle domain validation"""
        domain = args.domain.lower().strip()
        
        # Basic domain validation regex
        pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$'
        
        if re.match(pattern, domain):
            print(f"[✓] Valid domain format: {domain}")
            
            # Check TLD
            tld = domain.split('.')[-1]
            if tld in self.whois_engine.TLD_SERVERS:
                print(f"[✓] Known TLD: .{tld}")
                print(f"    WHOIS server: {self.whois_engine.TLD_SERVERS[tld]}")
            else:
                print(f"[!] Unknown TLD: .{tld}")
                print(f"    Will use IANA WHOIS server")
            
            # Try to resolve
            try:
                socket.gethostbyname(domain)
                print(f"[✓] Domain resolves to an IP address")
            except:
                print(f"[!] Domain does not resolve (may be parked or inactive)")
        
        else:
            print(f"[✗] Invalid domain format: {domain}")
            print(f"    Expected format: example.com")
    
    def handle_stats(self, args):
        """Handle statistics generation"""
        with open(args.file, 'r') as f:
            data = json.load(f)
        
        stats = {
            'total_domains': 0,
            'successful_lookups': 0,
            'failed_lookups': 0,
            'registrars': {},
            'tlds': {},
            'creation_years': {},
        }
        
        if isinstance(data, dict):
            results = data.values() if len(data) > 1 else [data]
        else:
            results = data
        
        for result in results:
            stats['total_domains'] += 1
            
            if 'error' in result:
                stats['failed_lookups'] += 1
                continue
            
            stats['successful_lookups'] += 1
            
            # Analyze registrar
            if 'parsed' in result and 'registrar' in result['parsed']:
                registrar = result['parsed']['registrar']
                stats['registrars'][registrar] = stats['registrars'].get(registrar, 0) + 1
            
            # Analyze TLD
            if 'investigation' in result and 'tld' in result['investigation']:
                tld = result['investigation']['tld']
                stats['tlds'][tld] = stats['tlds'].get(tld, 0) + 1
            
            # Analyze creation year
            if 'parsed' in result and 'creation_date' in result['parsed']:
                date_str = result['parsed']['creation_date']
                year_match = re.search(r'(\d{4})', date_str)
                if year_match:
                    year = year_match.group(1)
                    stats['creation_years'][year] = stats['creation_years'].get(year, 0) + 1
        
        # Generate report
        report = f"""# Investigation Statistics

## Summary
- **Total Domains Analyzed:** {stats['total_domains']}
- **Successful Lookups:** {stats['successful_lookups']}
- **Failed Lookups:** {stats['failed_lookups']}
- **Success Rate:** {(stats['successful_lookups']/stats['total_domains']*100):.1f}%

## Top Registrars
{self._format_top_items(stats['registrars'])}

## Top TLDs
{self._format_top_items(stats['tlds'])}

## Creation Years
{self._format_top_items(stats['creation_years'])}

## Analysis Date
{datetime.now().isoformat()}
"""
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"[+] Statistics saved to: {args.output}")
        else:
            print(report)
    
    def _format_top_items(self, items: Dict, limit: int = 10) -> str:
        """Format top items for statistics"""
        sorted_items = sorted(items.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        lines = []
        for item, count in sorted_items:
            percentage = (count / sum(items.values())) * 100
            lines.append(f"- {item}: {count} ({percentage:.1f}%)")
        
        return "\n".join(lines)



# MAIN EXECUTION
# ==============

def main():
    """Main entry point"""
    print("""
                 ^═══════════════^
                  WHOIS DETECTIVE    
              ____     <_>             ._.  
             / ___|    | |__   ___  ___| |_ 
            | |  _ ____| |_ \ / _ \/ __| __| 
            | |_| |____| | | | (_) \__ \ |_ 
             \____|    |_| |_|\___/|___/\__| v1.0
                
           Advanced Domain Investigation Tool  
                 By:Yashwanth        
          <═════════════════════════════════>
          admin:RudraDeva
          mail :saiyashwanthpro@proton.me
            
    """)
    
    # Check for installation mode
    if len(sys.argv) > 1 and sys.argv[1] == '--install':
        create_install_script()
        return
    
    # Run CLI
    cli = WhoisDetectiveCLI()
    cli.run()

if __name__ == '__main__':
    main()
