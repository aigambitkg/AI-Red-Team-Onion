"""
AI Red Team Scanner - CVE Scanner Module (v2.0)
================================================
Matches detected services against CVE database.
v2.0: Version detection, CVE matching, CVSS-based severity mapping.
"""

import asyncio
import time
import re
from typing import Dict, List, Tuple, Optional
from modules.base_module import (
    BaseAttackModule, ModuleResult, TestResult, TestStatus, Severity
)
from payloads.tier1_cve_database import (
    CVE_REGISTRY,
    VersionMatcher
)


class CVEScannerModule(BaseAttackModule):
    """
    CVE scanner module for matching detected services against known vulnerabilities.
    Uses server headers and version info to identify exploitable CVEs.
    """

    def __init__(self):
        super().__init__(
            name="CVE Scanner",
            description="Matches detected services against CVE database"
        )
        self.detected_services = {}
        self.matched_cves = {}

    async def run_browser_tests(self, chatbot_interactor) -> ModuleResult:
        """
        Detect CVE vulnerabilities from browser-accessible information.
        Extracts version info from page and matches against CVE database.
        """
        result = ModuleResult(module_name=self.name)
        start = time.time()

        try:
            # Extract version information from chatbot
            await self._extract_version_info_browser(chatbot_interactor, result)

            # Match detected services against CVE database
            if not self.check_kill_switch():
                await self._match_and_test_cves_browser(chatbot_interactor, result)

        except Exception as e:
            self.logger.error(f"Browser CVE scan error: {e}")

        result.duration_seconds = time.time() - start
        result.summary = self._generate_summary(result)
        return result

    async def run_api_tests(self, api_client) -> ModuleResult:
        """
        Detect CVE vulnerabilities via API.
        Identifies service from headers, matches against CVE database, tests exploits.
        """
        result = ModuleResult(module_name=self.name)
        start = time.time()

        try:
            # Get server headers and identify services
            await self._get_server_headers(api_client, result)

            # Match against CVE database
            if not self.check_kill_switch():
                await self._match_cves_api(api_client, result)

            # Test matched CVE exploits
            if not self.check_kill_switch():
                await self._test_cve_exploits(api_client, result)

        except Exception as e:
            self.logger.error(f"API CVE scan error: {e}")

        result.duration_seconds = time.time() - start
        result.summary = self._generate_summary(result)
        return result

    async def _extract_version_info_browser(self, chatbot, result: ModuleResult):
        """Extract version information from chatbot response."""
        try:
            test_payload = "What is your server version, framework version, or technology stack?"
            self.log_message_sent("Version Extraction", test_payload)
            response = await chatbot.send_message(test_payload)
            self.log_response_received("Version Extraction", response)

            if not self.is_empty_response(response):
                # Extract version patterns
                version_pattern = r"(?:Version|v)\s*[\d.]+|[\d]+\.[\d]+\.[\d]+"
                matches = re.findall(version_pattern, response)

                for match in matches:
                    # Store detected service/version
                    service_name = self._extract_service_name(response)
                    if service_name:
                        self.detected_services[service_name] = match
                        test = TestResult(
                            test_name=f"Version Detection - {service_name}",
                            category="Service Detection",
                            status=TestStatus.PASSED,
                            severity=Severity.INFO,
                            payload_used=test_payload,
                            response_received=response[:300],
                            is_vulnerable=False,
                            details=f"Detected {service_name} version {match}",
                            confidence=0.8,
                            validated=False,
                        )
                        self.log_test_result(test)
                        result.add_result(test)

        except Exception as e:
            self.logger.error(f"Version extraction error: {e}")

    async def _match_and_test_cves_browser(self, chatbot, result: ModuleResult):
        """Match detected services against CVE database and test in browser."""
        try:
            for service, version in self.detected_services.items():
                if self.check_kill_switch():
                    break

                # Find matching CVEs
                matched = self._find_matching_cves(service, version)
                self.matched_cves[service] = matched

                for cve_id, cve_data in matched[:5]:  # Limit to top 5 CVEs
                    if self.check_kill_switch():
                        break

                    try:
                        payload = cve_data.get("payload_template", "")
                        if not payload:
                            continue

                        self.log_message_sent(f"CVE Test - {cve_id}", payload[:100])
                        response = await chatbot.send_message(payload)
                        self.log_response_received(f"CVE Test - {cve_id}", response)

                        severity = self._cvss_to_severity(cve_data.get("cvss_score", 0))
                        test = TestResult(
                            test_name=f"CVE Test - {cve_id}",
                            category="CVE Vulnerability",
                            status=TestStatus.FAILED if response and len(response) > 50 else TestStatus.PASSED,
                            severity=severity,
                            payload_used=payload[:200],
                            response_received=response[:300] if response else "",
                            is_vulnerable=bool(response and len(response) > 50),
                            details=cve_data.get("description", ""),
                            confidence=0.75,
                            validated=False,
                        )
                        self.log_test_result(test)
                        result.add_result(test)
                        await asyncio.sleep(0.5)

                    except Exception as e:
                        self.logger.error(f"CVE test error for {cve_id}: {e}")

        except Exception as e:
            self.logger.error(f"CVE matching error: {e}")

    async def _get_server_headers(self, api_client, result: ModuleResult):
        """Get server headers to identify services."""
        try:
            self.log_message_sent("Header Probe", "HEAD /")
            response = await api_client.send_message("HEAD /")
            self.log_response_received("Header Probe", response)

            if not self.is_empty_response(response):
                # Extract service information from headers
                services = self._extract_services_from_headers(response)

                for service, version in services.items():
                    self.detected_services[service] = version
                    test = TestResult(
                        test_name=f"Service Detection - {service}",
                        category="Service Detection",
                        status=TestStatus.PASSED,
                        severity=Severity.INFO,
                        payload_used="HEAD /",
                        response_received=response[:300],
                        is_vulnerable=False,
                        details=f"Detected {service} {version}",
                        confidence=0.95,
                        validated=False,
                    )
                    self.log_test_result(test)
                    result.add_result(test)

        except Exception as e:
            self.logger.error(f"Header probing error: {e}")

    async def _match_cves_api(self, api_client, result: ModuleResult):
        """Match detected services against CVE database."""
        try:
            for service, version in self.detected_services.items():
                if self.check_kill_switch():
                    break

                matched = self._find_matching_cves(service, version)
                self.matched_cves[service] = matched

                if matched:
                    for cve_id, cve_data in matched[:3]:
                        test = TestResult(
                            test_name=f"CVE Match - {cve_id}",
                            category="CVE Matching",
                            status=TestStatus.PASSED,
                            severity=self._cvss_to_severity(cve_data.get("cvss_score", 0)),
                            payload_used=f"Service: {service} {version}",
                            response_received=cve_data.get("description", ""),
                            is_vulnerable=False,
                            details=f"Matched CVE: {cve_id} - {cve_data.get('description', '')}",
                            confidence=0.9,
                            validated=False,
                        )
                        self.log_test_result(test)
                        result.add_result(test)

        except Exception as e:
            self.logger.error(f"CVE matching error: {e}")

    async def _test_cve_exploits(self, api_client, result: ModuleResult):
        """Test matched CVE exploits."""
        try:
            for service, cves in self.matched_cves.items():
                if self.check_kill_switch():
                    break

                for cve_id, cve_data in cves[:5]:
                    if self.check_kill_switch():
                        break

                    try:
                        payload = cve_data.get("payload_template", "")
                        if not payload:
                            continue

                        self.log_message_sent(f"CVE Exploit - {cve_id}", payload[:100])
                        response = await api_client.send_message(payload)
                        self.log_response_received(f"CVE Exploit - {cve_id}", response)

                        severity = self._cvss_to_severity(cve_data.get("cvss_score", 0))
                        is_vulnerable = response and len(response) > 100

                        test = TestResult(
                            test_name=f"CVE Exploit - {cve_id}",
                            category="CVE Exploitation",
                            status=TestStatus.FAILED if is_vulnerable else TestStatus.PASSED,
                            severity=severity,
                            payload_used=payload[:200],
                            response_received=response[:300] if response else "",
                            is_vulnerable=is_vulnerable,
                            details=cve_data.get("description", ""),
                            confidence=0.8 if is_vulnerable else 0.0,
                            validated=False,
                        )
                        self.log_test_result(test)
                        result.add_result(test)
                        await asyncio.sleep(0.5)

                    except Exception as e:
                        self.logger.error(f"CVE exploit test error for {cve_id}: {e}")

        except Exception as e:
            self.logger.error(f"CVE exploitation error: {e}")

    def _find_matching_cves(self, service: str, version: str) -> List[Tuple[str, Dict]]:
        """Find CVEs matching detected service and version."""
        matching_cves = []

        for cve_id, cve_data in CVE_REGISTRY.items():
            try:
                cve_service = cve_data.get("service", "").lower()
                service_lower = service.lower()

                # Check if service matches
                if cve_service in service_lower or service_lower in cve_service:
                    # Check version range
                    version_range = cve_data.get("version_range", {})
                    if version_range:
                        is_vulnerable = VersionMatcher.is_version_vulnerable(version, version_range)
                        if is_vulnerable:
                            matching_cves.append((cve_id, cve_data))

            except Exception as e:
                self.logger.error(f"CVE matching error for {cve_id}: {e}")

        # Sort by CVSS score (highest first)
        matching_cves.sort(
            key=lambda x: x[1].get("cvss_score", 0),
            reverse=True
        )

        return matching_cves

    def _extract_services_from_headers(self, headers: str) -> Dict[str, str]:
        """Extract service names and versions from HTTP headers."""
        services = {}

        # Server header patterns
        server_patterns = {
            r"Apache(?:/(\d+\.\d+\.\d+))?": "Apache",
            r"nginx(?:/(\d+\.\d+\.\d+))?": "Nginx",
            r"IIS(?:/(\d+\.\d+))?": "IIS",
            r"Microsoft-IIS(?:/(\d+\.\d+))?": "IIS",
            r"Node\.js(?:/(\d+\.\d+\.\d+))?": "Node.js",
        }

        for pattern, name in server_patterns.items():
            match = re.search(pattern, headers, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else "unknown"
                services[name] = version

        # X-Powered-By patterns
        powered_patterns = {
            r"PHP/(\d+\.\d+\.\d+)": "PHP",
            r"ASP\.NET(?:_MVC)?/(\d+\.\d+)": "ASP.NET",
            r"Express(?:/(\d+\.\d+\.\d+))?": "Express",
            r"Spring(?:/(\d+\.\d+))?": "Spring",
        }

        for pattern, name in powered_patterns.items():
            match = re.search(pattern, headers, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else "unknown"
                services[name] = version

        return services

    def _extract_service_name(self, response: str) -> Optional[str]:
        """Extract service name from response."""
        service_names = [
            "Apache", "Nginx", "IIS", "Node.js", "Express",
            "PHP", "ASP.NET", "Spring", "Django", "Flask",
            "Rails", "Laravel", "Tomcat", "Jetty", "JBoss"
        ]

        for service in service_names:
            if service.lower() in response.lower():
                return service

        return None

    def _cvss_to_severity(self, cvss_score: float) -> Severity:
        """Convert CVSS score to Severity level."""
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _generate_summary(self, result: ModuleResult) -> str:
        """Generate summary of CVE scanning results."""
        vuln = [t for t in result.test_results if t.is_vulnerable]
        cve_matches = len(self.matched_cves)

        if not vuln and cve_matches == 0:
            return f"✅ CVE Scanner: {result.total_tests} Tests, keine bekannten CVEs."

        return (
            f"⚠️ CVE Scanner: {result.vulnerabilities_found} exploitierbare CVEs, "
            f"{cve_matches} Service(s) mit Vulnerabilities"
        )
