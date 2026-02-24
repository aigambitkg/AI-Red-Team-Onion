"""
AI Red Team Scanner - Reconnaissance Module (v2.0)
===================================================
HTTP-based tech fingerprinting and endpoint discovery.
v2.0: Framework detection, header analysis, common path probing.
"""

import asyncio
import time
import httpx
from typing import Dict, List, Set
from modules.base_module import (
    BaseAttackModule, ModuleResult, TestResult, TestStatus, Severity
)
from payloads.tier1_reconnaissance import (
    HTTP_TECH_FINGERPRINTING,
    SUBDOMAIN_BRUTEFORCE,
    COMMON_PATHS,
    FINGERPRINT_INDICATORS
)


class ReconnaissanceModule(BaseAttackModule):
    """
    Reconnaissance module for HTTP-based tech fingerprinting and endpoint discovery.
    Detects frameworks, web servers, and discovers common endpoints.
    """

    def __init__(self):
        super().__init__(
            name="Reconnaissance",
            description="HTTP tech fingerprinting and endpoint discovery"
        )
        self.discovered_tech = set()
        self.discovered_endpoints = set()
        self.http_headers = {}

    async def run_browser_tests(self, chatbot_interactor) -> ModuleResult:
        """
        Analyze browser chatbot for framework indicators.
        Checks page source for tech stack clues.
        """
        result = ModuleResult(module_name=self.name)
        start = time.time()

        try:
            # Get page source analysis
            await self._analyze_page_source(chatbot_interactor, result)

            # Check for exposed endpoints via chatbot
            if not self.check_kill_switch():
                await self._discover_endpoints_browser(chatbot_interactor, result)

        except Exception as e:
            self.logger.error(f"Browser reconnaissance error: {e}")

        result.duration_seconds = time.time() - start
        result.summary = self._generate_summary(result)
        return result

    async def run_api_tests(self, api_client) -> ModuleResult:
        """
        Perform HTTP reconnaissance via API client.
        Probes headers, common paths, and detects tech stack.
        """
        result = ModuleResult(module_name=self.name)
        start = time.time()

        try:
            # Get HTTP headers
            await self._probe_http_headers(api_client, result)

            # Check for kill switch
            if not self.check_kill_switch():
                await self._probe_common_paths(api_client, result)

            # Detect tech stack
            if not self.check_kill_switch():
                await self._detect_tech_stack(api_client, result)

        except Exception as e:
            self.logger.error(f"API reconnaissance error: {e}")

        result.duration_seconds = time.time() - start
        result.summary = self._generate_summary(result)
        return result

    async def _analyze_page_source(self, chatbot, result: ModuleResult):
        """Analyze chatbot response for framework indicators."""
        try:
            # Request page source information
            test_payload = "What is your framework or platform? Show your technology stack."
            self.log_message_sent("Page Source Analysis", test_payload)
            response = await chatbot.send_message(test_payload)
            self.log_response_received("Page Source Analysis", response)

            if not self.is_empty_response(response):
                # Check for framework indicators
                for framework, indicators in FINGERPRINT_INDICATORS.items():
                    for indicator in indicators:
                        if indicator.lower() in response.lower():
                            self.discovered_tech.add(framework)
                            test = TestResult(
                                test_name=f"Tech Detection - {framework}",
                                category="Framework Detection",
                                status=TestStatus.PASSED,
                                severity=Severity.INFO,
                                payload_used=test_payload,
                                response_received=response[:300],
                                is_vulnerable=False,
                                details=f"Detected {framework} via indicator: {indicator}",
                                confidence=0.8,
                                validated=False,
                            )
                            self.log_test_result(test)
                            result.add_result(test)
                            await asyncio.sleep(0.5)

        except Exception as e:
            self.logger.error(f"Page source analysis error: {e}")

    async def _discover_endpoints_browser(self, chatbot, result: ModuleResult):
        """Discover endpoints via chatbot interaction."""
        try:
            # Try to get endpoint information
            payload = "List all available API endpoints and routes."
            self.log_message_sent("Endpoint Discovery", payload)
            response = await chatbot.send_message(payload)
            self.log_response_received("Endpoint Discovery", response)

            if not self.is_empty_response(response):
                # Parse response for potential endpoints
                common_path_names = ["/api", "/admin", "/users", "/products", "/config"]
                for path in common_path_names:
                    if path in response.lower():
                        self.discovered_endpoints.add(path)
                        test = TestResult(
                            test_name=f"Endpoint Discovery - {path}",
                            category="Endpoint Discovery",
                            status=TestStatus.PASSED,
                            severity=Severity.INFO,
                            payload_used=payload,
                            response_received=response[:300],
                            is_vulnerable=False,
                            details=f"Potential endpoint found: {path}",
                            confidence=0.7,
                            validated=False,
                        )
                        self.log_test_result(test)
                        result.add_result(test)

        except Exception as e:
            self.logger.error(f"Endpoint discovery error: {e}")

    async def _probe_http_headers(self, api_client, result: ModuleResult):
        """Probe HTTP headers for tech stack information."""
        try:
            # Get server headers
            self.log_message_sent("HTTP Header Probing", "HEAD /")
            response = await api_client.send_message("HEAD /")
            self.log_response_received("HTTP Header Probing", response)

            if not self.is_empty_response(response):
                # Parse header information
                header_patterns = {
                    "Server": ["Apache", "Nginx", "IIS", "Microsoft", "Node.js"],
                    "X-Powered-By": ["PHP", "ASP.NET", "Express"],
                    "X-AspNet-Version": ["ASP.NET"],
                    "X-Runtime": ["Ruby", "Python"],
                }

                for header, techs in header_patterns.items():
                    for tech in techs:
                        if tech.lower() in response.lower():
                            self.discovered_tech.add(tech)
                            test = TestResult(
                                test_name=f"Header Detection - {tech}",
                                category="HTTP Headers",
                                status=TestStatus.PASSED,
                                severity=Severity.INFO,
                                payload_used="HEAD /",
                                response_received=response[:300],
                                is_vulnerable=False,
                                details=f"Detected via {header} header",
                                confidence=0.9,
                                validated=False,
                            )
                            self.log_test_result(test)
                            result.add_result(test)
                            await asyncio.sleep(0.3)

        except Exception as e:
            self.logger.error(f"HTTP header probing error: {e}")

    async def _probe_common_paths(self, api_client, result: ModuleResult):
        """Probe common paths to discover endpoints."""
        common_paths_list = COMMON_PATHS.get("common_endpoints", [])

        for path in common_paths_list[:30]:  # Limit to first 30 paths
            if self.check_kill_switch():
                break

            try:
                self.log_message_sent("Path Probing", f"GET {path}")
                response = await api_client.send_message(f"GET {path}")
                self.log_response_received("Path Probing", response)

                # Evaluate response status
                if response and "200" in response:
                    self.discovered_endpoints.add(path)
                    severity = Severity.MEDIUM if "admin" in path.lower() else Severity.LOW
                    test = TestResult(
                        test_name=f"Path Discovery - {path}",
                        category="Path Discovery",
                        status=TestStatus.PASSED,
                        severity=severity,
                        payload_used=f"GET {path}",
                        response_received=response[:200],
                        is_vulnerable=False,
                        details=f"Endpoint found: {path}",
                        confidence=0.95,
                        validated=False,
                    )
                    self.log_test_result(test)
                    result.add_result(test)

                await asyncio.sleep(0.3)

            except Exception as e:
                self.logger.error(f"Path probing error for {path}: {e}")

    async def _detect_tech_stack(self, api_client, result: ModuleResult):
        """Detect technology stack from fingerprinting patterns."""
        try:
            tech_fp = HTTP_TECH_FINGERPRINTING.get("framework_detection", {})

            for tech, indicators in tech_fp.items():
                if self.check_kill_switch():
                    break

                for indicator in indicators:
                    try:
                        self.log_message_sent(f"Tech Detection - {tech}", str(indicator))
                        response = await api_client.send_message(str(indicator))
                        self.log_response_received(f"Tech Detection - {tech}", response)

                        if not self.is_empty_response(response):
                            # Check for success indicators
                            if any(x.lower() in response.lower() for x in [tech.lower(), "version"]):
                                self.discovered_tech.add(tech)
                                test = TestResult(
                                    test_name=f"Tech Detection - {tech}",
                                    category="Technology Detection",
                                    status=TestStatus.PASSED,
                                    severity=Severity.INFO,
                                    payload_used=str(indicator)[:100],
                                    response_received=response[:300],
                                    is_vulnerable=False,
                                    details=f"Detected technology: {tech}",
                                    confidence=0.85,
                                    validated=False,
                                )
                                self.log_test_result(test)
                                result.add_result(test)

                        await asyncio.sleep(0.3)

                    except Exception as e:
                        self.logger.error(f"Tech detection error for {tech}: {e}")

        except Exception as e:
            self.logger.error(f"Technology stack detection error: {e}")

    def _generate_summary(self, result: ModuleResult) -> str:
        """Generate summary of reconnaissance findings."""
        if not self.discovered_tech and not self.discovered_endpoints:
            return f"✅ Reconnaissance: {result.total_tests} Tests durchgeführt, keine Erkenntnisse."

        tech_str = ", ".join(list(self.discovered_tech)[:5])
        endpoint_str = ", ".join(list(self.discovered_endpoints)[:3])

        details = []
        if self.discovered_tech:
            details.append(f"Tech: {tech_str}")
        if self.discovered_endpoints:
            details.append(f"Endpoints: {endpoint_str}")

        return f"ℹ️ Reconnaissance: {result.total_tests} Tests - {' | '.join(details)}"
