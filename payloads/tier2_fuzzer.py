"""
Tier 2: API and Input Fuzzing Payload Generator
=================================================
Generates mutated payloads for API and input fuzzing.
Tests for various vulnerability types through malformed inputs.

Features:
- APIFuzzer for JSON, query parameters, headers, and form data
- BoundaryTester for edge case testing
- MutationStrategy for payload manipulation
- Anomaly detection in responses
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple
from enum import Enum
import random
import string
import json
from datetime import datetime
import sys


class AnomalyType(Enum):
    """Types of anomalies detected in responses."""
    CRASH = "crash"
    TIMEOUT = "timeout"
    MEMORY_SPIKE = "memory_spike"
    UNEXPECTED_RESPONSE = "unexpected_response"
    ERROR_MESSAGE = "error_message"
    SLOW_RESPONSE = "slow_response"
    INVALID_ENCODING = "invalid_encoding"
    EXECUTION_FLOW_CHANGE = "execution_flow_change"


class FuzzingStrategy(Enum):
    """Fuzzing strategies."""
    RANDOM = "random"
    BOUNDARY = "boundary"
    MUTATION = "mutation"
    FORMAT_STRING = "format_string"
    TYPE_CONFUSION = "type_confusion"


@dataclass
class FuzzResult:
    """
    Result from a fuzz test.
    
    Attributes:
        payload: The payload that was sent
        response_code: HTTP response code
        response_time: Response time in milliseconds
        response_body: Response body content
        is_anomaly: Whether an anomaly was detected
        anomaly_type: Type of anomaly if detected
        description: Human-readable description
    """
    payload: Any
    response_code: int = 0
    response_time: float = 0.0
    response_body: str = ""
    is_anomaly: bool = False
    anomaly_type: str = ""
    description: str = ""
    
    def to_dict(self) -> Dict:
        """Convert FuzzResult to dictionary."""
        return {
            "payload": str(self.payload),
            "response_code": self.response_code,
            "response_time": self.response_time,
            "response_body": self.response_body[:200],  # Truncate for storage
            "is_anomaly": self.is_anomaly,
            "anomaly_type": self.anomaly_type,
            "description": self.description
        }


class APIFuzzer:
    """
    Generates fuzzing payloads for API testing.
    Creates malformed inputs to test API robustness.
    """
    
    def __init__(self, seed: int = None):
        """
        Initialize the APIFuzzer.
        
        Args:
            seed: Random seed for reproducibility
        """
        if seed:
            random.seed(seed)
        self.special_chars = "<>\"'%;()&+$,=?#@[]{}"
        self.unicode_chars = "©®™°¢£¥€¤¿¡§¶†‡"
        self.sql_patterns = ["'", "\"", "--", ";", "/*", "*/", "xp_", "sp_"]
        self.xss_patterns = ["<", ">", "'", '"', "script", "onclick", "onerror"]
    
    def fuzz_json(self, schema: Dict, count: int = 50) -> List[Dict]:
        """
        Generate mutated JSON objects based on schema.
        
        Args:
            schema: Base JSON schema/object
            count: Number of fuzzing variants to generate
            
        Returns:
            List of mutated JSON objects
        """
        fuzzed = []
        
        for i in range(count):
            mutated = self._deep_copy_dict(schema)
            
            strategy = i % 5  # Rotate through strategies
            
            if strategy == 0:
                # Missing required fields
                mutated = self._remove_random_fields(mutated, min(len(mutated), 2))
            elif strategy == 1:
                # Wrong data types
                mutated = self._change_field_types(mutated)
            elif strategy == 2:
                # Overflow values
                mutated = self._inject_overflow_values(mutated)
            elif strategy == 3:
                # Special characters in strings
                mutated = self._inject_special_chars(mutated)
            elif strategy == 4:
                # Null values and empty containers
                mutated = self._inject_empty_values(mutated)
            
            fuzzed.append(mutated)
        
        # Add deeply nested object to test stack limits
        for depth in [10, 50, 100]:
            nested = self._create_nested_object(depth)
            fuzzed.append(nested)
        
        return fuzzed
    
    def _deep_copy_dict(self, obj: Any) -> Any:
        """Deep copy a dictionary structure."""
        if isinstance(obj, dict):
            return {k: self._deep_copy_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy_dict(v) for v in obj]
        else:
            return obj
    
    def _remove_random_fields(self, obj: Dict, count: int) -> Dict:
        """Remove random fields from object."""
        keys = list(obj.keys())
        for _ in range(min(count, len(keys))):
            if keys:
                del obj[random.choice(keys)]
                keys = list(obj.keys())
        return obj
    
    def _change_field_types(self, obj: Dict) -> Dict:
        """Change field types to wrong types."""
        for key in list(obj.keys()):
            current = obj[key]
            if isinstance(current, str):
                obj[key] = random.randint(0, 1000)
            elif isinstance(current, int):
                obj[key] = "string_instead_of_int"
            elif isinstance(current, bool):
                obj[key] = "true"
            elif isinstance(current, list):
                obj[key] = "array_as_string"
            elif isinstance(current, dict):
                obj[key] = ["array", "instead", "of", "object"]
        return obj
    
    def _inject_overflow_values(self, obj: Dict) -> Dict:
        """Inject overflow and boundary values."""
        overflow_values = [
            sys.maxsize,
            -sys.maxsize - 1,
            sys.maxsize + 1,
            -sys.maxsize,
            0,
            -1,
            "A" * 10000,  # Very long string
            "A" * 100000,  # Even longer string
            1.7976931348623157e+308,  # Near float max
        ]
        
        for key in list(obj.keys()):
            obj[key] = random.choice(overflow_values)
        
        return obj
    
    def _inject_special_chars(self, obj: Dict) -> Dict:
        """Inject special characters into string fields."""
        for key in list(obj.keys()):
            if isinstance(obj[key], str):
                special = random.choice(self.special_chars)
                obj[key] = f"{obj[key]}{special}{obj[key]}"
            elif isinstance(obj[key], dict):
                obj[key] = self._inject_special_chars(obj[key])
        
        return obj
    
    def _inject_empty_values(self, obj: Dict) -> Dict:
        """Inject null and empty values."""
        empty_values = [None, "", [], {}, 0, False]
        
        for key in list(obj.keys()):
            obj[key] = random.choice(empty_values)
        
        return obj
    
    def _create_nested_object(self, depth: int) -> Dict:
        """Create deeply nested object to test recursion limits."""
        current = {"value": "nested"}
        for _ in range(depth):
            current = {"nested": current}
        return current
    
    def fuzz_query_params(self, base_url: str, params: Dict, count: int = 30) -> List[str]:
        """
        Generate URLs with fuzzed query parameters.
        
        Args:
            base_url: Base URL without parameters
            params: Base parameters dictionary
            count: Number of variants to generate
            
        Returns:
            List of URLs with fuzzed parameters
        """
        urls = []
        
        for i in range(count):
            fuzzed_params = self._deep_copy_dict(params)
            
            strategy = i % 4
            if strategy == 0:
                # Remove parameters
                for key in list(fuzzed_params.keys())[:random.randint(1, len(fuzzed_params))]:
                    del fuzzed_params[key]
            elif strategy == 1:
                # Change parameter values to SQL patterns
                for key in fuzzed_params:
                    fuzzed_params[key] = random.choice(self.sql_patterns)
            elif strategy == 2:
                # Change to very long values
                for key in fuzzed_params:
                    fuzzed_params[key] = "A" * (1000 + i * 100)
            elif strategy == 3:
                # Inject format strings and XSS
                for key in fuzzed_params:
                    if random.choice([True, False]):
                        fuzzed_params[key] = "%x %x %x %s %s"
                    else:
                        fuzzed_params[key] = random.choice(self.xss_patterns)
            
            # Build URL
            query_string = "&".join(f"{k}={v}" for k, v in fuzzed_params.items())
            urls.append(f"{base_url}?{query_string}")
        
        # Add parameter pollution
        for _ in range(5):
            polluted = params.copy()
            key = random.choice(list(params.keys()))
            urls.append(f"{base_url}?{key}=val1&{key}=val2&{key}={random.randint(0, 100)}")
        
        return urls
    
    def fuzz_headers(self, base_headers: Dict, count: int = 20) -> List[Dict]:
        """
        Generate fuzzed HTTP headers.
        
        Args:
            base_headers: Base headers dictionary
            count: Number of header variants
            
        Returns:
            List of header dictionaries
        """
        fuzzed_headers = []
        
        fuzzing_payloads = [
            ("X-Forwarded-For", "127.0.0.1, 192.168.1.1"),
            ("X-Original-URL", "/admin/secret"),
            ("X-Rewrite-URL", "/admin/secret"),
            ("X-Original-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("Host", "localhost"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("User-Agent", "' OR '1'='1"),
            ("Referer", "javascript:alert(1)"),
            ("Accept", "*/*"),
            ("Accept-Language", "en-US;q=0.9, *;q=0.8"),
            ("Accept-Encoding", "gzip, deflate, br"),
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "WebSocket"),
            ("Cookie", "admin=true; role=admin"),
            ("Authorization", "Bearer ' OR '1'='1"),
            ("X-API-Key", "' OR '1'='1"),
            ("X-CSRF-Token", "%x%x%x%x"),
            ("Content-Length", str(sys.maxsize)),
        ]
        
        for i in range(min(count, len(fuzzing_payloads))):
            headers = self._deep_copy_dict(base_headers)
            header_name, header_value = fuzzing_payloads[i]
            headers[header_name] = header_value
            fuzzed_headers.append(headers)
        
        # Header injection (CRLF)
        for _ in range(5):
            headers = self._deep_copy_dict(base_headers)
            headers["X-Custom"] = "value\r\nX-Injected: injected_value"
            fuzzed_headers.append(headers)
        
        return fuzzed_headers
    
    def fuzz_form_data(self, fields: Dict, count: int = 30) -> List[Dict]:
        """
        Generate mutated form data submissions.
        
        Args:
            fields: Base form fields
            count: Number of variants
            
        Returns:
            List of mutated form data dictionaries
        """
        fuzzed_data = []
        
        for i in range(count):
            form = self._deep_copy_dict(fields)
            
            strategy = i % 5
            if strategy == 0:
                # Remove fields
                for key in list(form.keys())[:random.randint(1, len(form))]:
                    del form[key]
            elif strategy == 1:
                # Inject SQL payloads
                for key in form:
                    form[key] = "' OR '1'='1"
            elif strategy == 2:
                # Inject file path traversal
                for key in form:
                    form[key] = "../../etc/passwd"
            elif strategy == 3:
                # Inject command execution
                for key in form:
                    form[key] = "; ls -la"
            elif strategy == 4:
                # Long string overflow
                for key in form:
                    form[key] = "A" * (1000 + i * 100)
            
            fuzzed_data.append(form)
        
        return fuzzed_data


class BoundaryTester:
    """Tests boundary conditions and edge cases."""
    
    @staticmethod
    def test_integer_boundaries(field_name: str) -> List[Dict]:
        """
        Generate boundary test cases for integer fields.
        
        Args:
            field_name: Name of the integer field
            
        Returns:
            List of test cases with boundary values
        """
        test_cases = []
        
        boundary_values = [
            0,
            -1,
            1,
            sys.maxsize,
            -sys.maxsize - 1,
            sys.maxsize + 1,
            -sys.maxsize,
            2**31 - 1,  # 32-bit max
            -2**31,     # 32-bit min
            2**63 - 1,  # 64-bit max
            -2**63,     # 64-bit min
            0xFFFFFFFF,  # All bits set (32-bit)
            0xFFFFFFFFFFFFFFFF,  # All bits set (64-bit)
        ]
        
        for value in boundary_values:
            test_cases.append({field_name: value})
        
        return test_cases
    
    @staticmethod
    def test_string_boundaries(field_name: str) -> List[Dict]:
        """
        Generate boundary test cases for string fields.
        
        Args:
            field_name: Name of the string field
            
        Returns:
            List of test cases with boundary values
        """
        test_cases = []
        
        boundary_values = [
            "",  # Empty string
            " ",  # Single space
            "\x00",  # Null byte
            "\r\n",  # CRLF
            "A" * 256,  # 256 chars
            "A" * 1024,  # 1KB
            "A" * 10000,  # 10KB
            "A" * 100000,  # 100KB
            "🔥" * 100,  # Unicode emoji
            "\u0000" * 10,  # Null bytes
            "%s%s%s%s%s",  # Format string
            "${7*7}",  # Template injection
            "{{7*7}}",  # Template injection
            "' OR '1'='1",  # SQL injection
            "</script><script>alert(1)</script>",  # XSS
        ]
        
        for value in boundary_values:
            test_cases.append({field_name: value})
        
        return test_cases
    
    @staticmethod
    def test_array_boundaries(field_name: str) -> List[Dict]:
        """
        Generate boundary test cases for array fields.
        
        Args:
            field_name: Name of the array field
            
        Returns:
            List of test cases with boundary values
        """
        test_cases = []
        
        test_cases.append({field_name: []})  # Empty array
        test_cases.append({field_name: [None] * 10})  # Null array
        test_cases.append({field_name: ["A" * 1000] * 10000})  # Large array
        
        # Nested arrays
        nested = []
        for _ in range(100):
            nested.append([1, 2, 3])
        test_cases.append({field_name: nested})
        
        # Mixed types
        test_cases.append({field_name: [1, "string", None, True, {"nested": "object"}]})
        
        return test_cases
    
    @staticmethod
    def test_type_confusion(field_name: str, expected_type: str) -> List[Dict]:
        """
        Generate type confusion test cases.
        
        Args:
            field_name: Name of the field
            expected_type: Expected type ("int", "str", "bool", "array", "object")
            
        Returns:
            List of test cases with wrong types
        """
        test_cases = []
        
        type_mappings = {
            "int": ["string", True, [1, 2], {"val": 1}, None],
            "str": [123, True, [1, 2], {"val": 1}, None],
            "bool": ["true", 1, "false", 0, None],
            "array": ["string", 123, True, {"key": "value"}, None],
            "object": ["string", 123, True, [1, 2, 3], None],
        }
        
        wrong_types = type_mappings.get(expected_type, [])
        
        for value in wrong_types:
            test_cases.append({field_name: value})
        
        return test_cases


class MutationStrategy:
    """Implements various payload mutation strategies."""
    
    @staticmethod
    def bit_flip(data: bytes, count: int = 10) -> List[bytes]:
        """
        Flip random bits in data.
        
        Args:
            data: Input data
            count: Number of bit flips to generate
            
        Returns:
            List of bit-flipped data variants
        """
        mutations = []
        
        for _ in range(count):
            data_array = bytearray(data)
            
            # Flip 1-3 random bits
            bits_to_flip = random.randint(1, 3)
            for _ in range(bits_to_flip):
                byte_index = random.randint(0, len(data_array) - 1)
                bit_index = random.randint(0, 7)
                data_array[byte_index] ^= (1 << bit_index)
            
            mutations.append(bytes(data_array))
        
        return mutations
    
    @staticmethod
    def arithmetic_mutation(value: int, count: int = 10) -> List[int]:
        """
        Apply arithmetic mutations to integer values.
        
        Args:
            value: Input integer
            count: Number of mutations
            
        Returns:
            List of mutated integer values
        """
        mutations = []
        
        mutations_to_try = [
            value + 1,
            value - 1,
            value * 2,
            value // 2,
            value + random.randint(-100, 100),
            -value,
            value ^ 0xFF,  # Bitwise NOT (8-bit)
            value << 1,  # Shift left
            value >> 1,  # Shift right
            value + sys.maxsize,
        ]
        
        for _ in range(count):
            mutations.append(random.choice(mutations_to_try))
        
        return mutations
    
    @staticmethod
    def format_string_injection(field_name: str) -> List[str]:
        """
        Generate format string injection payloads.
        
        Args:
            field_name: Name of the field
            
        Returns:
            List of format string injection payloads
        """
        payloads = []
        
        format_strings = [
            "%x" * 10,
            "%s" * 10,
            "%n" * 10,
            "%x.%x.%x.%x.%x.%x.%x.%x",
            "%08x.%08x.%08x.%08x.%08x.%08x",
            "%p" * 10,
            "%08p.%08p.%08p.%08p",
            "${7*7}",
            "{{7*7}}",
            "{0} {1} {2} {3} {4}",
            "%{0}",
            "%{65536}",
            "%257x",  # Large width
        ]
        
        for fmt in format_strings:
            payloads.append(f"{{{field_name}: {fmt}}}")
            payloads.append(f"{field_name}={fmt}")
        
        return payloads


def generate_fuzz_report(results: List[FuzzResult]) -> Dict:
    """
    Generate a report from fuzz test results.
    
    Args:
        results: List of FuzzResult objects
        
    Returns:
        Dictionary with analysis
    """
    if not results:
        return {"total_tests": 0, "anomalies_found": 0}
    
    anomalies = [r for r in results if r.is_anomaly]
    
    report = {
        "total_tests": len(results),
        "total_anomalies": len(anomalies),
        "anomaly_rate": len(anomalies) / len(results),
        "anomaly_types": {},
        "response_codes": {},
        "avg_response_time": sum(r.response_time for r in results) / len(results),
        "anomalies": [a.to_dict() for a in anomalies[:10]]  # Top 10
    }
    
    # Count anomaly types
    for result in anomalies:
        atype = result.anomaly_type
        report["anomaly_types"][atype] = report["anomaly_types"].get(atype, 0) + 1
    
    # Count response codes
    for result in results:
        code = result.response_code
        report["response_codes"][str(code)] = report["response_codes"].get(str(code), 0) + 1
    
    return report


# Example usage
if __name__ == "__main__":
    # Example schema
    schema = {
        "username": "admin",
        "password": "secret123",
        "email": "admin@example.com",
        "age": 25,
        "active": True
    }
    
    # Fuzz JSON
    fuzzer = APIFuzzer(seed=42)
    json_payloads = fuzzer.fuzz_json(schema, count=20)
    print(f"Generated {len(json_payloads)} JSON fuzz payloads")
    print(f"First payload: {json_payloads[0]}")
    
    # Fuzz query params
    params = {"id": "123", "name": "test", "role": "user"}
    urls = fuzzer.fuzz_query_params("http://api.example.com/users", params, count=10)
    print(f"\nGenerated {len(urls)} URL fuzz payloads")
    print(f"First URL: {urls[0]}")
    
    # Fuzz headers
    headers = {"Content-Type": "application/json", "Authorization": "Bearer token"}
    fuzzed_headers = fuzzer.fuzz_headers(headers, count=10)
    print(f"\nGenerated {len(fuzzed_headers)} header fuzz payloads")
    
    # Test integer boundaries
    int_tests = BoundaryTester.test_integer_boundaries("user_id")
    print(f"\nGenerated {len(int_tests)} integer boundary tests")
    
    # Test string boundaries
    str_tests = BoundaryTester.test_string_boundaries("message")
    print(f"Generated {len(str_tests)} string boundary tests")
    
    # Format string injection
    fmt_payloads = MutationStrategy.format_string_injection("username")
    print(f"\nGenerated {len(fmt_payloads)} format string injection payloads")
