# Tier 2 Payload Files - Summary

## Overview
Two advanced payload generation and evasion modules for the AI Red Team Onion project.

### File 1: tier2_adaptive.py (662 lines)
**Context-Sensitive Adaptive Payload Generation**

#### Classes:

1. **TechStackMapper** (Lines 36-147)
   - Maps 15+ technologies to their exploitation vectors
   - Returns ranked payload recommendations with confidence scores
   - Supported techs: MySQL, Apache, Nginx, PHP, Python, Java, Node, WordPress, Oracle, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, GraphQL
   - Confidence scoring based on technology-payload alignment

2. **AdaptivePayloadGenerator** (Lines 150-410)
   - Main class for generating context-aware payloads
   - `generate_for_context()`: 4-step process (mapping → LLM → mutations → ranking)
   - `generate_from_feedback()`: Adapts failed payloads based on error analysis
   - `_estimate_success()`: Heuristic probability estimation
   - Integrated mutation support
   - Returns top 50 ranked payloads

3. **PayloadRanker** (Lines 413-465)
   - Multi-criteria ranking (confidence, novelty, evasion)
   - `deduplicate()`: Removes semantically similar payloads using MD5 normalization
   - `rank()`: Custom scoring with configurable weights

#### Key Features:
- Tier 1 payload template library (SQL injection, path traversal, SSRF, template injection, command injection, log4j)
- LLM-optional integration for enhanced generation
- Feedback-driven mutation from failed attempts
- Semantic deduplication
- Confidence scoring throughout

---

### File 2: tier2_evasion.py (739 lines)
**Polymorphic and Metamorphic Evasion Engine**

#### Classes:

1. **PolymorphicEngine** (Lines 28-310)
   - `mutate()`: Generate 10+ variants using multiple techniques
   - **Encoding techniques:**
     - `url_encode()`: Single/double URL encoding (levels 1-2)
     - `base64_encode()`: Base64 with prefix detection
     - `hex_encode()`: Full hex conversion with 0x prefix
     - `unicode_encode()`: Unicode escape sequences (\uXXXX)
     - `double_encode()`: Chained URL encoding
   - **Obfuscation techniques:**
     - `case_variation()`: 6 different case patterns (upper, lower, alternating, etc.)
     - `null_byte_inject()`: Strategic %00 insertion (start, end, middle positions)
     - `comment_insert()`: Language-specific comments (SQL /\*\*/, HTML, shell, C)
     - `whitespace_variation()`: 7 whitespace patterns (tabs, newlines, mixed)
     - `concat_split()`: String concatenation (SQL CONCAT, shell $IFS)

2. **WAFBypass** (Lines 313-432)
   - Detects 4 WAF types from headers/body
   - Supported WAFs: ModSecurity, Cloudflare, AWS WAF, Imperva
   - `bypass()`: Generates WAF-specific bypass variants
   - Technique selection based on known WAF signatures
   - Generic bypass fallback for unknown WAFs
   - Returns deduped variants

3. **MetamorphicEngine** (Lines 435-570)
   - `rewrite()`: Semantic rewriting with optional LLM
   - `structural_variation()`: 4+ structural changes per payload type:
     - SQL: comment insertion, keyword replacement, concatenation, whitespace
     - Commands: IFS substitution, quoting changes, escaping
     - XSS: event handler rotation, tag transformation
   - `synonym_replace()`: SQL keyword obfuscation (SELECT→sElEcT, etc.)
   - `obfuscate_command()`: Shell command obfuscation with base64 encoding

#### Key Features:
- 10+ encoding/obfuscation techniques fully implemented
- Language-aware mutations (SQL, shell, HTML, C)
- WAF fingerprinting and evasion
- Deduplication on all outputs
- Synonym replacement dictionaries
- Command obfuscation with base64
- Chaining of multiple techniques

---

## Integration Points

### With tier2_adaptive.py:
- AdaptivePayloadGenerator uses PolymorphicEngine for mutations
- PayloadRanker uses evasion level as ranking criterion

### With CognitiveEngine:
- Optional LLM integration in both files
- MetamorphicEngine supports semantic rewriting
- AdaptivePayloadGenerator can use LLM for exploit generation

### With Tier 1 Payloads:
- TechStackMapper references Tier 1 payload types
- Can be extended with actual Tier 1 payload templates

---

## Statistics

| Metric | Value |
|--------|-------|
| Total Lines | 1,401 |
| Classes | 6 |
| Methods | 40+ |
| Encoding Techniques | 7 |
| Obfuscation Techniques | 5 |
| Technologies Mapped | 15+ |
| WAF Types Supported | 5 |
| Mutation Variants per Payload | 10+ |

---

## Testing Commands

```bash
# Test tier2_adaptive.py
python3 -c "from payloads.tier2_adaptive import AdaptivePayloadGenerator; g = AdaptivePayloadGenerator(); payloads = g.generate_for_context(['apache', 'php', 'mysql']); print(f'Generated {len(payloads)} payloads')"

# Test tier2_evasion.py
python3 -c "from payloads.tier2_evasion import PolymorphicEngine; p = PolymorphicEngine(); mutations = p.mutate(\\\"' OR '1'='1\\\"); print(f'Generated {len(mutations)} mutations')"
```

---

## Next Steps

1. Integrate with Tier 1 payloads module
2. Connect with CognitiveEngine for LLM-based generation
3. Add feedback loop from execution results
4. Implement database for success tracking
5. Create evaluation suite for effectiveness metrics
