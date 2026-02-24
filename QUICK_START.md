# Tier 2 Payload Files - Quick Start Guide

## Files Created

### 1. tier2_adaptive.py (662 lines, 23 KB)
**Context-Sensitive Adaptive Payload Generation**

Location: `/home/kevin/ai_red_team/payloads/tier2_adaptive.py`

Key Classes:
- `TechStackMapper` - Maps 15+ technologies to attack vectors
- `AdaptivePayloadGenerator` - Generates context-aware payloads
- `PayloadRanker` - Ranks and deduplicates payloads

Quick Start:
```python
from payloads.tier2_adaptive import AdaptivePayloadGenerator

gen = AdaptivePayloadGenerator()
payloads = gen.generate_for_context(['apache', 'php', 'mysql'])
print(f"Generated {len(payloads)} payloads")
```

### 2. tier2_evasion.py (739 lines, 24 KB)
**Polymorphic and Metamorphic Evasion Engine**

Location: `/home/kevin/ai_red_team/payloads/tier2_evasion.py`

Key Classes:
- `PolymorphicEngine` - 10+ encoding/obfuscation techniques
- `WAFBypass` - Detects and bypasses 4 WAF types
- `MetamorphicEngine` - Semantic payload rewriting

Quick Start:
```python
from payloads.tier2_evasion import PolymorphicEngine, WAFBypass

poly = PolymorphicEngine()
mutations = poly.mutate("' OR '1'='1", count=10)

waf = WAFBypass()
bypasses = waf.bypass("UNION SELECT * FROM users", "cloudflare")
```

---

## Feature Summary

### tier2_adaptive.py Features
- Maps 15 technologies (MySQL, Apache, Nginx, PHP, Python, Java, Node, WordPress, Oracle, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, GraphQL)
- 4-step payload generation: mapping → LLM → mutations → ranking
- Feedback-driven mutation from execution results
- Confidence scoring and ranking
- Semantic deduplication
- LLM integration support (optional)
- 50+ payloads per context

### tier2_evasion.py Features
- 7 encoding techniques: URL, Base64, Hex, Unicode, Double, etc.
- 5 obfuscation techniques: Case variation, Null bytes, Comments, Whitespace, Concatenation
- 4 WAF types supported: ModSecurity, Cloudflare, AWS WAF, Imperva
- Semantic rewriting with LLM support
- 4+ structural variations per payload type
- 10-30 unique variants per payload
- Fully working implementation (no placeholders)

---

## Key Methods

### tier2_adaptive.py

**TechStackMapper**
- `map_tech_to_payloads(tech_stack: list[str]) -> dict`
  - Input: ['mysql', 'apache', 'php']
  - Output: Dict with ranked payloads and confidence scores

**AdaptivePayloadGenerator**
- `generate_for_context(tech_stack, vulnerabilities, kb_payloads) -> list[dict]`
  - Returns: Top 50 ranked payloads with confidence scores
  
- `generate_from_feedback(original_payload, execution_result) -> list[dict]`
  - Returns: Mutation variants optimized for bypass

**PayloadRanker**
- `rank(payloads, criteria) -> list[dict]`
  - Scores by: Confidence (60%), Novelty (20%), Evasion (20%)
  
- `deduplicate(payloads) -> list[dict]`
  - Removes semantically identical payloads

### tier2_evasion.py

**PolymorphicEngine**
- `url_encode(payload, level=1) -> str` - Single/double URL encoding
- `base64_encode(payload) -> str` - Base64 with prefix
- `hex_encode(payload) -> str` - Hex encoding
- `unicode_encode(payload) -> str` - Unicode escapes
- `case_variation(payload) -> list[str]` - 6 case patterns
- `null_byte_inject(payload) -> list[str]` - Strategic %00 insertion
- `comment_insert(payload, language) -> str` - Language-aware comments
- `whitespace_variation(payload) -> list[str]` - 7 whitespace patterns
- `concat_split(payload, language) -> str` - String concatenation
- `mutate(payload, techniques, count=10) -> list[str]` - Chain all techniques

**WAFBypass**
- `bypass(payload, waf_type) -> list[str]` - WAF-specific bypasses
- `detect_waf(headers, body) -> str` - Identify WAF type

**MetamorphicEngine**
- `rewrite(payload, cognitive_engine) -> str` - Semantic rewriting
- `structural_variation(payload) -> list[str]` - 4+ variations
- `synonym_replace(payload) -> str` - Keyword obfuscation
- `obfuscate_command(command) -> str` - Shell obfuscation

---

## Example Workflows

### Workflow 1: Basic Exploitation
```python
from payloads.tier2_adaptive import AdaptivePayloadGenerator
from payloads.tier2_evasion import PolymorphicEngine

# Step 1: Generate context-aware payloads
gen = AdaptivePayloadGenerator()
payloads = gen.generate_for_context(['apache', 'php', 'mysql'])

# Step 2: Create evasion variants
poly = PolymorphicEngine()
for payload in payloads[:5]:
    mutations = poly.mutate(payload['payload'], count=5)
    print(f"Original: {payload['payload']}")
    print(f"Mutations: {mutations[:3]}")
```

### Workflow 2: WAF Detection & Bypass
```python
from payloads.tier2_evasion import WAFBypass

waf = WAFBypass()
payload = "' UNION SELECT * FROM users--"

# Detect WAF
detected = waf.detect_waf(response_headers, response_body)
print(f"Detected WAF: {detected}")

# Generate bypasses
bypasses = waf.bypass(payload, detected)
for bypass in bypasses[:5]:
    print(f"Bypass: {bypass}")
```

### Workflow 3: Adaptive Mutation
```python
from payloads.tier2_adaptive import AdaptivePayloadGenerator

gen = AdaptivePayloadGenerator()

# Initial payloads
payloads = gen.generate_for_context(['apache', 'php', 'mysql'])

# Execute and get feedback
result = execute_payload(payloads[0]['payload'])

# Adapt based on failure
if result['status'] == 'blocked':
    adapted = gen.generate_from_feedback(
        original_payload=payloads[0]['payload'],
        execution_result=result
    )
    print(f"Generated {len(adapted)} adapted payloads")
```

### Workflow 4: Polymorphic Mutation
```python
from payloads.tier2_evasion import PolymorphicEngine

poly = PolymorphicEngine()

# Generate multiple mutations
payload = "SELECT * FROM users WHERE id=1"
mutations = poly.mutate(payload, count=20)

print(f"Original: {payload}")
for i, mutation in enumerate(mutations[:5], 1):
    print(f"{i}. {mutation}")
```

### Workflow 5: Semantic Rewriting
```python
from payloads.tier2_evasion import MetamorphicEngine

meta = MetamorphicEngine()

# SQL payload variations
sql = "SELECT * FROM users WHERE id=1"
variations = meta.structural_variation(sql)

print(f"Original: {sql}")
for i, var in enumerate(variations[:3], 1):
    print(f"{i}. {var}")
```

---

## Common Tasks

### Generate Payloads for a Specific Stack
```python
from payloads.tier2_adaptive import AdaptivePayloadGenerator

gen = AdaptivePayloadGenerator()
techs = ['nginx', 'node', 'mongodb']
payloads = gen.generate_for_context(techs)
```

### Create Multiple Mutations
```python
from payloads.tier2_evasion import PolymorphicEngine

poly = PolymorphicEngine()
payload = "' OR '1'='1"
variants = poly.mutate(payload, count=50)  # Generate 50 variants
```

### Bypass Specific WAF
```python
from payloads.tier2_evasion import WAFBypass

waf = WAFBypass()
sql_payload = "UNION SELECT * FROM users"
cloudflare_bypasses = waf.bypass(sql_payload, "cloudflare")
```

### Chain Techniques Together
```python
from payloads.tier2_evasion import PolymorphicEngine

poly = PolymorphicEngine()
payload = "SELECT * FROM users"

# Apply specific techniques
encoded = poly.url_encode(payload, level=2)
with_comments = poly.comment_insert(encoded, "sql")
case_varied = poly.case_variation(with_comments)
```

---

## Performance Notes

| Operation | Time | Output |
|-----------|------|--------|
| generate_for_context() | Fast | 20-50 payloads |
| mutate() with 10 variants | Fast | 10+ unique strings |
| WAF detection | Fast | String (WAF type) |
| bypass() | Fast | 15-30 variants |
| rank() | O(n log n) | Sorted payloads |
| deduplicate() | O(n) | Unique payloads |

---

## Documentation Files

1. **TIER2_SUMMARY.md** - High-level overview and statistics
   - Location: `/home/kevin/ai_red_team/payloads/TIER2_SUMMARY.md`
   - Content: Class descriptions, feature list, integration points

2. **IMPLEMENTATION_DETAILS.md** - Complete technical documentation
   - Location: `/home/kevin/ai_red_team/payloads/IMPLEMENTATION_DETAILS.md`
   - Content: All method signatures, parameters, examples, workflows

3. **TIER2_COMPLETION_REPORT.md** - Full completion report
   - Location: `/home/kevin/ai_red_team/TIER2_COMPLETION_REPORT.md`
   - Content: Requirements checklist, validation results, statistics

---

## File Locations

```
/home/kevin/ai_red_team/payloads/
├── tier2_adaptive.py          [662 lines] ← Context-aware generation
├── tier2_evasion.py           [739 lines] ← Polymorphic evasion
├── TIER2_SUMMARY.md           [Quick overview]
└── IMPLEMENTATION_DETAILS.md  [Full documentation]

/home/kevin/ai_red_team/
└── TIER2_COMPLETION_REPORT.md [Detailed report]
```

---

## Integration with Other Modules

These modules integrate with:
- **tier2_chain_builder.py** - Build attack chains using generated payloads
- **tier2_fuzzer.py** - Fuzz using polymorphic variants
- **tier1_cve_database.py** - Match payloads to known CVEs
- **tier1_reconnaissance.py** - Use detected tech for context

---

## Validation Status

Both files are validated and tested:
- ✓ Python syntax check (py_compile)
- ✓ All imports working
- ✓ All classes instantiable
- ✓ All methods functional
- ✓ Cross-module integration verified
- ✓ Output types correct

---

## Next Steps

1. **Integrate with execution engine** to get real feedback
2. **Add database** to track payload success rates
3. **Connect CognitiveEngine** for LLM-based generation
4. **Create evaluation metrics** for effectiveness
5. **Build feedback loop** from execution results

---

## Troubleshooting

**Import Error:**
```python
# Make sure to add to path
import sys
sys.path.insert(0, '/home/kevin/ai_red_team')
from payloads.tier2_adaptive import AdaptivePayloadGenerator
```

**No Mutations Generated:**
- Check payload length (too short may have limited variants)
- Verify techniques list is correct
- Try increasing count parameter

**WAF Not Detected:**
- Check response headers are passed correctly
- Check response body for WAF signatures
- Falls back to generic bypass

---

## Support

For detailed information:
- See IMPLEMENTATION_DETAILS.md for method signatures
- See TIER2_SUMMARY.md for feature overview
- Check class docstrings for usage examples
- Review TIER2_COMPLETION_REPORT.md for statistics

---

**Version:** 1.0
**Status:** Complete and Tested
**Ready for Integration:** Yes
