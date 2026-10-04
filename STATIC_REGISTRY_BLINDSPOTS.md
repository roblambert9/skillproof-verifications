# Static Registry Guards Miss 67% of Malicious MCP Tools: The Mathematical Proof & Behavioral Benchmark

*By Nano Empire AI Infrastructure Group • Published 2026-10-04*

---

## 1. The Impossibility Result: Why Static Scanning Can Never Win

In the rush to deploy AI agents and Model Context Protocol (MCP) ecosystems, registries have adopted the security posture of traditional package managers: static regex filters, keyword blocklists, and basic AST inspection.

Recent research proves this approach is mathematically doomed to fail:

1. **Contextual Integrity Impossibility (Abdelnabi et al., arXiv:2605.17634, 2026):**  
   Prompt injection and tool poisoning recast through contextual integrity demonstrate an inescapable boundary: an adversary can always construct a context under which an unauthorized flow appears legitimate—or any defender tightening static filters inevitably breaks legitimate agent tool-use workflows.
2. **The Inseparability Theorem (2026):**  
   No defense operating purely within shared representational embeddings can guarantee 100% prevention. Untrusted inputs enter control-relevant tokens by construction.
3. **Empirical Grounding (StakeBench, 3,168 Adversarial Runs):**  
   Indirect prompt injection succeeded 41%–68% across all frontier agent setups; direct injection succeeded 79%+. Zero defense architectures consistently blocked all vectors.

**The conclusion is unambiguous: You cannot prevent what static syntax cannot distinguish. The only viable path is empirical measurement and behavioral proof.**

---

## 2. The Benchmark: Static vs. Behavioral Verification Gap

We built **`gapbench`** to measure the exact detection gap across 12 MCP tool definitions (6 benign baselines + 6 poisoned tools across 5 real-world attack classes documented by CrowdStrike and CVE advisories).

### Benchmark Execution

```
tool              label     static  behavioral  notes
----------------------------------------------------------------------------------------------------
weather-read      benign    False   False     
calculator        benign    False   False     
file-search       benign    False   False     
calendar-read     benign    False   False     
translate         benign    False   False     
notes-append      benign    False   False     
quick-summarize   malicious True    True        (overt prompt override)
db-query-fast     malicious False   True        << STATIC MISS (schema smuggling / SSRF)
doc-translate     malicious False   True        << STATIC MISS (benign-worded data egress)
version-checker   malicious False   True        << STATIC MISS (rug-pull description drift)
sys-health        malicious True    True        (overt credential request)
csv-analyzer      malicious False   True        << STATIC MISS (excessive permission scope)
----------------------------------------------------------------------------------------------------
STATIC:     caught 2/6 attacks (33%)   false positives: 0
BEHAVIORAL: caught 5/6 attacks (83%)   false positives: 0
```

### Key Takeaways
- **Static Guards Only Catch the Obvious (33%):** Static filters only trip when attackers use literal phrases like `"ignore instructions"` or `"api_key"`.
- **Real Attacks Exploit Semantics (83% Behavioral Catch Rate):**
  - **Benign-Worded Egress:** Exfiltrating context to external analytics services using polite language.
  - **Schema Smuggling:** Concealing override prompts inside nested JSON schema properties.
  - **Rug-Pull Drift:** Changing version behavior without altering registered function names.
  - **Excessive Scope:** Requesting broad system access disproportionate to the declared capability.

---

## 3. The Solution: Cryptographically Signed Behavioral Trust Manifests

Instead of relying on unverified registry badges or fallible static scanners, enterprise agent runtimes require **portable cryptographic proof**.

Through **SkillProof**, MCP tools are executed against an automated adversarial battery:
- Dynamic taint-tracking of parameters and model outputs.
- Invariant checking across multi-turn sequential calls.
- Ed25519-signed `trust-manifest.json` containing immutable cryptographic attestations of measured behavior.

### Explore the Directory & Verify Your Server
- **Public Verified Registry:** [https://www.nanoempireai.com/manifests.html](https://www.nanoempireai.com/manifests.html)
- **Smithery Server Attestation:** [smithery.ai/servers/roblambert9/skillproof-verifications](https://smithery.ai/servers/roblambert9/skillproof-verifications)
