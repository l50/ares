# LESSMONEY: cost-reduction plan for ares LLM spend

Baseline: op-20260629-074433 cost $28.14 for 25m20s (15.087M input / 0.124M output, gpt-5.2). Input is 94% of spend; output is rounding error. Three workstreams below, ordered by effort/payoff.

---

## 1. Track OpenAI cached tokens (visibility + accurate billing)

### The bug
`ares-llm/src/provider/openai.rs:126-129` defines `ApiUsage` as:

```rust
struct ApiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}
```

OpenAI returns `prompt_tokens_details.cached_tokens` whenever auto-caching fires on a prefix >1024 tokens. We drop it on the floor. The parser at `openai.rs:369-374` charges every input token at full rate even when half of them were billed at 50%.

For the baseline op, every step re-sent system + tools + accumulated history. With a stable prefix, OpenAI's auto-caching almost certainly fired across steps within the 5–10 minute cache window. The displayed $28.14 is an upper bound on what we actually paid.

### Plan

1. **Extend `ApiUsage`** (`ares-llm/src/provider/openai.rs:126`) to parse `prompt_tokens_details.cached_tokens`:
   ```rust
   struct ApiUsage {
       prompt_tokens: u32,
       completion_tokens: u32,
       #[serde(default)]
       prompt_tokens_details: Option<PromptTokensDetails>,
   }
   struct PromptTokensDetails { cached_tokens: u32 }
   ```
2. **Map cached → `cache_read_input_tokens`** at the usage parse site (`openai.rs:369-374`). The field already exists on `TokenUsage` (`ares-llm/src/provider/mod.rs:152`) — Anthropic populates it, OpenAI should too. Map `cached_tokens` to `cache_read_input_tokens` and subtract from `input_tokens` so downstream cost math is correct.
3. **Update cost lookup** in `ares-core/src/token_usage.rs`:
   - Extend `MODEL_COSTS` from `(name, in, out)` to `(name, in, cached_in, out)`. OpenAI gpt-5.2 cached input is $0.175/M (10% of $1.75). gpt-5 cached is $0.125/M. Anthropic cache reads are 10% of input.
   - In `estimate_usage_cost` (`token_usage.rs:108-145`), bill `cache_read_input_tokens × cached_rate + uncached_input × input_rate + output × output_rate`.
4. **Surface cache stats** in `task ec2:runtime` output (`ares-cli/src/ops/runtime.rs`): one extra line `Cache: hit X / Y tokens (Z%)`. This is the feedback loop — once we can see hit rate per role, we can tune.
5. **Verification.** Run a short op against a known target, eyeball the OpenAI dashboard `cached input tokens` for the same time window, and confirm ares math matches within 1%. If they diverge, we're parsing wrong.

### Expected impact
0% real cost reduction (this only fixes the display), but it gates everything below — without per-call cache visibility we can't tell whether change (2) actually helps or whether (3) is paying off.

### Effort
~1 hour. Single small struct add + arithmetic update + one line in the runtime printout. No protocol changes, no config migration.

---

## 2. Enforce prompt-prefix stability for reliable OpenAI auto-caching

### The setup
OpenAI auto-caches on byte-identical request prefixes (system message + tools array, in order). Caching is best-effort — if anything in the prefix shifts, the cache misses entirely and we pay full freight. Anthropic prompt caching is already wired explicitly (`ares-llm/src/provider/anthropic.rs:208,342`). OpenAI relies on this implicit prefix match.

### Risks to verify in the current code path

- **Tool ordering.** `convert_tools` (`ares-llm/src/provider/openai.rs:222-234`) iterates `request.tools` as a `Vec`. Source: `tool_registry::tools_for_role(role)` (`ares-llm/src/tool_registry/...`). If that function uses a `HashMap` anywhere upstream, ordering is non-deterministic across process restarts. Cache breaks silently.
- **Tool schema content.** Any non-deterministic field (e.g. example timestamps, listener IP baked into the schema description) makes the bytes change per op. The listener IP injected in `llm_runner.rs:50-62` is injected into the *system prompt*, not tool definitions — confirm by grepping `listener_ip` against `tool_registry/`. If it shows up in tool descriptions, move it out.
- **System prompt body.** The orchestrator's `build_system_prompt` (`llm_runner.rs:170-200+`) renders a Tera template with snapshot data (`StateSnapshot`). Snapshot includes discovered hosts/creds/domains, which *change every step*. **This is the silent cache killer**: the system prompt is rebuilt with fresh state on every `execute_task` call, so the prefix mutates and OpenAI auto-caching cannot fire across steps within a single agent loop unless the snapshot happens to be identical.
- **JSON field ordering.** `ApiRequest` derives `Serialize` (`openai.rs:36-48`); serde-json emits in struct-declaration order, which is stable. No issue here.

### Plan

1. **Split the system prompt into two layers**:
   - **Static layer**: role identity, capability list, technique priorities, golden rules. This is the cacheable prefix.
   - **Dynamic layer**: snapshot facts (current creds, hosts, domains, exploited paths). This goes into the **first user message** instead of the system prompt.

   OpenAI caches on the longest matching prefix of the request body. Moving the volatile bits into user-message position keeps the system block and tool definitions byte-identical across every step of a role's loop.

2. **Audit `tool_registry::tools_for_role`** for `HashMap`/`HashSet` iteration. Convert to `BTreeMap` or explicit `Vec` with sorted ordering. Add a unit test: serialize tools for `Recon` twice and assert byte equality.

3. **Pin tool-definition strings.** No `format!()` with timestamps or operation IDs inside tool `description` fields. Grep `tool_registry/` for `format!\(` and confirm.

4. **Test harness.** Add an integration test that runs two consecutive `execute_task` calls for the same role with a fixed snapshot, captures the serialized request body, and asserts the first N bytes (where N = static-layer size) are byte-equal.

### Expected impact
On a 25-minute op with 50–100 LLM steps per role and the system+tools prefix accounting for the bulk of input tokens, getting auto-caching to fire reliably should cut input cost by **30–50%**. Cached input is $0.175/M vs $1.75/M on gpt-5.2 — a 10× discount on whatever fraction hits the cache.

### Effort
~1 day. The split-into-two-layers refactor touches every role template (`ares-llm/templates/redteam/agents/*.md.tera`) and the prompt-building code in `llm_runner.rs`. Tests are mechanical once the structure is in place. Workstream (1) must land first so we can measure.

---

## 3. Per-role model selection (the big lever)

### The dead config
`config/ares.yaml` already declares `model:` under every `agents.<role>` block (lines 67, 97, 125, 147, 160, 177, 231, 261). But `ares-cli/src/orchestrator/mod.rs:414` reads only `agents.orchestrator.model` and creates a single `LlmProvider`. That provider is threaded through `LlmTaskRunner` (`ares-cli/src/orchestrator/llm_runner.rs:25-65`), which holds **one** `Box<dyn LlmProvider>` and **one** `AgentLoopConfig` (one model string) for all roles. The per-role model fields in YAML are read by `task ares config` (`ares-cli/src/config.rs`) but never reach the runtime.

So every recon enumeration, every cracker hashcat dispatch, every coercion attempt today pays gpt-5.2 reasoning prices for what is mostly tool-selection mechanics.

### Plan

1. **`LlmTaskRunner` owns a provider map, not a single provider.**
   Change `provider: Box<dyn LlmProvider>` → `providers: HashMap<AgentRole, (Box<dyn LlmProvider>, AgentLoopConfig)>`. `execute_task` (`llm_runner.rs:85`) already takes `role: AgentRole`, so it looks up the per-role provider and config at dispatch time.

2. **Orchestrator builds the map at startup.** In `orchestrator/mod.rs:405-426`, replace the single `create_provider(&model_spec)` with a loop over `cfg.agents`, calling `create_provider` per role. Fall back to the orchestrator's model when a role has no model set.

3. **Per-role `AgentLoopConfig`.** `AgentLoopConfig::from_env(model_name, temperature)` (`ares-llm/src/agent_loop/config.rs:61`) is already model-parameterized — just call it once per role with that role's model string.

4. **Pick the right model per role.** Suggested first pass (verify in benchmark before locking in):
   - `orchestrator` → **gpt-5.2** ($1.75/$14.00) — the only true reasoning role; chooses what to dispatch next, weighs strategy. Keep.
   - `acl` → **gpt-5.2** — ACL graph traversal needs real reasoning. Keep.
   - `privesc` → **gpt-5.2** — same. Keep.
   - `lateral` → **gpt-5** ($1.25/$10.00) — mostly picks a host + a tool from a known matrix. 29% cheaper.
   - `credential_access` → **gpt-5** — same shape. 29% cheaper.
   - `coercion` → **gpt-5-mini** ($0.25/$2.00) — fire-the-coercion-tool loop. 7× cheaper.
   - `recon` → **gpt-5-mini** — enumerate-and-emit. 7× cheaper.
   - `cracker` → **gpt-5-mini** — dispatch hashcat, parse output. 7× cheaper.

5. **Per-role token accounting.** `ares-core/src/token_usage.rs` already keys per-model counters in Redis (`ares:op:{op_id}:token_usage`, field `model:{base64(name)}:input_tokens`). Per-role spend will fall out naturally once different roles report different models.

6. **Bench before locking in.** Run two ops on the same target back-to-back: one with uniform gpt-5.2, one with the mixed map. Compare success criteria (DA achieved, golden ticket, hashes) + total cost. If the mini-model assignment drops success rate, walk it back to gpt-5 (still cheaper than gpt-5.2).

### Expected impact

Rough envelope assuming current input distribution is roughly even across roles. If 5 of 8 roles drop from gpt-5.2 to gpt-5 or gpt-5-mini:
- gpt-5 saves 29% on those roles
- gpt-5-mini saves 86% on those roles
- Blended: ~**40–55% input-cost reduction**

Combined with workstream (2): plausible **60–70% total cost reduction** vs current baseline, taking a $28 op to ~$10. The compromise quality should be unchanged for the mechanical roles; the strategic roles (orchestrator/acl/privesc) keep gpt-5.2 so the brains of the operation are untouched.

### Effort

~2 days. The runner refactor is the bulk of it; everything else (config plumbing, per-role accounting) already exists in skeleton form and just needs to be wired up. Bench cycle adds another day.

### Risk

The mini-model roles may regress. Recon especially — choosing what to scan and how to interpret unusual nmap output benefits from a stronger model. If we see operations missing hosts or skipping enumeration depth, the right move is to escalate that role one tier (mini → gpt-5), not to revert wholesale.

---

## Sequencing

1. **Workstream 1** first — visibility before optimization. Without cache-aware accounting, we can't measure (2) or (3).
2. **Workstream 2** second — passive caching is the cheapest win we can ship without changing model behavior. Cleaner baseline for comparing (3).
3. **Workstream 3** last — biggest payoff, biggest behavior risk. Bench against the now-cache-aware metrics from (1) and (2) so the savings attribution is honest.

Each stage stands alone and ships a real number to compare against the $28.14 baseline.
