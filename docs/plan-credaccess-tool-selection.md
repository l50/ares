# Plan: tighten credaccess_with_creds prompt to suppress wrong-tool warmup

## Problem

When `auto_credential_access` dispatches a `credential_access` task with
`technique: secretsdump` for a `(credential, DC IP)` pair, the rendered
`credaccess_with_creds` task prompt tells the agent to run "EACH technique
above in order" — i.e., `secretsdump(target=…, username=…, domain=…)`.

In practice the gpt-5.2 agent often calls `smbexec` / `evil_winrm` /
`ldap_search` / `nmap_scan` / `smb_signing_check` *first* as exploration,
then gets denied (the cred is non-admin on member hosts but has DCSync on
the DC), and only later — sometimes much later — fires the assigned
`secretsdump`. Each wrong tool call costs ~10-30 s of LLM round-trip plus
the underlying tool runtime, and the agent's reasoning context grows with
each rejected attempt, biasing the next pick further.

Evidence from op-20260606-063217: brandon.stark paired with `10.1.10.11`
(the correct north.sevenkingdoms.local DC) appeared in **6 tool spans** —
all `tool.smbexec`, `tool.evil_winrm`, `tool.ldap_search`, **zero
`tool.secretsdump`**. First DA on north.sevenkingdoms.local landed at
07:26:58, ~55 min into the op; the upstream `dreadnode/ares` reportedly
gets the same range to first DA in ~30 min.

The current prompt's `DO NOT` list is:

```
- Run smb_sweep (wastes 5+ minutes)
- Run kerberos_user_enum_noauth (not your job)
- Do additional recon before completing assigned techniques
```

`smbexec`, `evil_winrm`, `ldap_search`, `nmap_scan`, `smb_signing_check`
are not listed, and "additional recon" is vague enough that the LLM
rationalizes lateral-movement and LDAP-bind calls as task-aligned.

## Proposed fix

Edit `ares-llm/templates/redteam/tasks/credaccess_with_creds.md.tera` to:

1. Name every observed wrong-first-pick explicitly in `DO NOT`.
2. Replace the generic "execute … in order" instruction with a positive
   rule: **your very first tool call must be the first listed technique**.
3. Add a one-line rationale so the LLM doesn't try to explain away the rule.

### Concrete changes

- Expand the `DO NOT` block from 3 bullets to ~8, covering the observed
  misuses: `smbexec`, `wmiexec`, `evil_winrm`, `ldap_search`,
  `ldap_search_descriptions` (when not the assigned technique),
  `nmap_scan`, `smb_signing_check`, plus the existing `smb_sweep` and
  `kerberos_user_enum_noauth`.
- Add a single line above the techniques list: **Your first tool call
  must be technique #1 below. No exploration, no warm-up, no "let me
  check first".**
- Keep the rest of the template structure intact so existing template
  tests and template renderers don't churn.

### Non-goals

- Changing the dispatcher / planner. The work item generation in
  `select_credential_secretsdump_work` is correct; the issue is purely
  at the LLM-agent-prompt layer.
- Deterministic-bypass-of-LLM for DCSync-equipped credentials. That's
  a higher-impact follow-up but a much larger change (new automation
  module, BloodHound ACE plumbing into the scheduler) and is out of
  scope for a prompt-only PR.
- Per-tool blocklist enforcement in the tool dispatcher (kill the call
  if it's not the assigned technique). Same: bigger PR, separate risk
  surface.

## Verification

1. `cargo check -p ares-llm` — template literal change must keep all
   call sites compiling.
2. `cargo test -p ares-llm --bin ares prompt::credential_access` — existing
   prompt-render tests still pass with the expanded literal.
3. `cargo clippy -p ares-llm -- -D warnings` — keep CI green.
4. Build + push to attacker-1, submit a fresh op against the GOAD Ludus
   range. Success signals:
   - First `tool.secretsdump` span for a `(non-DA cred, DC IP)` pair
     fires within ~30 s of the corresponding `Starting LLM agent loop`
     for that task (vs minutes today).
   - Time-to-first-DA on the range drops noticeably from the recent ~55 min.

## Future follow-ups (out of scope)

- A deterministic auto-planner that fires `secretsdump` immediately when
  a credential + ACL state shows `GetChangesAll` / `DS-Replication-Get-Changes`
  for that principal, bypassing the LLM entirely on the highest-EV path.
- Auditing other `*_with_creds` task prompts (kerberoast,
  share_spider, low_hanging) for the same wrong-first-tool failure mode.
- A test fixture that renders the prompt with a representative payload
  and asserts the `DO NOT` block matches a snapshot — would catch
  accidental regressions of this exact text.
