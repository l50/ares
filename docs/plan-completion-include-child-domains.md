# Plan: completion requires every discovered domain, not just forest roots

## Problem

`ares-cli/src/orchestrator/completion.rs::compute_undominated_forests` builds
its required-set by mapping every discovered domain through `forest_root_of()`
before insertion, and builds the dominated-set by filtering `dominated_domains`
down to entries that are themselves forest roots. The set difference therefore
operates entirely at the forest-root layer.

That model is wrong for any topology with child domains. Each AD domain owns a
distinct krbtgt principal — dominating `contoso.local` does **not** also
compromise `child.contoso.local`, and vice versa. The successful-attack chain
runs end-to-end against each child independently (via `raise_child` for
intra-forest, or independent PtH/coercion for separately seeded child DCs), and
the operator's success criterion is "all discovered domains compromised", not
"all forest roots compromised".

Live evidence (`runtime` output, redacted of range-specific names):

```
DOMAIN ADMIN ACHIEVED (2/3 domains)
GOLDEN TICKET OBTAINED (2/3 domains)
Domains (2/3 compromised, 2/2 forests):
  <forest-root-a> (forest root)           DA+GT  krbtgt: ntlm, admin: administrator
  <forest-root-b> (forest root)           DA+GT  krbtgt: ntlm, admin: administrator
    └─ <child-of-b> (child)
Status: completed
```

The runtime banner correctly reports `2/3 compromised`, but the completion
monitor stopped the op anyway with reason `"all forests dominated
(post-exploitation complete)"` — the child domain's krbtgt was never
extracted, and the chain that would have produced it (`raise_child` from the
parent's PtH-acquired DA) never got a chance to run before the grace period
expired.

## Fix

Replace the forest-root projection on both sides of the set-difference with
the actual domain identifiers:

- Required-set inserts `target_domain`, `first_domain`, every
  `trusted_domains[*].domain`, and every `domain_controllers.keys()` entry
  verbatim (lowercased), with no `forest_root_of` collapse.
- Dropped the `is_cross_forest()` filter on the trust loop: any enumerated
  trust contributes a required domain, because parent_child / external /
  unknown trust types all represent distinct AD domains the operator wants
  compromised.
- Dominated-set is `dominated_domains` itself, also no `forest_root_of`
  collapse. Owning the child shouldn't satisfy the parent's slot any more
  than owning the parent should satisfy the child's.

Function name `compute_undominated_forests` stays — every call site
(13 automations, StateInner, SharedState) would have to be touched to rename,
and the historical name is purely cosmetic. Docstring updated to clarify
that the semantics are now "all discovered domains".

`forest_root_of()` becomes unused with this change and is deleted along with
its 5 dedicated unit tests.

## Tests

Updated:

- `undominated_child_domain_not_separate_forest` → renamed
  `undominated_parent_child_trust_makes_child_required`; assertion flipped to
  the new (correct) semantics.
- `undominated_unknown_trust_not_cross_forest` → renamed
  `undominated_trust_required_regardless_of_trust_type`; the trust-type
  filter is gone, so unknown-typed trusts now contribute requirements.
- `undominated_child_trust_domain_maps_to_parent_forest` → renamed
  `undominated_trust_domain_kept_verbatim_not_collapsed_to_root`; child
  trust domains are required as-is, no forest-root collapse.
- `undominated_target_and_first_same_forest` → renamed
  `undominated_target_and_first_same_forest_are_distinct_domains`; both
  domains appear in the required set even when one is a child of the other.
- `undominated_dc_discovered_before_trust_enum` — expanded to also assert
  the child-DC case alongside the cross-forest fabrikam DC case.

Added:

- `undominated_parent_and_child_both_dominated_empty` — the mirror case:
  once the child's krbtgt is captured, the required-set drains.
- `undominated_child_dc_keeps_child_required_even_without_trust` —
  reproduces the live op pattern: two forest roots dominated, a child DC
  known via recon but no trust enumeration, child must still appear in
  the required set.

Removed:

- The 5 `forest_root_of_*` unit tests, since the function itself is gone.

Verification:

- `cargo test -p ares-cli`: 3403 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: clean (catches the
  removed-function reference if any code path still calls it).

## Non-goals

- Renaming `compute_undominated_forests` to `compute_undominated_domains`,
  `all_forests_dominated()` to `all_domains_dominated()`, or the
  `all_forests_dominated_at` state field. Touches 13 automation files plus
  StateInner and SharedState; orthogonal to the semantic fix.
- Changing the runtime / loot banner that already correctly reports
  "N/M domains compromised". The misalignment lived in the completion
  check, not the display layer.
- Touching `auto_trust_follow` (PR #64) or the credaccess prompt
  (PR #65) — both already merged and out of scope here.

## Future follow-ups

- Rename pass to replace "forests" with "domains" across the public API and
  call sites for clarity; can ride a future readability-focused PR.
- A counterpart fix on the planner side that prioritizes `raise_child`
  against discovered child domains immediately after parent DA so the new
  required-set isn't left blocking on something the planner could trivially
  produce.
