//! Active probes that confirm whether a candidate FQDN is a real AD domain.
//!
//! `publishing::domains` records weak-evidence FQDNs as `CandidateDomain`
//! entries. The worker in this module periodically drains those candidates,
//! runs a probe (currently DNS SRV for `_ldap._tcp.dc._msdcs.<fqdn>`), and
//! either promotes confirmed results or drops rejections.
//!
//! Design notes:
//! - The trait abstracts the probe so unit tests can swap in a deterministic
//!   stub. Real prober uses `hickory-resolver` against the system resolver,
//!   which mirrors what BloodHound / NetExec / runZero do.
//! - DNS SRV is a reliable positive signal *and* a useful negative signal:
//!   if `_ldap._tcp.dc._msdcs.<fqdn>` does not resolve, the suffix is not an
//!   AD domain. We treat NXDOMAIN as `Rejected`; transient errors stay
//!   `Indeterminate` so we retry later.
//! - CLDAP NetLogon ping (UDP/389) is the gold-standard probe used by
//!   `DsGetDcName`. It is intentionally not implemented in this first cut —
//!   it requires ~300 LoC of BER ASN.1 + raw UDP and adds a dependency. DNS
//!   SRV alone matches industry practice for asset discovery and yields the
//!   correctness improvement we want without the implementation cost.

pub mod dns_srv;
pub mod worker;

use async_trait::async_trait;

pub use dns_srv::DnsSrvProber;
pub use worker::{spawn_domain_probe_worker, DomainProbeContext};

/// Result of probing a candidate domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe positively identified an AD domain. Promote.
    ///
    /// `dc` optionally carries the domain controller the probe resolved from
    /// the `_ldap._tcp.dc._msdcs.<fqdn>` SRV record (target hostname + its
    /// resolved A record). When present, the worker registers it so
    /// `resolve_dc_ip` works for this realm — without it a probe-confirmed
    /// foreign realm lands in `state.domains` but has no DC IP, so the
    /// selectors that need one (foreign-group enum, cross-forest, ADCS) can't
    /// target it directly. `None` preserves the prior confirm-only behavior
    /// (e.g. SRV resolved but the target A lookup failed).
    Confirmed { dc: Option<ProbedDc> },
    /// The probe authoritatively says this is not an AD domain. Drop.
    Rejected(&'static str),
    /// Transient error or insufficient signal. Leave the candidate to retry.
    Indeterminate,
}

/// A domain controller resolved during a DNS SRV probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbedDc {
    /// SRV target hostname, e.g. `dc01.contoso.local`.
    pub hostname: String,
    /// Resolved IPv4/IPv6 address of `hostname`.
    pub ip: String,
}

/// Pluggable domain prober. Implementers return a `ProbeOutcome` for an FQDN.
#[async_trait]
pub trait DomainProber: Send + Sync {
    async fn probe(&self, fqdn: &str) -> ProbeOutcome;
}
