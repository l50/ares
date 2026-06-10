//! DNS SRV-based domain prober.
//!
//! Real AD domains publish `_ldap._tcp.dc._msdcs.<domain>` SRV records. This
//! is the same lookup that NetExec, runZero, and BloodHound use to discover
//! domain controllers, and it serves equally well as a binary "is this a real
//! AD domain?" probe.
//!
//! Resolver behavior:
//! - We construct a `TokioResolver` from the system resolv.conf so we
//!   pick up whatever recursive resolver the operator has configured (often
//!   the same DNS server an attacker would query during real-world recon).
//! - NXDOMAIN / NoRecordsFound → `Rejected` (the suffix is definitely not AD).
//! - Successful answer with at least one SRV record → `Confirmed`.
//! - I/O / timeout / refused → `Indeterminate` (we'll retry next tick).

use async_trait::async_trait;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;

use super::{DomainProber, ProbeOutcome, ProbedDc};

/// Real DNS prober. Wraps a hickory `TokioResolver`.
pub struct DnsSrvProber {
    resolver: TokioResolver,
}

impl DnsSrvProber {
    /// Construct using the system resolver (resolv.conf on Unix).
    /// Falls back to a Cloudflare/Google config if system config is unreadable
    /// — we still need *something* to query in container environments where
    /// /etc/resolv.conf may be missing.
    pub fn from_system() -> Self {
        let resolver = TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .unwrap_or_else(|e| {
                tracing::warn!(err = %e, "DNS SRV prober: system resolver unreadable, falling back to defaults");
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .expect("default ResolverConfig should always build")
            });
        Self { resolver }
    }
}

#[async_trait]
impl DomainProber for DnsSrvProber {
    async fn probe(&self, fqdn: &str) -> ProbeOutcome {
        let query = format!("_ldap._tcp.dc._msdcs.{}.", fqdn.trim_end_matches('.'));
        match self.resolver.srv_lookup(&query).await {
            Ok(answer) => {
                let answers = answer.answers();
                if answers.is_empty() {
                    return ProbeOutcome::Rejected("no SRV records");
                }
                // SRV confirms the realm. Best-effort: resolve the SRV target
                // (the DC's hostname) to an A/AAAA record so the realm gets a
                // usable DC IP. The `target` field is the DC FQDN. If the A
                // lookup fails we still confirm — `dc: None` preserves the
                // prior confirm-only behavior rather than dropping the realm.
                let target_host: Option<String> = answers.iter().find_map(|rec| match &rec.data {
                    RData::SRV(srv) => {
                        let h = srv.target.to_utf8();
                        let h = h.trim_end_matches('.').to_string();
                        if h.is_empty() {
                            None
                        } else {
                            Some(h)
                        }
                    }
                    _ => None,
                });
                let dc = match target_host {
                    Some(host) => match self.resolver.lookup_ip(format!("{host}.")).await {
                        Ok(ips) => ips.iter().next().map(|ip| ProbedDc {
                            hostname: host,
                            ip: ip.to_string(),
                        }),
                        Err(e) => {
                            tracing::debug!(target = %host, err = %e, "DNS SRV: target A lookup failed; confirming without DC IP");
                            None
                        }
                    },
                    None => None,
                };
                ProbeOutcome::Confirmed { dc }
            }
            Err(e) => match &e {
                NetError::Dns(DnsError::NoRecordsFound(_)) => {
                    ProbeOutcome::Rejected("NXDOMAIN / no _ldap._tcp.dc._msdcs SRV")
                }
                _ => {
                    tracing::debug!(fqdn = %fqdn, err = %e, "DNS SRV probe transient error");
                    ProbeOutcome::Indeterminate
                }
            },
        }
    }
}
