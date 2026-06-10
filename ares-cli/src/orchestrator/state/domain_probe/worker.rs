//! Periodic worker that drains candidate domains and probes them.
//!
//! Spawned once at orchestrator startup. Every 30 seconds it pulls the
//! current candidate set, probes each entry concurrently, and:
//! - Confirmed → `promote_domain`
//! - Rejected  → `drop_candidate_domain`
//! - Indeterminate → `mark_candidate_probed` (back off; promotion can still
//!   come from a stronger source landing later)
//!
//! Tick cadence is deliberately slow (30s vs 5s for `discovery_poller`):
//! domain promotion is not on the hot path of attack flow, and we don't want
//! to hammer DNS for transient resolution failures. The worker is also
//! resilient to shutdown — it joins the existing `watch::Receiver<bool>`
//! pattern used by every other background task.

use std::sync::Arc;
use std::time::Duration;

use redis::aio::{ConnectionLike, ConnectionManager};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use super::{DomainProber, ProbeOutcome, ProbedDc};
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;
use ares_core::models::Host;

/// Register a DC discovered by a DNS SRV probe so `resolve_dc_ip` works for
/// the realm. Routes through `register_dc` (the canonical DC path) which also
/// derives + promotes the DC's domain. Best-effort: a failure is logged but
/// never blocks domain promotion. Generic over the connection type so the
/// real worker (`ConnectionManager`) and the mock-backed tests share one path.
async fn record_probed_dc<C>(state: &SharedState, queue: &TaskQueueCore<C>, dc: &ProbedDc)
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    let host = Host {
        ip: dc.ip.clone(),
        hostname: dc.hostname.clone(),
        os: String::new(),
        roles: Vec::new(),
        services: Vec::new(),
        is_dc: true,
        owned: false,
    };
    if let Err(e) = state.register_dc(queue, &host).await {
        debug!(hostname = %dc.hostname, ip = %dc.ip, err = %e, "register_dc after SRV probe failed");
    } else {
        info!(hostname = %dc.hostname, ip = %dc.ip, "Recorded DC from SRV probe");
    }
}

/// Wired-up dependencies for the probe worker.
pub struct DomainProbeContext {
    pub state: SharedState,
    pub queue: TaskQueueCore<ConnectionManager>,
    pub prober: Arc<dyn DomainProber>,
}

/// Tick interval. Long enough to avoid DNS hammering, short enough that a
/// candidate landing mid-operation gets confirmed within tens of seconds.
const TICK_SECS: u64 = 30;

/// Spawn the candidate-domain probe worker on a Tokio task.
pub fn spawn_domain_probe_worker(
    ctx: DomainProbeContext,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run(ctx, shutdown).await;
    })
}

async fn run(ctx: DomainProbeContext, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(TICK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!("Domain probe worker started");
    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
        drain_once(&ctx).await;
    }
    info!("Domain probe worker stopped");
}

async fn drain_once(ctx: &DomainProbeContext) {
    let pending = ctx.state.pending_candidate_domains().await;
    if pending.is_empty() {
        return;
    }
    debug!(count = pending.len(), "Probing candidate domains");
    for cand in pending {
        let outcome = ctx.prober.probe(&cand.fqdn).await;
        match outcome {
            ProbeOutcome::Confirmed { dc } => {
                if let Err(e) = ctx.state.promote_domain(&ctx.queue, &cand.fqdn).await {
                    debug!(domain = %cand.fqdn, err = %e, "Promote after probe failed");
                } else {
                    info!(domain = %cand.fqdn, "Promoted candidate domain after DNS SRV probe");
                }
                if let Some(dc) = dc {
                    record_probed_dc(&ctx.state, &ctx.queue, &dc).await;
                }
            }
            ProbeOutcome::Rejected(reason) => {
                if let Err(e) = ctx
                    .state
                    .drop_candidate_domain(&ctx.queue, &cand.fqdn)
                    .await
                {
                    debug!(domain = %cand.fqdn, err = %e, "Drop candidate failed");
                } else {
                    debug!(domain = %cand.fqdn, reason = %reason, "Dropped candidate domain (probe rejected)");
                }
            }
            ProbeOutcome::Indeterminate => {
                if let Err(e) = ctx
                    .state
                    .mark_candidate_probed(&ctx.queue, &cand.fqdn)
                    .await
                {
                    debug!(domain = %cand.fqdn, err = %e, "Mark probed failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::models::DomainEvidence;
    use ares_core::state::mock_redis::MockRedisConnection;
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    /// Test prober that returns a fixed outcome per FQDN.
    struct StubProber {
        results: Mutex<std::collections::HashMap<String, ProbeOutcome>>,
    }

    impl StubProber {
        fn new(entries: Vec<(&str, ProbeOutcome)>) -> Self {
            let mut map = std::collections::HashMap::new();
            for (k, v) in entries {
                map.insert(k.to_string(), v);
            }
            Self {
                results: Mutex::new(map),
            }
        }
    }

    #[async_trait]
    impl DomainProber for StubProber {
        async fn probe(&self, fqdn: &str) -> ProbeOutcome {
            self.results
                .lock()
                .unwrap()
                .get(fqdn)
                .cloned()
                .unwrap_or(ProbeOutcome::Indeterminate)
        }
    }

    /// Internal helper that runs one drain pass against a mock-backed state.
    /// We can't call `drain_once` directly because the public `DomainProbeContext`
    /// is parameterized on `ConnectionManager`, but the test substitutes
    /// `MockRedisConnection`. Instead we replicate the loop body by hand.
    async fn drain_with_mock(
        state: &SharedState,
        queue: &TaskQueueCore<MockRedisConnection>,
        prober: &dyn DomainProber,
    ) {
        let pending = state.pending_candidate_domains().await;
        for cand in pending {
            match prober.probe(&cand.fqdn).await {
                ProbeOutcome::Confirmed { dc } => {
                    state.promote_domain(queue, &cand.fqdn).await.unwrap();
                    if let Some(dc) = dc {
                        record_probed_dc(state, queue, &dc).await;
                    }
                }
                ProbeOutcome::Rejected(_) => {
                    state
                        .drop_candidate_domain(queue, &cand.fqdn)
                        .await
                        .unwrap();
                }
                ProbeOutcome::Indeterminate => {
                    state
                        .mark_candidate_probed(queue, &cand.fqdn)
                        .await
                        .unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn confirmed_candidate_is_promoted() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(&q, "contoso.local", DomainEvidence::HostnameInference, None)
            .await
            .unwrap();
        let prober = StubProber::new(vec![(
            "contoso.local",
            ProbeOutcome::Confirmed { dc: None },
        )]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.iter().any(|d| d == "contoso.local"));
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn confirmed_with_dc_records_resolvable_dc_ip() {
        // Follow-up: a probe that resolves the SRV target to an IP must record
        // the DC so `resolve_dc_ip` works for the realm — the gap that left a
        // probe-confirmed foreign realm in state.domains with no DC, blocking
        // foreign-group enum / cross-forest selectors from targeting it.
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "fabrikam.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        let prober = StubProber::new(vec![(
            "fabrikam.local",
            ProbeOutcome::Confirmed {
                dc: Some(ProbedDc {
                    hostname: "dc01.fabrikam.local".into(),
                    ip: "192.168.58.20".into(),
                }),
            },
        )]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(
            s.domains.iter().any(|d| d == "fabrikam.local"),
            "realm must be promoted, got {:?}",
            s.domains
        );
        assert_eq!(
            s.resolve_dc_ip("fabrikam.local").as_deref(),
            Some("192.168.58.20"),
            "DC IP from the SRV probe must be recorded so resolve_dc_ip succeeds"
        );
    }

    #[tokio::test]
    async fn rejected_candidate_is_dropped() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "fake.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        let prober = StubProber::new(vec![("fake.contoso.local", ProbeOutcome::Rejected("nx"))]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        assert!(s.candidate_domains.is_empty());
    }

    #[tokio::test]
    async fn indeterminate_candidate_marked_probed_but_kept() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "transient.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        let prober = StubProber::new(vec![]);
        drain_with_mock(&state, &q, &prober).await;
        let s = state.inner.read().await;
        assert!(s.domains.is_empty());
        let cand = s.candidate_domains.get("transient.contoso.local").unwrap();
        assert!(cand.probed);
    }

    #[tokio::test]
    async fn dc_zone_apex_hostname_promotes_child_after_probe_confirms() {
        // End-to-end regression for the child-domain alias bug: a
        // child-domain DC's SMB hostname query returns the bare domain
        // (`child.contoso.local`) instead of the proper FQDN
        // (`dc02.child.contoso.local`). The hosts.rs publisher's parts[1..]
        // extractor only sees the parent suffix; the child must reach
        // state.domains via the whole-hostname candidate + DNS SRV probe.
        use ares_core::models::Host;

        let state = SharedState::new("op-1".into());
        let q = mock_queue();

        let host = Host {
            ip: "192.168.58.11".into(),
            hostname: "child.contoso.local".into(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: true,
            owned: false,
        };
        state.publish_host(&q, host).await.unwrap();

        // Parent domain promotes immediately (DcSelfReport evidence on
        // parts[1..]). Child is held as a candidate awaiting SRV probe.
        {
            let s = state.inner.read().await;
            assert!(
                s.domains.iter().any(|d| d == "contoso.local"),
                "parent should auto-promote, got {:?}",
                s.domains
            );
            assert!(
                s.candidate_domains.contains_key("child.contoso.local"),
                "child must be queued for probe, got candidates {:?}",
                s.candidate_domains.keys().collect::<Vec<_>>()
            );
        }

        // Simulate DNS SRV probe confirming the child is a real domain.
        let prober = StubProber::new(vec![(
            "child.contoso.local",
            ProbeOutcome::Confirmed { dc: None },
        )]);
        drain_with_mock(&state, &q, &prober).await;

        let s = state.inner.read().await;
        assert!(
            s.domains.iter().any(|d| d == "child.contoso.local"),
            "child should be promoted after probe confirms, got {:?}",
            s.domains
        );
    }

    #[tokio::test]
    async fn dc_normal_fqdn_zone_apex_candidate_rejected_by_probe() {
        // Negative regression: the zone-apex probe path must NOT pollute
        // state.domains with ordinary DC host FQDNs (`dc01.contoso.local`).
        // The candidate gets recorded but the SRV probe rejects it; the
        // child of a known parent can't sneak in via parent_known
        // corroboration because the new probe-only path bypasses that
        // shortcut.
        use ares_core::models::Host;

        let state = SharedState::new("op-1".into());
        let q = mock_queue();

        let host = Host {
            ip: "192.168.58.10".into(),
            hostname: "dc01.contoso.local".into(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: true,
            owned: false,
        };
        state.publish_host(&q, host).await.unwrap();

        let prober = StubProber::new(vec![(
            "dc01.contoso.local",
            ProbeOutcome::Rejected("no SRV"),
        )]);
        drain_with_mock(&state, &q, &prober).await;

        let s = state.inner.read().await;
        assert!(
            s.domains.contains(&"contoso.local".to_string()),
            "parent must still be promoted"
        );
        assert!(
            !s.domains.contains(&"dc01.contoso.local".to_string()),
            "DC host FQDN must NEVER reach state.domains, got {:?}",
            s.domains
        );
        assert!(
            !s.candidate_domains.contains_key("dc01.contoso.local"),
            "probe-rejected candidate should be dropped, not lingering"
        );
    }

    #[tokio::test]
    async fn probed_candidates_are_not_repolled() {
        let state = SharedState::new("op-1".into());
        let q = mock_queue();
        state
            .publish_candidate_domain(
                &q,
                "transient.contoso.local",
                DomainEvidence::HostnameInference,
                None,
            )
            .await
            .unwrap();
        // First pass: indeterminate → marked probed.
        let prober = StubProber::new(vec![]);
        drain_with_mock(&state, &q, &prober).await;
        // Second pass should now skip the already-probed candidate.
        let pending = state.pending_candidate_domains().await;
        assert!(pending.is_empty());
    }
}
