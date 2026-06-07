//! Task routing — decides which agent queue receives a task.
//!
//! Routes by role, respects per-role concurrency limits, tracks active tasks.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Per-role tracking of in-flight tasks.
#[derive(Debug, Clone)]
pub struct ActiveTask {
    pub task_id: String,
    pub task_type: String,
    pub role: String,
    pub submitted_at: std::time::Instant,
    /// Last forward-progress timestamp — bumped via [`ActiveTaskTracker::touch`]
    /// on each LLM response. The staleness sweep ([`ActiveTaskTracker::stale_tasks`])
    /// evicts on inactivity here, not total runtime (`submitted_at`), so a
    /// slow-but-progressing agent loop (a reasoning model taking minutes per
    /// step) isn't killed mid-flight and its in-flight credential slot reclaimed
    /// out from under it.
    pub last_activity: std::time::Instant,
    /// `"user@domain"` when the task is gated by `CredentialInflight`. The
    /// caller that successfully removes this task from the tracker is
    /// responsible for releasing the corresponding slot. Carrying it on the
    /// task makes the release happen even when stale-task cleanup evicts a
    /// task whose spawned future is still hung — otherwise the slot leaks
    /// and every subsequent task with the same credential gets deferred
    /// forever.
    pub credential_key: Option<String>,
}

/// Thread-safe tracker for all in-flight tasks.
#[derive(Debug, Clone)]
pub struct ActiveTaskTracker {
    inner: Arc<Mutex<TrackerInner>>,
}

#[derive(Debug, Default)]
struct TrackerInner {
    /// task_id -> ActiveTask
    tasks: HashMap<String, ActiveTask>,
    /// role -> count of active tasks
    role_counts: HashMap<String, usize>,
}

impl Default for ActiveTaskTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveTaskTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerInner::default())),
        }
    }

    /// Register a newly submitted task.
    pub async fn add(&self, task: ActiveTask) {
        let mut inner = self.inner.lock().await;
        *inner.role_counts.entry(task.role.clone()).or_insert(0) += 1;
        inner.tasks.insert(task.task_id.clone(), task);
    }

    /// Remove a completed/failed task. Returns the task if it was tracked.
    pub async fn remove(&self, task_id: &str) -> Option<ActiveTask> {
        let mut inner = self.inner.lock().await;
        if let Some(task) = inner.tasks.remove(task_id) {
            if let Some(count) = inner.role_counts.get_mut(&task.role) {
                *count = count.saturating_sub(1);
            }
            Some(task)
        } else {
            None
        }
    }

    /// Record forward progress for a tracked task, resetting its staleness
    /// clock. Called on each LLM response (via the per-task activity callback)
    /// so an actively-working agent loop is not evicted by [`Self::stale_tasks`].
    /// No-op if the task is no longer tracked (already completed or evicted).
    pub async fn touch(&self, task_id: &str) {
        let mut inner = self.inner.lock().await;
        if let Some(task) = inner.tasks.get_mut(task_id) {
            task.last_activity = std::time::Instant::now();
        }
    }

    /// Number of active tasks for a role.
    pub async fn count_for_role(&self, role: &str) -> usize {
        let inner = self.inner.lock().await;
        inner.role_counts.get(role).copied().unwrap_or(0)
    }

    /// Total number of active LLM-consuming tasks (excludes `crack`, `command`).
    pub async fn llm_task_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner
            .tasks
            .values()
            .filter(|t| !is_non_llm_task(&t.task_type))
            .count()
    }

    /// Total active tasks across all roles.
    pub async fn total(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.tasks.len()
    }

    /// Get all tracked task IDs (for result polling).
    pub async fn task_ids(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        inner.tasks.keys().cloned().collect()
    }

    /// Get tasks that have made no forward progress for `max_age` and have not
    /// received a result. Eviction is keyed on `last_activity` (bumped by
    /// [`Self::touch`]), not `submitted_at`, so a long-but-actively-progressing
    /// agent loop survives while a genuinely wedged one is still reaped.
    ///
    /// Tests-only — production cleanup uses [`Self::remove_stale_tasks`], which
    /// finds and removes stale tasks atomically under a single lock. Keeping
    /// the snapshot-only helper around lets the staleness regression suite
    /// (added in #35) verify activity-based eviction without mutating tracker
    /// state.
    #[cfg(test)]
    pub async fn stale_tasks(&self, max_age: std::time::Duration) -> Vec<ActiveTask> {
        let inner = self.inner.lock().await;
        let cutoff = std::time::Instant::now() - max_age;
        inner
            .tasks
            .values()
            .filter(|t| t.last_activity < cutoff)
            .cloned()
            .collect()
    }

    /// Atomically identify and remove every task whose `last_activity` is older
    /// than `max_age`. Returns the removed tasks so the caller can run auxiliary
    /// cleanup (credential slot release, queue status writes, etc.).
    ///
    /// This is preferred over `stale_tasks` followed by per-task `remove`
    /// because it performs the entire eviction under a single lock acquisition.
    /// The split version is observable in two states by other callers (the
    /// throttler in particular): between `stale_tasks` returning a snapshot and
    /// `remove` being called per-task, the tracker still reports those tasks as
    /// in-flight, so `Throttler::llm_task_count` and `count_for_role` overcount
    /// — and *both* counters can leak if a per-task remove ever fails to land
    /// (e.g. a future refactor that bails on the first error in the loop).
    /// Doing it atomically here makes the decrement at the cleanup site the
    /// same single source of truth as `remove`: `tasks.remove` paired with
    /// `role_counts saturating_sub`. Floors at 0, so calling cleanup twice is
    /// idempotent.
    pub async fn remove_stale_tasks(&self, max_age: std::time::Duration) -> Vec<ActiveTask> {
        let mut inner = self.inner.lock().await;
        let cutoff = std::time::Instant::now() - max_age;
        let stale_ids: Vec<String> = inner
            .tasks
            .values()
            .filter(|t| t.last_activity < cutoff)
            .map(|t| t.task_id.clone())
            .collect();
        let mut removed = Vec::with_capacity(stale_ids.len());
        for id in stale_ids {
            if let Some(task) = inner.tasks.remove(&id) {
                if let Some(count) = inner.role_counts.get_mut(&task.role) {
                    *count = count.saturating_sub(1);
                }
                removed.push(task);
            }
        }
        removed
    }
}

/// Task types that do not consume LLM tokens.
const NON_LLM_TYPES: &[&str] = &["crack", "command"];

pub fn is_non_llm_task(task_type: &str) -> bool {
    NON_LLM_TYPES.contains(&task_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_llm_task_classification() {
        assert!(is_non_llm_task("crack"));
        assert!(is_non_llm_task("command"));
        assert!(!is_non_llm_task("recon"));
        assert!(!is_non_llm_task("exploit"));
        assert!(!is_non_llm_task("privesc_enumeration"));
        assert!(!is_non_llm_task(""));
    }

    #[tokio::test]
    async fn tracker_add_remove() {
        let tracker = ActiveTaskTracker::new();
        assert_eq!(tracker.total().await, 0);

        tracker
            .add(ActiveTask {
                task_id: "t1".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        assert_eq!(tracker.total().await, 1);
        assert_eq!(tracker.count_for_role("recon").await, 1);
        assert_eq!(tracker.count_for_role("lateral").await, 0);

        let removed = tracker.remove("t1").await;
        assert!(removed.is_some());
        assert_eq!(tracker.total().await, 0);
        assert_eq!(tracker.count_for_role("recon").await, 0);
    }

    #[tokio::test]
    async fn tracker_remove_nonexistent() {
        let tracker = ActiveTaskTracker::new();
        assert!(tracker.remove("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn llm_count_excludes_non_llm() {
        let tracker = ActiveTaskTracker::new();

        for (id, task_type, role) in [
            ("t1", "recon", "recon"),
            ("t2", "crack", "cracker"),
            ("t3", "command", "lateral"),
            ("t4", "exploit", "privesc"),
        ] {
            tracker
                .add(ActiveTask {
                    task_id: id.into(),
                    task_type: task_type.into(),
                    role: role.into(),
                    submitted_at: std::time::Instant::now(),
                    last_activity: std::time::Instant::now(),
                    credential_key: None,
                })
                .await;
        }

        assert_eq!(tracker.total().await, 4);
        assert_eq!(tracker.llm_task_count().await, 2); // recon + exploit
    }

    #[tokio::test]
    async fn stale_tasks_detection() {
        let tracker = ActiveTaskTracker::new();

        tracker
            .add(ActiveTask {
                task_id: "old".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(120),
                last_activity: std::time::Instant::now() - std::time::Duration::from_secs(120),
                credential_key: None,
            })
            .await;

        tracker
            .add(ActiveTask {
                task_id: "new".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        let stale = tracker
            .stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].task_id, "old");
    }

    #[tokio::test]
    async fn touch_resets_staleness() {
        let tracker = ActiveTaskTracker::new();

        // A task submitted long ago whose last activity is also stale: without
        // a touch it would be evicted by the staleness sweep.
        tracker
            .add(ActiveTask {
                task_id: "slow".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(600),
                last_activity: std::time::Instant::now() - std::time::Duration::from_secs(600),
                credential_key: None,
            })
            .await;

        // Confirm it is stale before any progress signal.
        assert_eq!(
            tracker
                .stale_tasks(std::time::Duration::from_secs(300))
                .await
                .len(),
            1,
            "task with old last_activity should be stale"
        );

        // An LLM step lands → touch resets the activity clock. The task has now
        // been running 600s total but just made progress, so it must NOT evict.
        tracker.touch("slow").await;
        assert!(
            tracker
                .stale_tasks(std::time::Duration::from_secs(300))
                .await
                .is_empty(),
            "a freshly-touched task must not be evicted regardless of total runtime"
        );

        // Touch on an unknown task is a harmless no-op.
        tracker.touch("does-not-exist").await;
    }

    #[tokio::test]
    async fn task_ids_collected() {
        let tracker = ActiveTaskTracker::new();
        tracker
            .add(ActiveTask {
                task_id: "a".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;
        tracker
            .add(ActiveTask {
                task_id: "b".into(),
                task_type: "exploit".into(),
                role: "privesc".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        let mut ids = tracker.task_ids().await;
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn role_count_saturating_sub() {
        let tracker = ActiveTaskTracker::new();
        // Double-remove shouldn't panic or underflow
        tracker
            .add(ActiveTask {
                task_id: "t1".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;
        tracker.remove("t1").await;
        tracker.remove("t1").await; // second remove returns None
        assert_eq!(tracker.count_for_role("recon").await, 0);
    }

    #[tokio::test]
    async fn remove_stale_decrements_llm_and_role_counts() {
        // Reproduces the wedge symptom from the production log: a stale task
        // is evicted by the cleanup sweep, and both the global LLM counter
        // AND the per-role counter must drop. Before the fix the per-task
        // path could leak: the throttler then thinks the role slot is still
        // held, defers every new dispatch, and the orchestrator goes idle.
        let tracker = ActiveTaskTracker::new();
        tracker
            .add(ActiveTask {
                task_id: "stale".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(120),
                last_activity: std::time::Instant::now() - std::time::Duration::from_secs(120),
                credential_key: None,
            })
            .await;
        tracker
            .add(ActiveTask {
                task_id: "fresh".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        assert_eq!(tracker.llm_task_count().await, 2);
        assert_eq!(tracker.count_for_role("recon").await, 2);

        let removed = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;

        assert_eq!(removed.len(), 1, "exactly one stale task should evict");
        assert_eq!(removed[0].task_id, "stale");
        assert_eq!(
            tracker.llm_task_count().await,
            1,
            "global LLM counter must reflect the eviction"
        );
        assert_eq!(
            tracker.count_for_role("recon").await,
            1,
            "per-role counter must reflect the eviction — this is the slot-leak fix"
        );
    }

    #[tokio::test]
    async fn remove_stale_idempotent_under_repeated_calls() {
        // Calling the cleanup twice (as can happen if a sweep races with
        // another caller draining the same task) must not underflow the
        // per-role counter. `saturating_sub` is the floor — second call sees
        // an empty tracker and is a no-op.
        let tracker = ActiveTaskTracker::new();
        tracker
            .add(ActiveTask {
                task_id: "stale".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(120),
                last_activity: std::time::Instant::now() - std::time::Duration::from_secs(120),
                credential_key: None,
            })
            .await;

        let first = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert_eq!(first.len(), 1);
        assert_eq!(tracker.count_for_role("recon").await, 0);

        let second = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert!(second.is_empty(), "no tasks left to remove");
        assert_eq!(
            tracker.count_for_role("recon").await,
            0,
            "per-role counter must floor at 0, never underflow"
        );
        assert_eq!(tracker.llm_task_count().await, 0);
    }

    #[tokio::test]
    async fn remove_stale_leaves_active_task_intact() {
        // A task whose `last_activity` is recent must NOT be removed by the
        // cleanup. Symmetric to the wedge bug — over-eager eviction would
        // reap actively-progressing agent loops, which PR #35 explicitly
        // guarded against by switching to activity-based staleness.
        let tracker = ActiveTaskTracker::new();
        tracker
            .add(ActiveTask {
                task_id: "active".into(),
                task_type: "exploit".into(),
                role: "privesc".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(600),
                last_activity: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        let removed = tracker
            .remove_stale_tasks(std::time::Duration::from_secs(60))
            .await;

        assert!(removed.is_empty(), "active task must not be evicted");
        assert_eq!(tracker.llm_task_count().await, 1);
        assert_eq!(tracker.count_for_role("privesc").await, 1);
    }
}
