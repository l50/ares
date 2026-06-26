use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum BenchmarkCommands {
    /// Capture a complete benchmark snapshot from a finished operation.
    ///
    /// Exports the full Loki log state (all streams, noise included), fired
    /// Grafana alerts, red team state, and ground truth into a self-contained
    /// snapshot directory. This snapshot can later be replayed for deterministic
    /// blue team evaluation.
    Capture {
        /// Operation ID to capture (or use --latest)
        operation_id: Option<String>,

        /// Use the most recently completed operation
        #[arg(long)]
        latest: bool,

        /// Output directory for the snapshot
        #[arg(long, default_value = "benchmarks")]
        output_dir: String,

        /// S3 bucket to sync snapshot to after capture
        #[arg(long)]
        s3_bucket: Option<String>,

        /// Hours before attack start to include in the capture window
        #[arg(long, default_value_t = 1)]
        pre_window_hours: u32,

        /// Minutes after attack end to include in the capture window
        #[arg(long, default_value_t = 30)]
        post_window_minutes: u32,
    },

    /// Import a snapshot's Loki data into a target Loki instance.
    ///
    /// Reads the JSONL files from a snapshot directory and pushes them into
    /// the specified Loki instance. The target must be configured with
    /// `reject_old_samples: false` to accept historical timestamps.
    Load {
        /// Path to the snapshot directory
        snapshot_dir: String,

        /// Target Loki URL (e.g. http://localhost:3100)
        #[arg(long)]
        loki_url: String,

        /// Auth token for the target Loki instance
        #[arg(long)]
        loki_token: Option<String>,
    },

    /// Run a full benchmark replay: ephemeral Loki, import, investigate, score.
    ///
    /// Spins up an isolated Loki instance, imports the snapshot data, triggers
    /// a blue team investigation (from the captured alert or operation state),
    /// scores the investigation against ground truth, and tears everything down.
    Run {
        /// Path to the snapshot directory
        snapshot_dir: String,

        /// Loki mode: "ephemeral" creates a K8s pod, "external" uses --loki-url
        #[arg(long, default_value = "ephemeral")]
        loki_mode: String,

        /// External Loki URL (required when --loki-mode=external)
        #[arg(long)]
        loki_url: Option<String>,

        /// Trigger mode: "alert-replay" uses the first captured alert,
        /// "operation" uses the full operation context (like `blue from-operation`)
        #[arg(long, default_value = "alert-replay")]
        trigger_mode: String,

        /// Output directory for benchmark results
        #[arg(long, default_value = "benchmark-results")]
        output_dir: String,

        /// LLM model for the blue team investigation
        #[arg(long)]
        model: Option<String>,

        /// Maximum agent steps per investigation
        #[arg(long, default_value_t = 25)]
        max_steps: u32,

        /// K8s namespace for ephemeral Loki (when --loki-mode=ephemeral)
        #[arg(long, default_value = "attack-simulation")]
        namespace: String,
    },
}
