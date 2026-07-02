use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum BenchmarkCommands {
    /// Capture a complete benchmark snapshot from a finished operation.
    ///
    /// Exports the full Loki log state (all streams, noise included), fired
    /// Grafana alerts, red team state, and ground truth into a self-contained
    /// snapshot directory. Automatically uploads to the benchmark S3 bucket.
    Capture {
        /// Operation ID to capture (or use --latest)
        operation_id: Option<String>,

        /// Use the most recently completed operation
        #[arg(long)]
        latest: bool,

        /// Output directory for the snapshot
        #[arg(long, default_value = "benchmarks")]
        output_dir: String,

        /// Hours before attack start to include in the capture window
        #[arg(long, default_value_t = 1)]
        pre_window_hours: u32,

        /// Minutes after attack end to include in the capture window
        #[arg(long, default_value_t = 30)]
        post_window_minutes: u32,

        /// Skip automatic S3 upload after capture
        #[arg(long)]
        no_upload: bool,
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

    /// Run a full benchmark replay: provision EC2, load Loki, investigate, score.
    ///
    /// Provisions an ephemeral EC2 instance with Loki in the labs account,
    /// downloads the snapshot data, triggers a blue team investigation, scores
    /// the results against ground truth, and terminates the EC2 instance.
    ///
    /// Two replay modes are supported:
    /// - `static` (default): all data is pre-loaded, agent knows the full attack window.
    /// - `timeline`: a quiet period precedes the first alert, trigger uses
    ///   alert-replay (no attack_window_end), simulating an unfolding attack.
    Run {
        /// Snapshot ID (operation ID, e.g. op-20260630-222023).
        /// Downloaded from the benchmark S3 bucket.
        snapshot: String,

        /// Local snapshot directory (overrides S3 download for local testing)
        #[arg(long)]
        snapshot_dir: Option<String>,

        /// Replay mode: "static" loads all data upfront with full attack window;
        /// "timeline" adds a quiet period and uses alert-replay trigger (no end window)
        #[arg(long, default_value = "static")]
        replay_mode: String,

        /// Trigger mode: "alert-replay" uses the first captured alert,
        /// "operation" uses the full operation context (like `blue from-operation`).
        /// In timeline mode, this is always overridden to "alert-replay".
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

        /// Seconds of quiet time before first alert delivery (timeline mode).
        /// Simulates the agent being deployed to a "normal" environment.
        /// Set to 0 to skip. Default: random 60-300s.
        #[arg(long)]
        quiet_period: Option<f64>,

        /// Time compression factor for alert delivery (timeline mode).
        /// 1.0 = real-time, 10.0 = 10x faster, 0 = instant delivery.
        /// Default: 10.0.
        #[arg(long, default_value_t = 10.0)]
        time_compression: f64,
    },

    /// List available benchmark snapshots from S3.
    ///
    /// Shows snapshot metadata: operation ID, target domain, date, techniques,
    /// whether domain admin was achieved, and credential count.
    List,
}
