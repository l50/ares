use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Pretty-print the resolved configuration
    Show {
        /// Only show model assignments per role
        #[arg(long)]
        models: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Validate the configuration file
    Validate {
        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },

    /// Set the model for one or all agent roles (edits the YAML in-place)
    ///
    /// Forms: `set-model <role> <model>` or `set-model --all <model>`.
    SetModel {
        /// Without --all: the agent role (e.g. orchestrator, recon).
        /// With --all: the model identifier.
        arg1: Option<String>,

        /// The model identifier when setting a single role (omit with --all).
        arg2: Option<String>,

        /// Set all roles to the given model: `set-model --all <model>`
        #[arg(long)]
        all: bool,

        /// Path to config file (overrides ARES_CONFIG and defaults)
        #[arg(long, env = "ARES_CONFIG")]
        config: Option<String>,
    },
}
