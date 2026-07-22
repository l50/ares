//! Operation teardown — journal every persistent mutation an operation makes
//! against a target, then reverse it and validate the reversal.
//!
//! Pieces:
//! - [`journal`]  — the durable per-op record of mutations (Redis LIST).
//! - [`dispatcher::JournalingToolDispatcher`] — the decorator that captures
//!   mutations at the single `ToolDispatcher` choke point (LLM + deterministic).
//! - [`registry`] — maps each mutation to its inverse and a reversibility class.
//! - [`engine`]   — reads the journal (LIFO), reverses it, and reports.
//!
//! Entry points: the standalone `ares ops teardown <op-id>` subcommand (which
//! survives a SIGKILLed op), and — later — an in-process post-op pass.

pub mod capture;
pub mod dispatcher;
pub mod engine;
pub mod journal;
pub mod registry;

pub use dispatcher::JournalingToolDispatcher;
pub use engine::{run_teardown, TeardownOptions};
