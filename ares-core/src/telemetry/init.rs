//! Telemetry pipeline initialization and shutdown.
//!
//! Call [`init_telemetry`] once at application startup. It returns a
//! [`TelemetryGuard`] whose [`shutdown`](TelemetryGuard::shutdown) method
//! flushes remaining spans on graceful exit.

use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configuration for telemetry initialization.
pub struct TelemetryConfig {
    /// Service name reported in OTel resource attributes.
    pub service_name: String,
    /// Default log filter when `RUST_LOG` is not set.
    pub default_filter: String,
    /// Show the `target` column in console output.
    pub show_target: bool,
}

impl TelemetryConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            default_filter: "info".to_string(),
            show_target: false,
        }
    }

    pub fn with_default_filter(mut self, filter: impl Into<String>) -> Self {
        self.default_filter = filter.into();
        self
    }

    pub fn with_show_target(mut self, show: bool) -> Self {
        self.show_target = show;
        self
    }
}

/// Handle returned by [`init_telemetry`]. Call [`shutdown`](Self::shutdown) on
/// graceful exit to flush pending spans.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
    /// `true` when this guard is the no-op shim returned after a redundant
    /// [`init_telemetry`] call. Such guards do not own a provider and must
    /// not run shutdown.
    already_initialized: bool,
}

impl TelemetryGuard {
    /// Flush and shut down the tracer provider. Safe to call multiple times.
    pub fn shutdown(&mut self) {
        if self.already_initialized {
            return;
        }
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("telemetry shutdown error: {e}");
            }
        }
    }

    /// Returns true if this guard is a no-op shim because the tracing
    /// subscriber had already been installed by a previous call. Exposed for
    /// the regression test.
    #[cfg(test)]
    pub fn is_noop(&self) -> bool {
        self.already_initialized
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Initialize the telemetry pipeline.
///
/// When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT`
/// is set, spans are exported via OTLP. Transport is selected by
/// `OTEL_EXPORTER_OTLP_PROTOCOL`: `http/protobuf` for HTTP, gRPC otherwise.
/// Without an endpoint, only console logging is active (no-op for traces).
///
/// Returns a [`TelemetryGuard`] that must be kept alive for the duration of the
/// program. Dropping it flushes remaining spans.
pub fn init_telemetry(config: TelemetryConfig) -> TelemetryGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.default_filter));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(config.show_target)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Try to set up OTLP exporter if endpoint is configured.
    let otel = try_init_otel_provider(&config.service_name);

    match otel {
        Some(provider) => {
            let tracer = provider.tracer(config.service_name.clone());
            let otel_layer = OpenTelemetryLayer::new(tracer);

            // `try_init` returns Err if a global subscriber is already set
            // (e.g. the CLI initialized one before dispatching to a long-running
            // subcommand that wants its own service name). Treat that as a
            // soft success: log a notice and return a no-op guard, instead of
            // panicking the process at startup.
            let init_result = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(otel_layer)
                .try_init();

            match init_result {
                Ok(()) => {
                    tracing::info!(
                        service = %config.service_name,
                        "telemetry initialized with OTLP exporter"
                    );
                    TelemetryGuard {
                        provider: Some(provider),
                        already_initialized: false,
                    }
                }
                Err(_) => {
                    // Subscriber already installed — discard the freshly built
                    // OTel provider so we don't leak a BatchSpanProcessor that
                    // nothing is wired into. The pre-existing subscriber stays
                    // authoritative for this process.
                    if let Err(e) = provider.shutdown() {
                        eprintln!("telemetry: dropped redundant provider shutdown error: {e}");
                    }
                    tracing::debug!(
                        service = %config.service_name,
                        "telemetry already initialized by earlier call; using existing subscriber"
                    );
                    TelemetryGuard {
                        provider: None,
                        already_initialized: true,
                    }
                }
            }
        }
        None => {
            let init_result = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .try_init();

            match init_result {
                Ok(()) => TelemetryGuard {
                    provider: None,
                    already_initialized: false,
                },
                Err(_) => TelemetryGuard {
                    provider: None,
                    already_initialized: true,
                },
            }
        }
    }
}

/// Convenience wrapper: call `guard.shutdown()`.
pub fn shutdown_telemetry(guard: &mut TelemetryGuard) {
    guard.shutdown();
}

/// Attempt to build an OTLP span exporter + tracer provider. Returns `None` if
/// no OTLP endpoint is configured (neither `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
/// nor `OTEL_EXPORTER_OTLP_ENDPOINT`).
fn try_init_otel_provider(service_name: &str) -> Option<SdkTracerProvider> {
    // The OTel SDK reads OTEL_EXPORTER_OTLP_* env vars automatically.
    // We check presence and validity so we can skip provider creation entirely
    // when no collector is reachable — avoids noisy connection-refused or
    // RelativeUrlWithoutBase errors from the BatchSpanProcessor.
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT"))
        .ok()
        .filter(|v| !v.is_empty());

    let endpoint = endpoint?;

    // Reject non-absolute URLs early (e.g. un-substituted template placeholders)
    // to avoid noisy BatchSpanProcessor errors every flush interval.
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        eprintln!("ignoring OTEL endpoint: not an absolute URL: {endpoint:?}");
        return None;
    }

    // W3C TraceContext propagator for cross-service context propagation.
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    // Select transport based on OTEL_EXPORTER_OTLP_PROTOCOL (default: gRPC).
    let protocol = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").unwrap_or_default();
    let exporter = if protocol == "http/protobuf" {
        match SpanExporter::builder().with_http().build() {
            Ok(exp) => exp,
            Err(e) => {
                eprintln!("failed to create OTLP HTTP span exporter: {e}");
                return None;
            }
        }
    } else {
        match SpanExporter::builder().with_tonic().build() {
            Ok(exp) => exp,
            Err(e) => {
                eprintln!("failed to create OTLP gRPC span exporter: {e}");
                return None;
            }
        }
    };

    // Build resource with service name, namespace, and optional OTEL_RESOURCE_ATTRIBUTES.
    // service.name and service.namespace are authoritative — env vars cannot override them.
    let mut resource_attrs = vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.namespace", "attack-simulation"),
    ];

    // Parse OTEL_RESOURCE_ATTRIBUTES (comma-separated key=value pairs).
    // Skip service.name and service.namespace to prevent env-var clobbering.
    if let Ok(extra) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for pair in extra.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                let key = k.trim();
                if key == "service.name" || key == "service.namespace" {
                    continue;
                }
                resource_attrs.push(KeyValue::new(key.to_string(), v.trim().to_string()));
            }
        }
    }

    let resource = Resource::builder().with_attributes(resource_attrs).build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());

    Some(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the orchestrator double-init crash.
    ///
    /// Originally `init_telemetry` called `.init()` (which panics if a global
    /// dispatcher is already set). Running `ares --redis-url <url> orchestrator`
    /// would init once in `main` and again in `orchestrator::run`, panicking
    /// with `SetGlobalDefaultError`. After the fix, the second call must
    /// return a no-op `TelemetryGuard` instead of crashing the process.
    #[test]
    fn double_init_returns_noop_guard_instead_of_panicking() {
        // First call wins and installs the subscriber.
        let first = init_telemetry(TelemetryConfig::new("ares-test-first"));
        // Second call must not panic; it returns a guard flagged as noop.
        let second = init_telemetry(TelemetryConfig::new("ares-test-second"));

        assert!(
            !first.is_noop(),
            "first init_telemetry call should own the subscriber"
        );
        assert!(
            second.is_noop(),
            "second init_telemetry call must return a no-op guard, not panic"
        );

        // Dropping the noop guard must not panic / shutdown anything; dropping
        // the real guard runs the normal shutdown path.
        drop(second);
        drop(first);
    }
}
