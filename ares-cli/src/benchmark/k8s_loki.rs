//! Ephemeral Loki pod lifecycle management via kubectl.
//!
//! Creates a single-replica Loki pod in a K8s namespace for benchmark replay.
//! The pod uses `emptyDir` storage and `restartPolicy: Never` — data is
//! discarded when the pod is deleted. This guarantees each replay gets a
//! clean, isolated Loki instance.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

/// An ephemeral Loki instance running as a K8s pod.
///
/// Manages the full lifecycle: create → port-forward → destroy.
/// Implements `Drop` for best-effort cleanup on panic/early return.
pub struct EphemeralLoki {
    pub namespace: String,
    pub name: String,
    pub local_port: u16,
    port_forward_child: Option<Child>,
}

impl EphemeralLoki {
    /// Create and start an ephemeral Loki pod.
    ///
    /// Blocks until the pod is ready (up to 120 seconds).
    pub fn create(namespace: &str, snapshot_id: &str) -> Result<Self> {
        // Generate a unique-ish pod name from the snapshot ID
        let short_id = snapshot_id
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(8)
            .collect::<String>()
            .to_lowercase();
        let name = format!("loki-bench-{short_id}");

        let local_port = find_available_port()?;

        info!("creating ephemeral Loki pod {name} in namespace {namespace}");

        // Write combined YAML (ConfigMap + Pod) and apply via kubectl
        let spec = pod_spec(&name, namespace);
        let mut child = Command::new("kubectl")
            .args(["apply", "-f", "-", "-n", namespace])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn kubectl apply")?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(spec.as_bytes())
                .context("write pod spec to kubectl stdin")?;
        }

        let output = child.wait_with_output().context("kubectl apply")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("kubectl apply failed: {stderr}");
        }

        info!("waiting for pod {name} to be ready");

        let wait_output = Command::new("kubectl")
            .args([
                "wait",
                "--for=condition=Ready",
                &format!("pod/{name}"),
                "-n",
                namespace,
                "--timeout=120s",
            ])
            .output()
            .context("kubectl wait")?;

        if !wait_output.status.success() {
            let stderr = String::from_utf8_lossy(&wait_output.stderr);
            // Try to clean up on failure
            let _ = Command::new("kubectl")
                .args([
                    "delete",
                    "pod",
                    &name,
                    "-n",
                    namespace,
                    "--ignore-not-found",
                ])
                .output();
            let _ = Command::new("kubectl")
                .args([
                    "delete",
                    "configmap",
                    &format!("{name}-config"),
                    "-n",
                    namespace,
                    "--ignore-not-found",
                ])
                .output();
            bail!("pod failed to become ready within 120s: {stderr}");
        }

        info!("ephemeral Loki pod {name} is ready");

        Ok(Self {
            namespace: namespace.to_string(),
            name,
            local_port,
            port_forward_child: None,
        })
    }

    /// Start kubectl port-forward and return the local Loki URL.
    ///
    /// The port-forward process runs in the background until [`destroy`] is
    /// called or this struct is dropped.
    pub fn start_port_forward(&mut self) -> Result<String> {
        info!(
            "starting port-forward to {}/{} on local port {}",
            self.namespace, self.name, self.local_port
        );

        let child = Command::new("kubectl")
            .args([
                "port-forward",
                &format!("pod/{}", self.name),
                &format!("{}:3100", self.local_port),
                "-n",
                &self.namespace,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn kubectl port-forward")?;

        self.port_forward_child = Some(child);

        // Wait a moment for the port-forward to establish
        std::thread::sleep(std::time::Duration::from_secs(3));

        let url = format!("http://127.0.0.1:{}", self.local_port);
        info!("ephemeral Loki available at {url}");
        Ok(url)
    }

    /// Tear down the ephemeral Loki pod and configmap.
    pub fn destroy(&mut self) -> Result<()> {
        // Kill port-forward
        if let Some(ref mut child) = self.port_forward_child.take() {
            debug!("killing port-forward process");
            let _ = child.kill();
            let _ = child.wait();
        }

        info!("deleting ephemeral Loki pod {}", self.name);

        let _ = Command::new("kubectl")
            .args([
                "delete",
                "pod",
                &self.name,
                "-n",
                &self.namespace,
                "--ignore-not-found",
                "--wait=false",
            ])
            .output();

        let _ = Command::new("kubectl")
            .args([
                "delete",
                "configmap",
                &format!("{}-config", self.name),
                "-n",
                &self.namespace,
                "--ignore-not-found",
                "--wait=false",
            ])
            .output();

        Ok(())
    }
}

impl Drop for EphemeralLoki {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            warn!("ephemeral Loki cleanup failed: {e}");
        }
    }
}

/// Find an available local TCP port by binding to port 0.
fn find_available_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind to find available port")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

/// Generate the combined YAML spec (ConfigMap + Pod) for the ephemeral Loki.
fn pod_spec(name: &str, namespace: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: {name}-config
  namespace: {namespace}
  labels:
    ares.dreadnode.io/component: benchmark-loki
data:
  config.yaml: |
    auth_enabled: false
    server:
      http_listen_port: 3100
      log_level: warn
    common:
      path_prefix: /tmp/loki
      storage:
        filesystem:
          chunks_directory: /tmp/loki/chunks
          rules_directory: /tmp/loki/rules
      replication_factor: 1
      ring:
        kvstore:
          store: inmemory
    limits_config:
      reject_old_samples: false
      reject_old_samples_max_age: "8760h"
      ingestion_rate_mb: 100
      ingestion_burst_size_mb: 200
      per_stream_rate_limit: "50MB"
      max_entries_limit_per_query: 50000
    schema_config:
      configs:
      - from: "2020-01-01"
        store: tsdb
        object_store: filesystem
        schema: v13
        index:
          prefix: index_
          period: 24h
    query_range:
      results_cache:
        cache:
          embedded_cache:
            enabled: true
            max_size_mb: 100
    analytics:
      reporting_enabled: false
---
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    ares.dreadnode.io/component: benchmark-loki
spec:
  containers:
  - name: loki
    image: grafana/loki:3.4.2
    ports:
    - containerPort: 3100
      name: http
    args:
    - "-config.file=/etc/loki/config.yaml"
    volumeMounts:
    - name: config
      mountPath: /etc/loki
    - name: data
      mountPath: /tmp/loki
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "2Gi"
        cpu: "2000m"
    readinessProbe:
      httpGet:
        path: /ready
        port: 3100
      initialDelaySeconds: 3
      periodSeconds: 5
  volumes:
  - name: config
    configMap:
      name: {name}-config
  - name: data
    emptyDir:
      sizeLimit: 10Gi
  restartPolicy: Never
"#
    )
}
