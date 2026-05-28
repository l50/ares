//! Coercion task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::insert_state_context;
use super::templates::{render_template_with_context, TASK_COERCION};
use super::StateSnapshot;

pub(crate) fn generate_coercion_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    // For relay tasks (auto_ntlm_relay), the meaningful "target" is the
    // coercion source — the machine whose authentication we trigger to
    // bounce off the relay listener. Fall back to `target_ip` for legacy
    // unauth coercion tasks that don't carry a separate relay_target.
    let coercion_target = payload["coercion_source"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| payload["target_ip"].as_str())
        .unwrap_or("unknown");
    ctx.insert("target_ip", coercion_target);
    ctx.insert("listener_ip", payload["listener_ip"].as_str().unwrap_or(""));

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    // Relay-mode fields. Surfaced to the template so the LLM knows it must
    // start a relay listener BEFORE coercing — without these, the coercion
    // template only ran PetitPotam and ntlmrelayx was never spawned, making
    // every auto_ntlm_relay dispatch a no-op.
    if let Some(t) = payload["technique"].as_str().filter(|s| !s.is_empty()) {
        ctx.insert("technique", t);
    }
    if let Some(t) = payload["relay_target"].as_str().filter(|s| !s.is_empty()) {
        ctx.insert("relay_target", t);
    }
    if let Some(t) = payload["mssql_target"].as_str().filter(|s| !s.is_empty()) {
        ctx.insert("mssql_target", t);
    }
    if let Some(t) = payload["ca_name"].as_str().filter(|s| !s.is_empty()) {
        ctx.insert("ca_name", t);
    }
    if let Some(t) = payload["domain"].as_str().filter(|s| !s.is_empty()) {
        ctx.insert("relay_domain", t);
    }
    if let Some(cred) = payload.get("credential").and_then(|c| c.as_object()) {
        if let Some(u) = cred.get("username").and_then(|v| v.as_str()) {
            ctx.insert("coerce_user", u);
        }
        if let Some(d) = cred.get("domain").and_then(|v| v.as_str()) {
            ctx.insert("coerce_domain", d);
        }
        if cred.contains_key("password") {
            ctx.insert("has_coerce_credential", &true);
        }
    }

    insert_state_context(&mut ctx, state, "coercion", Some(coercion_target));

    render_template_with_context(TASK_COERCION, &ctx)
}
