//! LLM token usage tracking and cost estimation.
//!
//! Redis-backed atomic token counters.
//!
//! ## Redis key format
//!
//! All counters live in a single HASH at `ares:op:{op_id}:token_usage`:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `input_tokens` | Aggregate fresh (uncached) prompt tokens across all models |
//! | `output_tokens` | Aggregate completion tokens across all models |
//! | `cache_read_input_tokens` | Aggregate cached prompt tokens (discounted billing) |
//! | `model` | Last model name (last-writer-wins) |
//! | `model:{base64(name)}:input_tokens` | Per-model fresh input tokens |
//! | `model:{base64(name)}:output_tokens` | Per-model output tokens |
//! | `model:{base64(name)}:cache_read_input_tokens` | Per-model cached input tokens |
//!
//! Model names are URL-safe base64-encoded to avoid `:` / `/` collisions in
//! Redis HASH field names.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use redis::AsyncCommands;

/// Redis HASH field prefix for per-model counters.
const MODEL_PREFIX: &str = "model";

/// Token usage counters for a single LLM call.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Aggregated token usage for an operation, with per-model breakdown.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct OperationTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Last model that wrote to the HASH (informational).
    pub model: String,
    /// Per-model breakdown: `model_name -> {input_tokens, output_tokens}`.
    pub models: HashMap<String, ModelTokenUsage>,
}

/// Per-model token counters.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ModelTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Cached prefix tokens billed at the provider's discounted rate.
    /// OpenAI auto-caches identical ≥1024-token prefixes (50% off);
    /// Anthropic uses explicit cache_control breakpoints (90% off).
    #[serde(default)]
    pub cache_read_input_tokens: u64,
}

/// Per-model pricing: (input_per_million, output_per_million, cached_input_per_million) in USD.
///
/// The third entry is the per-million rate for cached prompt tokens. Provider
/// defaults today (Nov 2025):
///   * OpenAI: 50% of input rate (auto-cache for ≥1024-token prefixes)
///   * Anthropic: 10% of input rate (explicit cache_control)
///   * Gemini: 25% of input rate
///
/// Models not in the table are reported as "unpriced" in the breakdown.
const MODEL_COSTS: &[(&str, f64, f64, f64)] = &[
    // Anthropic Claude — cached read at 10% of input rate.
    ("claude-sonnet-4-20250514", 3.0, 15.0, 0.30),
    ("claude-opus-4-20250514", 15.0, 75.0, 1.50),
    ("claude-haiku-3-5-20241022", 0.80, 4.0, 0.08),
    ("claude-opus-4-8", 15.0, 75.0, 1.50),
    ("anthropic/claude-sonnet-4-20250514", 3.0, 15.0, 0.30),
    ("anthropic/claude-opus-4-20250514", 15.0, 75.0, 1.50),
    ("anthropic/claude-opus-4-8", 15.0, 75.0, 1.50),
    // OpenAI GPT-4.1 — cached read at 25% of input (50% off vs Chat Completions
    // post-2024-10 cache pricing).
    ("gpt-4.1", 2.0, 8.0, 0.50),
    ("gpt-4.1-mini", 0.40, 1.60, 0.10),
    ("gpt-4.1-nano", 0.10, 0.40, 0.025),
    ("openai/gpt-4.1", 2.0, 8.0, 0.50),
    ("openai/gpt-4.1-mini", 0.40, 1.60, 0.10),
    ("openai/gpt-4.1-nano", 0.10, 0.40, 0.025),
    // OpenAI GPT-4o/4-turbo
    ("gpt-4o", 2.50, 10.0, 1.25),
    ("gpt-4o-mini", 0.15, 0.60, 0.075),
    ("gpt-4-turbo", 10.0, 30.0, 5.0),
    ("openai/gpt-4o", 2.50, 10.0, 1.25),
    ("openai/gpt-4o-mini", 0.15, 0.60, 0.075),
    ("openai/gpt-4-turbo", 10.0, 30.0, 5.0),
    // OpenAI GPT-5 — cached input at ~10% of fresh input.
    ("gpt-5", 1.25, 10.0, 0.125),
    ("gpt-5.2", 1.75, 14.0, 0.175),
    ("gpt-5-mini", 0.25, 2.0, 0.025),
    ("openai/gpt-5", 1.25, 10.0, 0.125),
    ("openai/gpt-5.2", 1.75, 14.0, 0.175),
    ("openai/gpt-5-mini", 0.25, 2.0, 0.025),
    // Google Gemini — context caching at ~25% of input.
    ("gemini/gemini-2.5-pro", 1.25, 10.0, 0.3125),
    ("gemini/gemini-2.5-flash", 0.15, 0.60, 0.0375),
];

/// Cost breakdown for a single model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelCostBreakdown {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
}

/// Estimate the total cost for an operation's token usage.
///
/// Returns `(total_cost, priced_breakdown, unpriced_models)`.
/// If no models could be priced, `total_cost` is `None`.
pub fn estimate_usage_cost(
    usage: &OperationTokenUsage,
) -> (Option<f64>, Vec<ModelCostBreakdown>, Vec<String>) {
    if usage.models.is_empty() {
        return (None, vec![], vec![]);
    }

    let mut total_cost = 0.0f64;
    let mut breakdown = Vec::new();
    let mut unpriced = Vec::new();

    let mut models: Vec<_> = usage.models.iter().collect();
    models.sort_by_key(|(name, _)| name.to_lowercase());

    for (model_name, model_usage) in models {
        if let Some((input_rate, output_rate, cached_rate)) = lookup_model_cost(model_name) {
            // `input_tokens` is the fresh (uncached) portion;
            // `cache_read_input_tokens` is billed at the provider's discounted
            // rate. Without this split we over-bill cached prefixes by 5–10×.
            let cost = (model_usage.input_tokens as f64 * input_rate
                + model_usage.cache_read_input_tokens as f64 * cached_rate
                + model_usage.output_tokens as f64 * output_rate)
                / 1_000_000.0;
            total_cost += cost;
            breakdown.push(ModelCostBreakdown {
                model: model_name.clone(),
                input_tokens: model_usage.input_tokens,
                output_tokens: model_usage.output_tokens,
                total_tokens: model_usage.input_tokens
                    + model_usage.cache_read_input_tokens
                    + model_usage.output_tokens,
                cost,
            });
        } else {
            unpriced.push(model_name.clone());
        }
    }

    if breakdown.is_empty() {
        (None, breakdown, unpriced)
    } else {
        (Some(total_cost), breakdown, unpriced)
    }
}

/// Look up per-token pricing for a model: (input, output, cached_input) per million.
fn lookup_model_cost(model: &str) -> Option<(f64, f64, f64)> {
    let model_lower = model.to_lowercase();
    for &(name, input, output, cached) in MODEL_COSTS {
        if name == model_lower {
            return Some((input, output, cached));
        }
    }
    // Fuzzy fallback: check if model contains a known name as substring
    for &(name, input, output, cached) in MODEL_COSTS {
        if model_lower.contains(name) || name.contains(&model_lower) {
            return Some((input, output, cached));
        }
    }
    None
}

/// Build the Redis key for an operation's token usage HASH.
pub fn token_usage_key(operation_id: &str) -> String {
    format!("ares:op:{operation_id}:token_usage")
}

/// Build the Redis key for a blue team investigation's token usage HASH.
pub fn blue_token_usage_key(investigation_id: &str) -> String {
    format!("ares:blue:inv:{investigation_id}:token_usage")
}

/// Atomically increment token usage counters for a blue team investigation.
pub async fn increment_blue_token_usage(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
    model: &str,
) -> Result<(), redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);

    let input_i64 = i64::try_from(input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "input_tokens overflows i64",
        ))
    })?;
    let output_i64 = i64::try_from(output_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "output_tokens overflows i64",
        ))
    })?;
    let cache_read_i64 = i64::try_from(cache_read_input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "cache_read_input_tokens overflows i64",
        ))
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("input_tokens")
        .arg(input_i64);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("output_tokens")
        .arg(output_i64);
    if cache_read_i64 > 0 {
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg("cache_read_input_tokens")
            .arg(cache_read_i64);
    }

    if !model.is_empty() {
        pipe.cmd("HSET").arg(&key).arg("model").arg(model);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "output_tokens"))
            .arg(output_i64);
        if cache_read_i64 > 0 {
            pipe.cmd("HINCRBY")
                .arg(&key)
                .arg(model_field(model, "cache_read_input_tokens"))
                .arg(cache_read_i64);
        }
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read aggregated token usage for a blue team investigation.
///
/// Returns `None` if the key does not exist.
pub async fn get_blue_token_usage(
    conn: &mut impl AsyncCommands,
    investigation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = blue_token_usage_key(investigation_id);
    let data: HashMap<String, String> = conn.hgetall(&key).await?;
    if data.is_empty() {
        return Ok(None);
    }

    let input_tokens = data
        .get("input_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let output_tokens = data
        .get("output_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let model = data.get("model").cloned().unwrap_or_default();

    let mut models: HashMap<String, ModelTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((model_name, token_type)) = parse_model_field(field) {
            let entry = models.entry(model_name).or_default();
            let count = value.parse::<u64>().unwrap_or(0);
            match token_type.as_str() {
                "input_tokens" => entry.input_tokens = count,
                "output_tokens" => entry.output_tokens = count,
                "cache_read_input_tokens" => entry.cache_read_input_tokens = count,
                _ => {}
            }
        }
    }

    Ok(Some(OperationTokenUsage {
        input_tokens,
        output_tokens,
        model,
        models,
    }))
}

/// Encode a per-model HASH field name.
///
/// Format: `model:{url_safe_base64(model_name)}:{token_type}`
fn model_field(model: &str, token_type: &str) -> String {
    let encoded = URL_SAFE.encode(model.as_bytes());
    format!("{MODEL_PREFIX}:{encoded}:{token_type}")
}

/// Decode a per-model HASH field back to `(model_name, token_type)`.
///
/// Returns `None` for non-model fields (e.g. `input_tokens`, `model`).
fn parse_model_field(field: &str) -> Option<(String, String)> {
    let rest = field
        .strip_prefix(MODEL_PREFIX)
        .and_then(|s| s.strip_prefix(':'))?;
    let colon_pos = rest.rfind(':')?;
    let encoded = &rest[..colon_pos];
    let token_type = &rest[colon_pos + 1..];
    let decoded = URL_SAFE.decode(encoded).ok()?;
    let model_name = String::from_utf8(decoded).ok()?;
    Some((model_name, token_type.to_string()))
}

/// Atomically increment token usage counters for an operation.
///
/// Uses Redis HINCRBY for lock-free, crash-safe accumulation across workers.
///
/// `cache_read_input_tokens` is the count of prompt tokens served from the
/// provider's prompt cache (OpenAI auto-cache or Anthropic explicit cache).
/// These bill at a heavily discounted rate, so the estimator tracks them
/// separately rather than rolling them into `input_tokens` and over-billing.
pub async fn increment_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_input_tokens: u64,
    model: &str,
) -> Result<(), redis::RedisError> {
    let key = token_usage_key(operation_id);

    let input_i64 = i64::try_from(input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "input_tokens overflows i64",
        ))
    })?;
    let output_i64 = i64::try_from(output_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "output_tokens overflows i64",
        ))
    })?;
    let cache_read_i64 = i64::try_from(cache_read_input_tokens).map_err(|_| {
        redis::RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "cache_read_input_tokens overflows i64",
        ))
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("input_tokens")
        .arg(input_i64);
    pipe.cmd("HINCRBY")
        .arg(&key)
        .arg("output_tokens")
        .arg(output_i64);
    if cache_read_i64 > 0 {
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg("cache_read_input_tokens")
            .arg(cache_read_i64);
    }

    if !model.is_empty() {
        pipe.cmd("HSET").arg(&key).arg("model").arg(model);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "input_tokens"))
            .arg(input_i64);
        pipe.cmd("HINCRBY")
            .arg(&key)
            .arg(model_field(model, "output_tokens"))
            .arg(output_i64);
        if cache_read_i64 > 0 {
            pipe.cmd("HINCRBY")
                .arg(&key)
                .arg(model_field(model, "cache_read_input_tokens"))
                .arg(cache_read_i64);
        }
    }

    pipe.query_async::<()>(conn).await?;
    Ok(())
}

/// Read aggregated token usage for an operation. Returns `None` if absent.
pub async fn get_token_usage(
    conn: &mut impl AsyncCommands,
    operation_id: &str,
) -> Result<Option<OperationTokenUsage>, redis::RedisError> {
    let key = token_usage_key(operation_id);
    let data: HashMap<String, String> = conn.hgetall(&key).await?;
    if data.is_empty() {
        return Ok(None);
    }

    let input_tokens = data
        .get("input_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let output_tokens = data
        .get("output_tokens")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let model = data.get("model").cloned().unwrap_or_default();

    let mut models: HashMap<String, ModelTokenUsage> = HashMap::new();
    for (field, value) in &data {
        if let Some((model_name, token_type)) = parse_model_field(field) {
            let entry = models.entry(model_name).or_default();
            let count = value.parse::<u64>().unwrap_or(0);
            match token_type.as_str() {
                "input_tokens" => entry.input_tokens = count,
                "output_tokens" => entry.output_tokens = count,
                "cache_read_input_tokens" => entry.cache_read_input_tokens = count,
                _ => {}
            }
        }
    }

    Ok(Some(OperationTokenUsage {
        input_tokens,
        output_tokens,
        model,
        models,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_field_roundtrip() {
        let field = model_field("openai/gpt-4.1-mini", "input_tokens");
        assert!(field.starts_with("model:"));
        assert!(field.ends_with(":input_tokens"));

        let (model, token_type) = parse_model_field(&field).unwrap();
        assert_eq!(model, "openai/gpt-4.1-mini");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn model_field_with_slashes_and_dots() {
        // Ensure models with special chars survive encoding
        let names = [
            "anthropic/claude-sonnet-4-20250514",
            "openai/gpt-4.1",
            "gemini/gemini-2.5-pro",
        ];
        for name in names {
            let field = model_field(name, "output_tokens");
            let (decoded, tt) = parse_model_field(&field).unwrap();
            assert_eq!(decoded, name);
            assert_eq!(tt, "output_tokens");
        }
    }

    #[test]
    fn parse_non_model_fields() {
        assert!(parse_model_field("input_tokens").is_none());
        assert!(parse_model_field("output_tokens").is_none());
        assert!(parse_model_field("model").is_none());
    }

    #[test]
    fn estimate_usage_cost_bills_cache_reads_at_discounted_rate() {
        // gpt-5.2: $1.75/M input, $14/M output, $0.175/M cached input.
        // 1M fresh input × $1.75 + 1M cached input × $0.175 + 0.1M out × $14
        // = $1.75 + $0.175 + $1.40 = $3.325. Without the cache split this
        // would over-bill by $1.575 (1M × ($1.75 − $0.175)).
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            model: "openai/gpt-5.2".to_string(),
            models: HashMap::from([(
                "openai/gpt-5.2".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 100_000,
                    cache_read_input_tokens: 1_000_000,
                },
            )]),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(unpriced.is_empty());
        let cost = total.unwrap();
        assert!(
            (cost - 3.325).abs() < 0.001,
            "expected ~$3.325, got ${cost}"
        );
        assert_eq!(breakdown[0].total_tokens, 2_100_000);
    }

    #[test]
    fn estimate_usage_cost_zero_cache_matches_pre_cache_billing() {
        // When cache_read is 0, totals match the pre-cache calculation.
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            model: "openai/gpt-5.2".to_string(),
            models: HashMap::from([(
                "openai/gpt-5.2".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 100_000,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let (total, _, _) = estimate_usage_cost(&usage);
        let cost = total.unwrap();
        // 1M × $1.75 + 0.1M × $14 = $3.15
        assert!((cost - 3.15).abs() < 0.001);
    }

    #[test]
    fn estimate_usage_cost_single_model() {
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 500_000,
            model: "openai/gpt-4.1-mini".to_string(),
            models: HashMap::from([(
                "openai/gpt-4.1-mini".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 500_000,
                    cache_read_input_tokens: 0,
                },
            )]),
        };

        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
        // gpt-4.1-mini: $0.40/M input + $1.60/M output
        // cost = 1M * 0.40/1M + 0.5M * 1.60/1M = 0.40 + 0.80 = 1.20
        let cost = total.unwrap();
        assert!((cost - 1.20).abs() < 0.001, "expected ~1.20, got {cost}");
    }

    #[test]
    fn estimate_usage_cost_multi_model() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            output_tokens: 1_000_000,
            model: "openai/gpt-4.1".to_string(),
            models: HashMap::from([
                (
                    "openai/gpt-4.1-mini".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                        cache_read_input_tokens: 0,
                    },
                ),
                (
                    "openai/gpt-4.1".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                        cache_read_input_tokens: 0,
                    },
                ),
            ]),
        };

        let (total, breakdown, _) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 2);
        // gpt-4.1-mini: 1M * 0.40 + 0.5M * 1.60 = 0.40 + 0.80 = 1.20
        // gpt-4.1:      1M * 2.00 + 0.5M * 8.00 = 2.00 + 4.00 = 6.00
        // total = 7.20
        let cost = total.unwrap();
        assert!((cost - 7.20).abs() < 0.001, "expected ~7.20, got {cost}");
    }

    #[test]
    fn estimate_usage_cost_unknown_model() {
        let usage = OperationTokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            model: "unknown-model-v99".to_string(),
            models: HashMap::from([(
                "unknown-model-v99".to_string(),
                ModelTokenUsage {
                    input_tokens: 100,
                    output_tokens: 50,
                    cache_read_input_tokens: 0,
                },
            )]),
        };

        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert_eq!(unpriced, vec!["unknown-model-v99"]);
    }

    #[test]
    fn estimate_usage_cost_empty() {
        let usage = OperationTokenUsage::default();
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert!(unpriced.is_empty());
    }

    #[test]
    fn token_usage_key_basic() {
        assert_eq!(
            super::token_usage_key("op-abc-123"),
            "ares:op:op-abc-123:token_usage"
        );
    }

    #[test]
    fn blue_token_usage_key_format() {
        assert_eq!(
            blue_token_usage_key("inv-xyz-456"),
            "ares:blue:inv:inv-xyz-456:token_usage"
        );
    }

    #[test]
    fn lookup_model_cost_exact_match() {
        let result = lookup_model_cost("gpt-4o");
        let (input, output, _cached) = result.expect("gpt-4o should have known cost");
        assert!((input - 2.50).abs() < 0.001);
        assert!((output - 10.0).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_case_insensitive() {
        // Model names are lowercased before lookup
        let result = lookup_model_cost("GPT-4O");
        assert!(result.is_some());
    }

    #[test]
    fn lookup_model_cost_unknown_returns_none() {
        let result = lookup_model_cost("totally-unknown-model-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn model_field_roundtrip_simple() {
        let field = model_field("gpt-4o", "input_tokens");
        let (model, token_type) = parse_model_field(&field).unwrap();
        assert_eq!(model, "gpt-4o");
        assert_eq!(token_type, "input_tokens");
    }

    #[test]
    fn parse_model_field_invalid_prefix() {
        assert!(parse_model_field("something_else").is_none());
        assert!(parse_model_field("").is_none());
    }

    #[test]
    fn estimate_usage_cost_breakdown_total_tokens() {
        let usage = OperationTokenUsage {
            input_tokens: 500_000,
            output_tokens: 500_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 500_000,
                    output_tokens: 500_000,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let (_, breakdown, _) = estimate_usage_cost(&usage);
        assert_eq!(breakdown[0].total_tokens, 1_000_000);
        assert_eq!(breakdown[0].input_tokens, 500_000);
        assert_eq!(breakdown[0].output_tokens, 500_000);
    }

    #[test]
    fn token_usage_default() {
        let t = TokenUsage::default();
        assert_eq!(t.input_tokens, 0);
        assert_eq!(t.output_tokens, 0);
        assert_eq!(t.total_tokens, 0);
        assert!(t.model.is_none());
    }

    #[test]
    fn token_usage_serde_roundtrip() {
        let t = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            model: Some("gpt-4.1".to_string()),
        };
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: TokenUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.input_tokens, 100);
        assert_eq!(deserialized.output_tokens, 50);
        assert_eq!(deserialized.total_tokens, 150);
        assert_eq!(deserialized.model, Some("gpt-4.1".to_string()));
    }

    #[test]
    fn token_usage_serde_skips_none_model() {
        let t = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            total_tokens: 15,
            model: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("model"));
    }

    #[test]
    fn token_usage_deserialize_missing_model() {
        let json = r#"{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}"#;
        let t: TokenUsage = serde_json::from_str(json).unwrap();
        assert!(t.model.is_none());
    }

    #[test]
    fn operation_token_usage_default() {
        let o = OperationTokenUsage::default();
        assert_eq!(o.input_tokens, 0);
        assert_eq!(o.output_tokens, 0);
        assert!(o.model.is_empty());
        assert!(o.models.is_empty());
    }

    #[test]
    fn model_token_usage_default() {
        let m = ModelTokenUsage::default();
        assert_eq!(m.input_tokens, 0);
        assert_eq!(m.output_tokens, 0);
    }

    #[test]
    fn lookup_model_cost_all_known_models() {
        // Verify every model in the pricing table can be looked up
        let known_models = [
            "gpt-4.1",
            "gpt-4.1-mini",
            "gpt-4.1-nano",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-5",
            "gpt-5.2",
            "gpt-5-mini",
            "openai/gpt-4.1",
            "openai/gpt-4.1-mini",
            "openai/gpt-4o",
            "gemini/gemini-2.5-pro",
            "gemini/gemini-2.5-flash",
        ];
        for model in known_models {
            assert!(
                lookup_model_cost(model).is_some(),
                "Expected pricing for {model}"
            );
        }
    }

    #[test]
    fn lookup_model_cost_fuzzy_substring_match() {
        // A model name that contains a known name as substring
        let result = lookup_model_cost("azure/gpt-4o-2024-deployment");
        assert!(
            result.is_some(),
            "Expected fuzzy match for gpt-4o substring"
        );
    }

    #[test]
    fn lookup_model_cost_returns_correct_rates() {
        // gpt-4.1: $2.00/M input, $8.00/M output
        let (input, output, _cached) = lookup_model_cost("gpt-4.1").unwrap();
        assert!((input - 2.0).abs() < 0.001);
        assert!((output - 8.0).abs() < 0.001);

        // gpt-4.1-nano: $0.10/M input, $0.40/M output
        let (input, output, _cached) = lookup_model_cost("gpt-4.1-nano").unwrap();
        assert!((input - 0.10).abs() < 0.001);
        assert!((output - 0.40).abs() < 0.001);
    }

    #[test]
    fn model_field_empty_model_name() {
        let field = model_field("", "input_tokens");
        let (model, tt) = parse_model_field(&field).unwrap();
        assert!(model.is_empty());
        assert_eq!(tt, "input_tokens");
    }

    #[test]
    fn model_field_with_colons_in_name() {
        // Model names with colons should survive base64 encoding
        let name = "provider:model:variant";
        let field = model_field(name, "output_tokens");
        let (decoded, tt) = parse_model_field(&field).unwrap();
        assert_eq!(decoded, name);
        assert_eq!(tt, "output_tokens");
    }

    #[test]
    fn parse_model_field_malformed_base64() {
        // Valid prefix but invalid base64 content
        let result = parse_model_field("model:!!!invalid!!!:input_tokens");
        assert!(result.is_none());
    }

    #[test]
    fn estimate_usage_cost_mixed_models() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            output_tokens: 1_000_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([
                (
                    "gpt-4o".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                        cache_read_input_tokens: 0,
                    },
                ),
                (
                    "my-custom-model-v1".to_string(),
                    ModelTokenUsage {
                        input_tokens: 1_000_000,
                        output_tokens: 500_000,
                        cache_read_input_tokens: 0,
                    },
                ),
            ]),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_some());
        assert_eq!(breakdown.len(), 1); // Only gpt-4o is priced
        assert_eq!(unpriced.len(), 1);
        assert_eq!(unpriced[0], "my-custom-model-v1");
    }

    #[test]
    fn estimate_usage_cost_breakdown_sorted_by_name() {
        let usage = OperationTokenUsage {
            input_tokens: 2_000_000,
            output_tokens: 1_000_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([
                (
                    "gpt-4o".to_string(),
                    ModelTokenUsage {
                        input_tokens: 500_000,
                        output_tokens: 250_000,
                        cache_read_input_tokens: 0,
                    },
                ),
                (
                    "gpt-4.1-mini".to_string(),
                    ModelTokenUsage {
                        input_tokens: 500_000,
                        output_tokens: 250_000,
                        cache_read_input_tokens: 0,
                    },
                ),
            ]),
        };
        let (_, breakdown, _) = estimate_usage_cost(&usage);
        assert_eq!(breakdown.len(), 2);
        // Sorted alphabetically: gpt-4.1-mini before gpt-4o
        assert_eq!(breakdown[0].model, "gpt-4.1-mini");
        assert_eq!(breakdown[1].model, "gpt-4o");
    }

    #[test]
    fn token_usage_key_format_various() {
        assert_eq!(token_usage_key("op-123"), "ares:op:op-123:token_usage");
        assert_eq!(token_usage_key(""), "ares:op::token_usage");
    }

    #[test]
    fn blue_token_usage_key_format_various() {
        assert_eq!(
            blue_token_usage_key("inv-abc"),
            "ares:blue:inv:inv-abc:token_usage"
        );
        assert_eq!(blue_token_usage_key(""), "ares:blue:inv::token_usage");
    }

    #[test]
    fn model_cost_breakdown_serialize() {
        let b = ModelCostBreakdown {
            model: "gpt-4.1".to_string(),
            input_tokens: 1000,
            output_tokens: 500,
            total_tokens: 1500,
            cost: 0.006,
        };
        let json = serde_json::to_value(&b).unwrap();
        assert_eq!(json["model"], "gpt-4.1");
        assert_eq!(json["total_tokens"], 1500);
        assert!((json["cost"].as_f64().unwrap() - 0.006).abs() < 0.0001);
    }

    #[test]
    fn operation_token_usage_serialize() {
        let usage = OperationTokenUsage {
            input_tokens: 10000,
            output_tokens: 5000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 10000,
                    output_tokens: 5000,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let json = serde_json::to_value(&usage).unwrap();
        assert_eq!(json["input_tokens"], 10000);
        assert_eq!(json["output_tokens"], 5000);
        assert_eq!(json["model"], "gpt-4o");
        assert!(json["models"]["gpt-4o"].is_object());
    }

    #[test]
    fn estimate_usage_cost_zero_tokens_known_model() {
        let usage = OperationTokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert_eq!(total.expect("total should be set"), 0.0);
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
    }

    #[test]
    fn blue_token_usage_key_with_dashes() {
        assert_eq!(
            blue_token_usage_key("inv-123"),
            "ares:blue:inv:inv-123:token_usage"
        );
    }

    #[test]
    fn estimate_usage_cost_empty_models() {
        let usage = OperationTokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            model: "gpt-4o".to_string(),
            models: HashMap::new(),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert!(unpriced.is_empty());
    }

    #[test]
    fn estimate_usage_cost_all_unpriced() {
        let usage = OperationTokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            model: "unknown".to_string(),
            models: HashMap::from([(
                "unknown-model".to_string(),
                ModelTokenUsage {
                    input_tokens: 1000,
                    output_tokens: 500,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        assert!(total.is_none());
        assert!(breakdown.is_empty());
        assert_eq!(unpriced.len(), 1);
    }

    #[test]
    fn estimate_usage_cost_single_priced_model() {
        let usage = OperationTokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 500_000,
            model: "gpt-4o".to_string(),
            models: HashMap::from([(
                "gpt-4o".to_string(),
                ModelTokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 500_000,
                    cache_read_input_tokens: 0,
                },
            )]),
        };
        let (total, breakdown, unpriced) = estimate_usage_cost(&usage);
        let cost = total.expect("total should be set");
        // gpt-4o: 2.50/M input + 10.0/M output
        // 1M * 2.50/1M + 0.5M * 10.0/1M = 2.50 + 5.0 = 7.50
        assert!((cost - 7.50).abs() < 0.01);
        assert_eq!(breakdown.len(), 1);
        assert!(unpriced.is_empty());
    }

    #[test]
    fn lookup_model_cost_prefixed_openai() {
        let result = lookup_model_cost("openai/gpt-4o-mini");
        let (input, output, _cached) = result.expect("gpt-4o-mini should have known cost");
        assert!((input - 0.15).abs() < 0.001);
        assert!((output - 0.60).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_claude_opus() {
        let result = lookup_model_cost("claude-opus-4-20250514");
        let (input, output, _cached) = result.expect("claude-opus should have known cost");
        assert!((input - 15.0).abs() < 0.001);
        assert!((output - 75.0).abs() < 0.001);
    }

    #[test]
    fn lookup_model_cost_haiku() {
        let result = lookup_model_cost("claude-haiku-3-5-20241022");
        let (input, output, _cached) = result.expect("claude-haiku should have known cost");
        assert!((input - 0.80).abs() < 0.001);
        assert!((output - 4.0).abs() < 0.001);
    }
}
