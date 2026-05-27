//! OpenAI Chat Completions API provider.
//!
//! Implements the `LlmProvider` trait for the OpenAI Chat Completions API.
//! See: <https://platform.openai.com/docs/api-reference/chat>

use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    ChatMessage, ContentPart, LlmError, LlmProvider, LlmRequest, LlmResponse, Role, StopReason,
    TokenUsage, ToolCall,
};

const DEFAULT_API_URL: &str = "https://api.openai.com/v1/chat/completions";

pub struct OpenAiProvider {
    api_key: String,
    base_url: String,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(api_key: String, base_url: Option<String>) -> Self {
        Self {
            api_key,
            base_url: base_url.unwrap_or_else(|| DEFAULT_API_URL.to_string()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("failed to build reqwest client"),
        }
    }
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    messages: Vec<ApiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ApiTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<ApiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ApiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ApiContent {
    Text(String),
}

#[derive(Serialize)]
struct ApiToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: ApiFunction,
}

#[derive(Serialize)]
struct ApiFunction {
    name: String,
    arguments: String,
}

#[derive(Serialize)]
struct ApiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: ApiToolFunction,
}

#[derive(Serialize)]
struct ApiToolFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
struct ApiResponse {
    choices: Vec<ApiChoice>,
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct ApiChoice {
    message: ApiResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ApiResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ApiResponseToolCall>>,
}

#[derive(Deserialize)]
struct ApiResponseToolCall {
    id: String,
    function: ApiResponseFunction,
}

#[derive(Deserialize)]
struct ApiResponseFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ApiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: Option<String>,
}

fn convert_message(msg: &ChatMessage) -> ApiMessage {
    let role = match msg.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };

    // Handle tool result messages
    if msg.role == Role::Tool || msg.role == Role::User {
        if let Some(ref parts) = msg.parts {
            for part in parts {
                if let ContentPart::ToolResult {
                    tool_use_id,
                    content,
                } = part
                {
                    return ApiMessage {
                        role: "tool".to_string(),
                        content: Some(ApiContent::Text(content.clone())),
                        tool_calls: None,
                        tool_call_id: Some(tool_use_id.clone()),
                    };
                }
            }
        }
    }

    if msg.role == Role::Assistant {
        if let Some(ref parts) = msg.parts {
            let mut text_parts = Vec::new();
            let mut tool_calls = Vec::new();

            for part in parts {
                match part {
                    ContentPart::Text { text } => text_parts.push(text.clone()),
                    ContentPart::ToolUse { id, name, input } => {
                        tool_calls.push(ApiToolCall {
                            id: id.clone(),
                            call_type: "function".to_string(),
                            function: ApiFunction {
                                name: name.clone(),
                                arguments: serde_json::to_string(input).unwrap_or_default(),
                            },
                        });
                    }
                    _ => {}
                }
            }

            let content = if text_parts.is_empty() {
                None
            } else {
                Some(ApiContent::Text(text_parts.join("")))
            };

            let tool_calls = if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            };

            return ApiMessage {
                role: role.to_string(),
                content,
                tool_calls,
                tool_call_id: None,
            };
        }
    }

    ApiMessage {
        role: role.to_string(),
        content: Some(ApiContent::Text(msg.content.clone().unwrap_or_default())),
        tool_calls: None,
        tool_call_id: None,
    }
}

fn convert_tools(tools: &[super::ToolDefinition]) -> Vec<ApiTool> {
    tools
        .iter()
        .map(|t| ApiTool {
            tool_type: "function".to_string(),
            function: ApiToolFunction {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters: t.input_schema.clone(),
            },
        })
        .collect()
}

fn parse_stop_reason(reason: Option<&str>) -> StopReason {
    match reason {
        Some("stop") => StopReason::EndTurn,
        Some("tool_calls") => StopReason::ToolUse,
        Some("length") => StopReason::MaxTokens,
        Some(other) => StopReason::Other(other.to_string()),
        None => StopReason::EndTurn,
    }
}

fn uses_max_completion_tokens(model: &str) -> bool {
    let model = model.strip_prefix("openai/").unwrap_or(model);
    model.starts_with("gpt-5")
}

/// Heuristically detect OpenAI 403 messages that are caused by the API key's
/// organization not being allowlisted for the requested model. Restricted
/// models like `gpt-5.2` raise this on the *first* call, so catching it
/// cheaply lets the orchestrator fail fast with a useful hint instead of
/// letting every queued task tip over with the same opaque error.
pub(crate) fn is_org_restricted_message(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("do not have access to the organization")
        || lower.contains("must be verified to use the model")
        || lower.contains("not have access to model")
        || lower.contains("project does not have access")
}

/// Append a one-line operator hint to org-restricted / auth errors so the
/// failure log immediately points at the likely cause (wrong model default or
/// missing `OPENAI_ORG_ID`). Kept best-effort: if the upstream message
/// already contains a usable pointer, we don't duplicate it.
pub(crate) fn augment_org_hint(message: &str, model: &str) -> String {
    let already_hinted = message.contains("OPENAI_ORG_ID") || message.contains("ARES_LLM_MODEL");
    if already_hinted {
        return message.to_string();
    }
    format!(
        "{message} [model={model} — check OPENAI_ORG_ID and that your org is allowlisted for this model, or set ARES_LLM_MODEL to a widely-available alternative such as openai/gpt-4o-mini]"
    )
}

#[async_trait::async_trait]
impl LlmProvider for OpenAiProvider {
    async fn chat(&self, request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let mut messages: Vec<ApiMessage> = Vec::new();

        // System message goes as first message for OpenAI
        if let Some(ref system) = request.system {
            messages.push(ApiMessage {
                role: "system".to_string(),
                content: Some(ApiContent::Text(system.clone())),
                tool_calls: None,
                tool_call_id: None,
            });
        }

        for msg in &request.messages {
            if msg.role == Role::System {
                continue; // Already handled above
            }
            messages.push(convert_message(msg));
        }

        let use_max_completion_tokens = uses_max_completion_tokens(&request.model);
        let api_request = ApiRequest {
            model: request.model.clone(),
            messages,
            max_tokens: (!use_max_completion_tokens).then_some(request.max_tokens),
            max_completion_tokens: use_max_completion_tokens.then_some(request.max_tokens),
            tools: convert_tools(&request.tools),
            temperature: request.temperature,
        };

        info!(
            model = %request.model,
            msg_count = request.messages.len(),
            tool_count = request.tools.len(),
            "OpenAI API request"
        );

        let response = self
            .client
            .post(&self.base_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&api_request)
            .send()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|secs| (secs * 1000.0) as u64);
        let body = response
            .text()
            .await
            .map_err(|e| LlmError::Network(e.to_string()))?;

        if !status.is_success() {
            let message = if let Ok(err) = serde_json::from_str::<ApiErrorResponse>(&body) {
                // Check for context length exceeded
                if let Some(ref code) = err.error.error_type {
                    if (code == "context_length_exceeded" || code == "invalid_request_error")
                        && (err.error.message.contains("context length")
                            || err.error.message.contains("maximum context"))
                    {
                        return Err(LlmError::ContextTooLong(err.error.message));
                    }
                }
                err.error.message
            } else {
                body
            };

            return Err(match status.as_u16() {
                429 => LlmError::RateLimited { retry_after_ms },
                // 401 = bad/missing API key. 403 with org-restriction phrasing
                // means the key is valid but the org isn't allowlisted for the
                // requested model (typical for `gpt-5.2` and other restricted
                // models). Surface both as AuthError so callers fail fast with
                // a clearer message instead of treating it as a generic 4xx.
                401 => LlmError::AuthError(augment_org_hint(&message, &request.model)),
                403 if is_org_restricted_message(&message) => {
                    LlmError::AuthError(augment_org_hint(&message, &request.model))
                }
                _ => LlmError::ApiError {
                    status: status.as_u16(),
                    message,
                },
            });
        }

        let api_response: ApiResponse = serde_json::from_str(&body).map_err(|e| {
            LlmError::Other(anyhow::anyhow!("Failed to parse OpenAI response: {e}"))
        })?;

        let choice = api_response
            .choices
            .first()
            .ok_or_else(|| LlmError::Other(anyhow::anyhow!("No choices in OpenAI response")))?;

        let content = choice.message.content.clone().unwrap_or_default();

        let tool_calls: Vec<ToolCall> = choice
            .message
            .tool_calls
            .as_ref()
            .map(|calls| {
                calls
                    .iter()
                    .map(|tc| {
                        let args: serde_json::Value =
                            serde_json::from_str(&tc.function.arguments).unwrap_or_default();
                        ToolCall {
                            id: tc.id.clone(),
                            name: tc.function.name.clone(),
                            arguments: args,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let usage = api_response
            .usage
            .map_or_else(TokenUsage::default, |u| TokenUsage {
                input_tokens: u.prompt_tokens,
                output_tokens: u.completion_tokens,
                ..Default::default()
            });

        let stop_reason = parse_stop_reason(choice.finish_reason.as_deref());

        info!(
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            tool_calls = tool_calls.len(),
            stop = ?stop_reason,
            "OpenAI API response"
        );

        Ok(LlmResponse {
            content,
            tool_calls,
            stop_reason,
            usage,
        })
    }

    fn name(&self) -> &str {
        "openai"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_user_message() {
        let msg = ChatMessage::text(Role::User, "scan the network");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "user");
        assert!(api_msg.tool_calls.is_none());
    }

    #[test]
    fn convert_tool_result() {
        let msg = ChatMessage::tool_result("call_1", "scan done");
        let api_msg = convert_message(&msg);
        assert_eq!(api_msg.role, "tool");
        assert_eq!(api_msg.tool_call_id, Some("call_1".to_string()));
    }

    #[test]
    fn parse_openai_stop_reasons() {
        assert_eq!(parse_stop_reason(Some("stop")), StopReason::EndTurn);
        assert_eq!(parse_stop_reason(Some("tool_calls")), StopReason::ToolUse);
        assert_eq!(parse_stop_reason(Some("length")), StopReason::MaxTokens);
    }

    #[test]
    fn deserialize_openai_response() {
        let json = r#"{
            "choices": [{
                "message": {
                    "content": "I will scan the network.",
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "nmap_scan",
                            "arguments": "{\"target\":\"192.168.58.0/24\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50}
        }"#;
        let resp: ApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.choices.len(), 1);
        assert_eq!(
            resp.choices[0].message.tool_calls.as_ref().unwrap().len(),
            1
        );
    }

    #[test]
    fn convert_openai_tools() {
        let tools = vec![super::super::ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run nmap".into(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let api_tools = convert_tools(&tools);
        assert_eq!(api_tools[0].tool_type, "function");
        assert_eq!(api_tools[0].function.name, "nmap_scan");
    }

    #[test]
    fn gpt5_uses_max_completion_tokens() {
        assert!(uses_max_completion_tokens("gpt-5.2"));
        assert!(uses_max_completion_tokens("openai/gpt-5.2"));
        assert!(!uses_max_completion_tokens("gpt-4o-mini"));
    }

    #[test]
    fn detects_org_restricted_messages() {
        // Real 403 string observed when running against a non-allowlisted org.
        assert!(is_org_restricted_message(
            "You do not have access to the organization tied to the API key."
        ));
        // Verified-org wording for gated models (currently surfaces on gpt-5.2).
        assert!(is_org_restricted_message(
            "Your organization must be verified to use the model `gpt-5.2`."
        ));
        // Project-level access denial (project-scoped API keys).
        assert!(is_org_restricted_message(
            "This project does not have access to model `gpt-5.2`."
        ));
        // Unrelated 4xx must not be classified as org-restricted.
        assert!(!is_org_restricted_message(
            "Invalid request: temperature out of range"
        ));
        assert!(!is_org_restricted_message("Rate limit exceeded"));
    }

    #[test]
    fn augment_org_hint_adds_actionable_pointers() {
        let augmented = augment_org_hint(
            "You do not have access to the organization tied to the API key.",
            "gpt-5.2",
        );
        assert!(augmented.contains("OPENAI_ORG_ID"));
        assert!(augmented.contains("ARES_LLM_MODEL"));
        assert!(augmented.contains("gpt-5.2"));
    }

    #[test]
    fn augment_org_hint_is_idempotent() {
        // If the upstream message already mentions one of our pointers (e.g.
        // operator already saw the augmented message once and re-raised it),
        // we don't double up.
        let pre_augmented = "Some upstream wrapper said: set OPENAI_ORG_ID";
        assert_eq!(augment_org_hint(pre_augmented, "gpt-5.2"), pre_augmented,);
    }
}
