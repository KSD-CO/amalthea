use crate::core::{AIConfig, AmaltheaError, Result};
use anyhow::Result as AnyhowResult;
use serde::{Deserialize, Serialize};
use reqwest;

/// Anthropic Claude provider implementation
pub struct AnthropicProvider {
    config: AIConfig,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ClaudeMessage>,
    temperature: Option<f32>,
}

#[derive(Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Deserialize)]
struct ClaudeContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

impl AnthropicProvider {
    pub fn new(config: AIConfig) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }

    pub async fn generate_completion(&self, prompt: &str) -> Result<String> {
        let api_key = self.config.api_key.as_ref()
            .ok_or_else(|| AmaltheaError::ConfigError("ANTHROPIC_API_KEY not set".to_string()))?;

        let default_url = "https://api.anthropic.com".to_string();
        let base_url = self.config.base_url.as_ref().unwrap_or(&default_url);
        
        let model = self.config.model.as_str();

        call_claude_api(&self.client, base_url, api_key, model, prompt, &self.config).await
            .map_err(|e| AmaltheaError::ProviderError(format!("Claude API error: {}", e)))
    }
}

/// Call Anthropic Claude API for text generation
pub async fn call_claude_api(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
    config: &AIConfig,
) -> AnyhowResult<String> {
    let url = format!("{}/v1/messages", base_url);
    
    let request = ClaudeRequest {
        model: model.to_string(),
        max_tokens: config.max_tokens.unwrap_or(4096),
        messages: vec![ClaudeMessage {
            role: "user".to_string(),
            content: prompt.to_string(),
        }],
        temperature: if config.temperature > 0.0 { Some(config.temperature) } else { None },
    };

    let response = client
        .post(&url)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Claude API returned status {}: {}", status, error_text));
    }

    let claude_response: ClaudeResponse = response.json().await?;
    
    if let Some(content) = claude_response.content.first() {
        if content.content_type == "text" {
            return Ok(content.text.clone());
        }
    }

    Err(anyhow::anyhow!("Claude response format unexpected"))
}
