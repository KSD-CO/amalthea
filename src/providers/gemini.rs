use crate::core::{AIConfig, AmaltheaError, Result};
use anyhow::Result as AnyhowResult;
use serde::{Deserialize, Serialize};
use reqwest;

/// Google Gemini provider implementation
pub struct GeminiProvider {
    config: AIConfig,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
    #[serde(rename = "generationConfig", skip_serializing_if = "Option::is_none")]
    generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Serialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Serialize)]
struct GeminiPart {
    text: String,
}

#[derive(Serialize)]
struct GeminiGenerationConfig {
    temperature: f32,
    #[serde(rename = "maxOutputTokens", skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiResponseContent,
    #[serde(rename = "finishReason", skip_serializing_if = "Option::is_none")]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct GeminiResponseContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<Vec<GeminiResponsePart>>,
}

#[derive(Deserialize)]
struct GeminiResponsePart {
    text: String,
}

impl GeminiProvider {
    pub fn new(config: AIConfig) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }

    pub async fn generate_completion(&self, prompt: &str) -> Result<String> {
        let api_key = self.config.api_key.as_ref()
            .ok_or_else(|| AmaltheaError::ConfigError("GOOGLE_API_KEY not set".to_string()))?;

        let default_url = "https://generativelanguage.googleapis.com".to_string();
        let base_url = self.config.base_url.as_ref().unwrap_or(&default_url);
        
        let model = self.config.model.as_str();

        call_gemini_api(&self.client, base_url, api_key, model, prompt, &self.config).await
            .map_err(|e| AmaltheaError::ProviderError(format!("Gemini API error: {}", e)))
    }
}

/// Call Google Gemini API for text generation
pub async fn call_gemini_api(
    client: &reqwest::Client,
    base_url: &str,
    api_key: &str,
    model: &str,
    prompt: &str,
    config: &AIConfig,
) -> AnyhowResult<String> {
    let url = format!("{}/v1beta/models/{}:generateContent", base_url, model);
    
    let generation_config = if config.temperature > 0.0 || config.max_tokens.is_some() {
        Some(GeminiGenerationConfig {
            temperature: config.temperature,
            max_output_tokens: config.max_tokens,
        })
    } else {
        None
    };

    let request = GeminiRequest {
        contents: vec![GeminiContent {
            parts: vec![GeminiPart {
                text: prompt.to_string(),
            }],
        }],
        generation_config,
    };

    let response = client
        .post(&url)
        .query(&[("key", api_key)])
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Gemini API returned status {}: {}", status, error_text));
    }

    let response_text = response.text().await?;
    
    let gemini_response: GeminiResponse = serde_json::from_str(&response_text)
        .map_err(|e| anyhow::anyhow!("Failed to parse Gemini response: {}", e))?;
    
    if let Some(candidate) = gemini_response.candidates.first() {
        // Check if finish reason indicates issue
        if let Some(finish_reason) = &candidate.finish_reason {
            if finish_reason == "MAX_TOKENS" {
                return Err(anyhow::anyhow!("Gemini response truncated due to max tokens limit. Try reducing input size or increasing max_tokens."));
            }
        }
        
        // Try to get text from parts
        if let Some(parts) = &candidate.content.parts {
            if let Some(part) = parts.first() {
                return Ok(part.text.clone());
            }
        }
        
        // If no parts but we have content, return error with more details
        return Err(anyhow::anyhow!("Gemini response has no content parts. Finish reason: {:?}", candidate.finish_reason));
    }

    Err(anyhow::anyhow!("Gemini response contains no candidates"))
}
