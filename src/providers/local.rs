use crate::core::{AIConfig, AmaltheaError, Result};
use anyhow::Result as AnyhowResult;
use serde::{Deserialize, Serialize};
use reqwest;

/// Local/Ollama provider implementation
pub struct LocalProvider {
    config: AIConfig,
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
    done: bool,
}

impl LocalProvider {
    pub fn new(config: AIConfig) -> Self {
        Self { config }
    }

    pub async fn generate_completion(&self, prompt: &str) -> Result<String> {
        let default_url = "http://localhost:11434".to_string();
        let base_url = self.config.base_url.as_ref()
            .unwrap_or(&default_url);
        
        let model = self.config.model.as_str();

        call_ollama_api(base_url, model, prompt).await
            .map_err(|e| AmaltheaError::ProviderError(format!("Ollama API error: {}", e)))
    }
}

/// Call Ollama API for text generation
pub async fn call_ollama_api(base_url: &str, model: &str, prompt: &str) -> AnyhowResult<String> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/generate", base_url);
    
    let request = OllamaRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
    };

    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Ollama API returned status: {}", response.status()));
    }

    let ollama_response: OllamaResponse = response.json().await?;
    
    if !ollama_response.done {
        return Err(anyhow::anyhow!("Ollama response incomplete"));
    }

    Ok(ollama_response.response)
}
