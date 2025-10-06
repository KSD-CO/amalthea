use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::core::types::{AIModel, AIProvider};

/// Configuration for AI providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    pub provider: AIProvider,
    pub model: AIModel,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub temperature: f32,
    pub max_tokens: Option<u32>,
    pub timeout_seconds: u32,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            provider: AIProvider::OpenAI,
            model: AIModel::Gpt4,
            api_key: None,
            base_url: None,
            temperature: 0.7,
            max_tokens: Some(2048),
            timeout_seconds: 30,
        }
    }
}

impl AIConfig {
    pub fn new(model: AIModel) -> Self {
        Self {
            provider: model.provider(),
            model,
            ..Default::default()
        }
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = Some(base_url);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Get API key from config or environment
    pub fn get_api_key(&self) -> Result<String> {
        if let Some(key) = &self.api_key {
            return Ok(key.clone());
        }

        // Try environment variables based on provider
        let env_var = match self.provider {
            AIProvider::OpenAI => "OPENAI_API_KEY",
            AIProvider::Anthropic => "ANTHROPIC_API_KEY", 
            AIProvider::GoogleGemini => "GOOGLE_API_KEY",
            AIProvider::Local => return Err(anyhow::anyhow!("Local models don't require API keys")),
        };

        std::env::var(env_var)
            .map_err(|_| anyhow::anyhow!("API key not found in config or environment variable {}", env_var))
    }

    /// Get base URL for provider
    pub fn get_base_url(&self) -> String {
        if let Some(url) = &self.base_url {
            return url.clone();
        }

        match self.provider {
            AIProvider::OpenAI => "https://api.openai.com/v1".to_string(),
            AIProvider::Anthropic => "https://api.anthropic.com".to_string(),
            AIProvider::GoogleGemini => "https://generativelanguage.googleapis.com/v1".to_string(),
            AIProvider::Local => "http://localhost:11434".to_string(),
        }
    }
}
