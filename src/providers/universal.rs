use crate::core::{AIConfig, AIProvider, Result};
use crate::providers::{AnthropicProvider, GeminiProvider, LocalProvider, openai::OpenAiProvider};

/// Universal AI client that handles all providers
pub struct UniversalAIClient {
    config: AIConfig,
}

impl UniversalAIClient {
    pub fn new(config: AIConfig) -> Self {
        Self { config }
    }

    pub async fn generate_completion(&self, prompt: &str) -> Result<String> {
        match self.config.provider {
            AIProvider::OpenAI => {
                let provider = OpenAiProvider::new(self.config.clone());
                provider.generate_completion(prompt).await
            },
            AIProvider::Anthropic => {
                let provider = AnthropicProvider::new(self.config.clone());
                provider.generate_completion(prompt).await
            },
            AIProvider::GoogleGemini => {
                let provider = GeminiProvider::new(self.config.clone());
                provider.generate_completion(prompt).await
            },
            AIProvider::Local => {
                let provider = LocalProvider::new(self.config.clone());
                provider.generate_completion(prompt).await
            },
        }
    }

    pub fn provider(&self) -> &AIProvider {
        &self.config.provider
    }

    pub fn model_name(&self) -> &str {
        self.config.model.as_str()
    }
}

/// Factory function to create appropriate provider client
pub fn create_ai_client(config: AIConfig) -> UniversalAIClient {
    UniversalAIClient::new(config)
}
