use async_openai::{
    Client,
    types::{CreateChatCompletionRequest, ChatCompletionRequestMessage, ChatCompletionRequestUserMessage, ChatCompletionRequestUserMessageContent}
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

// AI Provider enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIProvider {
    OpenAI,
    Anthropic,
    GoogleGemini,
    Local,
}

impl AIProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            AIProvider::OpenAI => "openai",
            AIProvider::Anthropic => "anthropic",
            AIProvider::GoogleGemini => "gemini",
            AIProvider::Local => "local",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "openai" | "gpt" => Some(AIProvider::OpenAI),
            "anthropic" | "claude" => Some(AIProvider::Anthropic),
            "gemini" | "google" | "bard" => Some(AIProvider::GoogleGemini),
            "local" | "ollama" | "self-hosted" => Some(AIProvider::Local),
            _ => None,
        }
    }
}

impl Default for AIProvider {
    fn default() -> Self {
        AIProvider::OpenAI
    }
}

// Model configuration for each provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIModel {
    // OpenAI models
    Gpt35Turbo,
    Gpt4,
    Gpt4Turbo,
    Gpt4O,
    Gpt4OMini,
    
    // Anthropic Claude models
    Claude3Opus,
    Claude3Sonnet,
    Claude3Haiku,
    Claude35Sonnet,
    
    // Google Gemini models
    GeminiPro,
    Gemini15Pro,
    Gemini15Flash,
    
    // Local/Ollama models
    Llama2_7B,
    Llama2_13B,
    Llama2_70B,
    CodeLlama,
    Phi3Mini,
    Phi3Medium,
    Mistral7B,
    Qwen2_7B,
    Custom(String), // For custom local models
}

impl AIModel {
    pub fn as_str(&self) -> &str {
        match self {
            // OpenAI
            AIModel::Gpt35Turbo => "gpt-3.5-turbo",
            AIModel::Gpt4 => "gpt-4",
            AIModel::Gpt4Turbo => "gpt-4-turbo",
            AIModel::Gpt4O => "gpt-4o",
            AIModel::Gpt4OMini => "gpt-4o-mini",
            
            // Anthropic
            AIModel::Claude3Opus => "claude-3-opus-20240229",
            AIModel::Claude3Sonnet => "claude-3-sonnet-20240229",
            AIModel::Claude3Haiku => "claude-3-haiku-20240307",
            AIModel::Claude35Sonnet => "claude-3-5-sonnet-20240620",
            
            // Google Gemini
            AIModel::GeminiPro => "gemini-pro",
            AIModel::Gemini15Pro => "gemini-1.5-pro",
            AIModel::Gemini15Flash => "gemini-1.5-flash",
            
            // Local/Ollama
            AIModel::Llama2_7B => "llama2:7b",
            AIModel::Llama2_13B => "llama2:13b",
            AIModel::Llama2_70B => "llama2:70b",
            AIModel::CodeLlama => "codellama:7b",
            AIModel::Phi3Mini => "phi3:mini",
            AIModel::Phi3Medium => "phi3:medium",
            AIModel::Mistral7B => "mistral:7b",
            AIModel::Qwen2_7B => "qwen2:7b",
            AIModel::Custom(name) => name,
        }
    }

    pub fn provider(&self) -> AIProvider {
        match self {
            AIModel::Gpt35Turbo | AIModel::Gpt4 | AIModel::Gpt4Turbo | 
            AIModel::Gpt4O | AIModel::Gpt4OMini => AIProvider::OpenAI,
            
            AIModel::Claude3Opus | AIModel::Claude3Sonnet | AIModel::Claude3Haiku | 
            AIModel::Claude35Sonnet => AIProvider::Anthropic,
            
            AIModel::GeminiPro | AIModel::Gemini15Pro | AIModel::Gemini15Flash => AIProvider::GoogleGemini,
            
            AIModel::Llama2_7B | AIModel::Llama2_13B | AIModel::Llama2_70B | 
            AIModel::CodeLlama | AIModel::Phi3Mini | AIModel::Phi3Medium | 
            AIModel::Mistral7B | AIModel::Qwen2_7B | AIModel::Custom(_) => AIProvider::Local,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            // OpenAI aliases
            "gpt-3.5-turbo" | "3.5" | "turbo" => Some(AIModel::Gpt35Turbo),
            "gpt-4" | "4" => Some(AIModel::Gpt4),
            "gpt-4-turbo" | "4-turbo" => Some(AIModel::Gpt4Turbo),
            "gpt-4o" | "4o" => Some(AIModel::Gpt4O),
            "gpt-4o-mini" | "4o-mini" => Some(AIModel::Gpt4OMini),
            
            // Anthropic aliases
            "claude-3-opus" | "opus" => Some(AIModel::Claude3Opus),
            "claude-3-sonnet" | "sonnet" => Some(AIModel::Claude3Sonnet),
            "claude-3-haiku" | "haiku" => Some(AIModel::Claude3Haiku),
            "claude-3.5-sonnet" | "3.5-sonnet" => Some(AIModel::Claude35Sonnet),
            
            // Gemini aliases
            "gemini-pro" | "gemini" => Some(AIModel::GeminiPro),
            "gemini-1.5-pro" | "1.5-pro" => Some(AIModel::Gemini15Pro),
            "gemini-1.5-flash" | "1.5-flash" | "flash" => Some(AIModel::Gemini15Flash),
            
            // Local model aliases
            "llama2" | "llama2:7b" => Some(AIModel::Llama2_7B),
            "llama2:13b" => Some(AIModel::Llama2_13B),
            "llama2:70b" => Some(AIModel::Llama2_70B),
            "codellama" | "codellama:7b" => Some(AIModel::CodeLlama),
            "phi3" | "phi3:mini" => Some(AIModel::Phi3Mini),
            "phi3:medium" => Some(AIModel::Phi3Medium),
            "mistral" | "mistral:7b" => Some(AIModel::Mistral7B),
            "qwen2" | "qwen2:7b" => Some(AIModel::Qwen2_7B),
            
            _ => {
                // Check if it's a custom model name
                if s.contains(':') || s.len() > 3 {
                    Some(AIModel::Custom(s.to_string()))
                } else {
                    None
                }
            }
        }
    }
}

impl Default for AIModel {
    fn default() -> Self {
        AIModel::Gpt35Turbo
    }
}

// Configuration for different providers
#[derive(Debug, Clone)]
pub struct AIConfig {
    pub provider: AIProvider,
    pub model: AIModel,
    pub api_key: Option<String>,
    pub base_url: Option<String>, // For local/custom endpoints
    pub temperature: f32,
    pub max_tokens: Option<u32>,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            provider: AIProvider::default(),
            model: AIModel::default(),
            api_key: None,
            base_url: None,
            temperature: 0.7,
            max_tokens: Some(4000),
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
        self.temperature = temperature;
        self
    }
}

// Legacy support for backward compatibility
#[derive(Debug, Clone)]
pub enum OpenAIModel {
    Gpt35Turbo,
    Gpt4,
    Gpt4Turbo,
    Gpt4O,
    Gpt4OMini,
}

impl OpenAIModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            OpenAIModel::Gpt35Turbo => "gpt-3.5-turbo",
            OpenAIModel::Gpt4 => "gpt-4",
            OpenAIModel::Gpt4Turbo => "gpt-4-turbo",
            OpenAIModel::Gpt4O => "gpt-4o",
            OpenAIModel::Gpt4OMini => "gpt-4o-mini",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "gpt-3.5-turbo" | "3.5" | "turbo" => Some(OpenAIModel::Gpt35Turbo),
            "gpt-4" | "4" => Some(OpenAIModel::Gpt4),
            "gpt-4-turbo" | "4-turbo" => Some(OpenAIModel::Gpt4Turbo),
            "gpt-4o" | "4o" => Some(OpenAIModel::Gpt4O),
            "gpt-4o-mini" | "4o-mini" => Some(OpenAIModel::Gpt4OMini),
            _ => None,
        }
    }

    // Convert to new AIModel enum
    pub fn to_ai_model(&self) -> AIModel {
        match self {
            OpenAIModel::Gpt35Turbo => AIModel::Gpt35Turbo,
            OpenAIModel::Gpt4 => AIModel::Gpt4,
            OpenAIModel::Gpt4Turbo => AIModel::Gpt4Turbo,
            OpenAIModel::Gpt4O => AIModel::Gpt4O,
            OpenAIModel::Gpt4OMini => AIModel::Gpt4OMini,
        }
    }
}

impl Default for OpenAIModel {
    fn default() -> Self {
        OpenAIModel::Gpt35Turbo
    }
}

// Universal AI Client that can work with multiple providers
pub struct UniversalAIClient {
    config: AIConfig,
    openai_client: Option<Client<async_openai::config::OpenAIConfig>>,
}

impl UniversalAIClient {
    pub fn new(config: AIConfig) -> Result<Self> {
        let mut client = Self {
            config: config.clone(),
            openai_client: None,
        };

        // Initialize provider-specific clients
        match config.provider {
            AIProvider::OpenAI => {
                let api_key = config.api_key
                    .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                    .ok_or_else(|| anyhow::anyhow!("OpenAI API key not found. Set OPENAI_API_KEY environment variable or provide via --openai-key"))?;
                
                let openai_config = async_openai::config::OpenAIConfig::new().with_api_key(api_key);
                client.openai_client = Some(Client::with_config(openai_config));
            },
            AIProvider::Anthropic => {
                // Will be implemented when we add Claude support
                return Err(anyhow::anyhow!("Anthropic Claude support coming soon! Set ANTHROPIC_API_KEY when available."));
            },
            AIProvider::GoogleGemini => {
                // Will be implemented when we add Gemini support
                return Err(anyhow::anyhow!("Google Gemini support coming soon! Set GOOGLE_API_KEY when available."));
            },
            AIProvider::Local => {
                // Will be implemented for Ollama/local models
                return Err(anyhow::anyhow!("Local model support coming soon! Use --base-url for custom endpoints."));
            },
        }

        Ok(client)
    }

    pub fn from_model(model: AIModel) -> Result<Self> {
        let mut config = AIConfig::new(model.clone());
        
        // Set provider-specific defaults
        match model.provider() {
            AIProvider::Local => {
                config.base_url = Some("http://localhost:11434".to_string()); // Default Ollama endpoint
            },
            _ => {}
        }

        Self::new(config)
    }

    pub fn get_config(&self) -> &AIConfig {
        &self.config
    }

    pub fn get_model_info(&self) -> String {
        format!("{} ({})", self.config.model.as_str(), self.config.provider.as_str())
    }

    pub async fn generate_tests(&self, prompt: &str) -> Result<String> {
        match self.config.provider {
            AIProvider::OpenAI => self.call_openai(prompt).await,
            AIProvider::Anthropic => self.call_anthropic(prompt).await,
            AIProvider::GoogleGemini => self.call_gemini(prompt).await,
            AIProvider::Local => self.call_local(prompt).await,
        }
    }

    async fn call_openai(&self, prompt: &str) -> Result<String> {
        let client = self.openai_client.as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenAI client not initialized"))?;

        let request = CreateChatCompletionRequest {
            model: self.config.model.as_str().to_string(),
            messages: vec![
                ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
                    content: ChatCompletionRequestUserMessageContent::Text(prompt.to_string()),
                    name: None,
                }),
            ],
            temperature: Some(self.config.temperature),
            max_completion_tokens: self.config.max_tokens,
            ..Default::default()
        };

        let response = client.chat().create(request).await?;
        
        if let Some(choice) = response.choices.first() {
            if let Some(content) = &choice.message.content {
                return Ok(content.clone());
            }
        }
        
        Err(anyhow::anyhow!("No response from OpenAI"))
    }

    async fn call_anthropic(&self, _prompt: &str) -> Result<String> {
        // TODO: Implement Anthropic Claude API integration
        Err(anyhow::anyhow!("Anthropic Claude support coming in next version! 🚀"))
    }

    async fn call_gemini(&self, _prompt: &str) -> Result<String> {
        // TODO: Implement Google Gemini API integration
        Err(anyhow::anyhow!("Google Gemini support coming in next version! 🚀"))
    }

    async fn call_local(&self, _prompt: &str) -> Result<String> {
        // TODO: Implement Ollama/local model integration
        let base_url = self.config.base_url.as_deref().unwrap_or("http://localhost:11434");
        Err(anyhow::anyhow!(
            "Local model support coming in next version! 🚀\nPrepare your Ollama server at: {}", 
            base_url
        ))
    }
}

// Legacy OpenAI-specific client for backward compatibility
pub struct OpenAiProvider {
    client: Client<async_openai::config::OpenAIConfig>,
    model: OpenAIModel,
}

impl OpenAiProvider {
    pub fn new(config: crate::core::AIConfig) -> Self {
        let api_key = config.api_key
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .expect("OpenAI API key not found");
        
        let client = Client::with_config(
            async_openai::config::OpenAIConfig::new().with_api_key(api_key)
        );
        
        let model = match config.model.as_str() {
            "gpt-4" => OpenAIModel::Gpt4,
            "gpt-4o" => OpenAIModel::Gpt4O,
            "gpt-4o-mini" => OpenAIModel::Gpt4OMini,
            "gpt-3.5-turbo" => OpenAIModel::Gpt35Turbo,
            _ => OpenAIModel::Gpt4OMini, // Default
        };
        
        Self { client, model }
    }
    
    pub async fn generate_completion(&self, prompt: &str) -> crate::core::Result<String> {
        let request = CreateChatCompletionRequest {
            model: self.model.as_str().to_string(),
            messages: vec![
                ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
                    content: ChatCompletionRequestUserMessageContent::Text(prompt.to_string()),
                    name: None,
                })
            ],
            temperature: Some(0.7),
            ..Default::default()
        };

        let response = self.client.chat().create(request).await
            .map_err(|e| crate::core::AmaltheaError::ProviderError(format!("OpenAI error: {}", e)))?;
        
        Ok(response.choices
            .first()
            .and_then(|choice| choice.message.content.as_ref())
            .unwrap_or(&"No response generated".to_string())
            .clone())
    }
}

pub struct OpenAIClient {
    client: Client<async_openai::config::OpenAIConfig>,
    model: OpenAIModel,
}

impl OpenAIClient {
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Self::with_model(OpenAIModel::default())
    }

    pub fn with_model(model: OpenAIModel) -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY environment variable not set"))?;
        
        let client = Client::with_config(async_openai::config::OpenAIConfig::new().with_api_key(api_key));
        Ok(Self { client, model })
    }

    #[allow(dead_code)]
    pub fn set_model(&mut self, model: OpenAIModel) {
        self.model = model;
    }

    #[allow(dead_code)]
    pub fn get_model(&self) -> &OpenAIModel {
        &self.model
    }

    pub async fn generate_tests(&self, prompt: &str) -> Result<String> {
        let request = CreateChatCompletionRequest {
            model: self.model.as_str().to_string(),
            messages: vec![
                ChatCompletionRequestMessage::User(ChatCompletionRequestUserMessage {
                    content: ChatCompletionRequestUserMessageContent::Text(prompt.to_string()),
                    name: None,
                }),
            ],
            temperature: Some(0.7),
            ..Default::default()
        };

        let response = self.client.chat().create(request).await?;
        
        if let Some(choice) = response.choices.first() {
            if let Some(content) = &choice.message.content {
                return Ok(content.clone());
            }
        }
        
        Err(anyhow::anyhow!("No response from OpenAI"))
    }
}

// Helper functions for backward compatibility and convenience
pub fn detect_provider_from_model(model: &AIModel) -> AIProvider {
    model.provider()
}

pub fn ai_model_to_openai_model(model: &AIModel) -> OpenAIModel {
    match model {
        AIModel::Gpt35Turbo => OpenAIModel::Gpt35Turbo,
        AIModel::Gpt4 => OpenAIModel::Gpt4,
        AIModel::Gpt4Turbo => OpenAIModel::Gpt4Turbo,
        AIModel::Gpt4O => OpenAIModel::Gpt4O,
        AIModel::Gpt4OMini => OpenAIModel::Gpt4OMini,
        _ => {
            eprintln!("⚠️  Non-OpenAI model '{}' provided, falling back to GPT-4", model.as_str());
            OpenAIModel::Gpt4
        }
    }
}

pub fn string_to_ai_model(model_str: &str) -> AIModel {
    AIModel::from_str(model_str).unwrap_or_else(|| {
        eprintln!("⚠️  Unknown model '{}', using GPT-4", model_str);
        AIModel::Gpt4
    })
}
