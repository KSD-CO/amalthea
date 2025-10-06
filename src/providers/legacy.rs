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
            
            // Claude full model names
            "claude-3-opus-20240229" => Some(AIModel::Claude3Opus),
            "claude-3-sonnet-20240229" => Some(AIModel::Claude3Sonnet),
            "claude-3-haiku-20240307" => Some(AIModel::Claude3Haiku),
            "claude-3-5-sonnet-20240620" => Some(AIModel::Claude35Sonnet),
            
            // Gemini aliases
            "gemini-pro" | "gemini" => Some(AIModel::GeminiPro),
            "gemini-1.5-pro" | "1.5-pro" => Some(AIModel::Gemini15Pro),
            "gemini-1.5-flash" | "1.5-flash" | "flash" => Some(AIModel::Gemini15Flash),
            
            // Local model aliases
            "llama2" | "llama2:7b" => Some(AIModel::Llama2_7B),
            "llama2:13b" => Some(AIModel::Llama2_13B),
            "llama2:70b" => Some(AIModel::Llama2_70B),
            "codellama" | "codellama:7b" => Some(AIModel::CodeLlama),
            "phi3" | "phi3:mini" | "phi:latest" => Some(AIModel::Phi3Mini),
            "phi3:medium" => Some(AIModel::Phi3Medium),
            "mistral" | "mistral:7b" | "mistral:latest" => Some(AIModel::Mistral7B),
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

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
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
                // Anthropic Claude implementation is now available
                println!("🔧 Initializing Anthropic Claude provider...");
                if let Some(_api_key) = &config.api_key {
                    println!("✅ Anthropic API key configured");
                } else {
                    eprintln!("⚠️  Warning: ANTHROPIC_API_KEY not set, using provided key");
                }
            },
            AIProvider::GoogleGemini => {
                // Google Gemini implementation is now available
                println!("🔧 Initializing Google Gemini provider...");
                if let Some(_api_key) = &config.api_key {
                    println!("✅ Google API key configured");
                } else {
                    eprintln!("⚠️  Warning: GOOGLE_API_KEY not set, using provided key");
                }
            },
            AIProvider::Local => {
                // Local models don't need API keys, just validate the base_url
                println!("🔧 Initializing local AI provider...");
                if let Some(url) = &config.base_url {
                    println!("🔗 Local endpoint: {}", url);
                } else {
                    println!("🔗 Using default Ollama endpoint: http://localhost:11434");
                }
                // Local provider is ready - no additional setup needed
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

    async fn call_anthropic(&self, prompt: &str) -> Result<String> {
        // Convert legacy AIConfig to core AIConfig
        let core_config = crate::core::config::AIConfig {
            provider: crate::core::types::AIProvider::Anthropic,
            model: match &self.config.model {
                AIModel::Claude3Opus => crate::core::types::AIModel::Claude3Opus,
                AIModel::Claude3Sonnet => crate::core::types::AIModel::Claude3Sonnet,
                AIModel::Claude3Haiku => crate::core::types::AIModel::Claude3Haiku,
                AIModel::Claude35Sonnet => crate::core::types::AIModel::Claude35Sonnet,
                _ => crate::core::types::AIModel::Claude3Sonnet, // Default
            },
            api_key: self.config.api_key.clone(),
            base_url: self.config.base_url.clone(),
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            timeout_seconds: 30,
        };

        let anthropic_provider = crate::providers::anthropic::AnthropicProvider::new(core_config);
        anthropic_provider.generate_completion(prompt).await
            .map_err(|e| anyhow::anyhow!("Anthropic provider error: {}", e))
    }

    async fn call_gemini(&self, prompt: &str) -> Result<String> {
        // Convert legacy AIConfig to core AIConfig
        let core_config = crate::core::config::AIConfig {
            provider: crate::core::types::AIProvider::GoogleGemini,
            model: match &self.config.model {
                AIModel::GeminiPro => crate::core::types::AIModel::GeminiPro,
                AIModel::Gemini15Pro => crate::core::types::AIModel::Gemini15Pro,
                AIModel::Gemini15Flash => crate::core::types::AIModel::Gemini15Flash,
                _ => crate::core::types::AIModel::Gemini15Flash, // Default
            },
            api_key: self.config.api_key.clone(),
            base_url: self.config.base_url.clone(),
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            timeout_seconds: 30,
        };

        let gemini_provider = crate::providers::gemini::GeminiProvider::new(core_config);
        gemini_provider.generate_completion(prompt).await
            .map_err(|e| anyhow::anyhow!("Gemini provider error: {}", e))
    }

    async fn call_local(&self, prompt: &str) -> Result<String> {
        // Convert legacy AIConfig to core AIConfig
        let core_config = crate::core::config::AIConfig {
            provider: crate::core::types::AIProvider::Local,
            model: {
                // Try to parse the model to a core AIModel
                let model_str = self.config.model.as_str();
                match model_str {
                    "phi:latest" | "phi3:mini" => crate::core::types::AIModel::Phi3Mini,
                    "mistral:latest" | "mistral:7b" => crate::core::types::AIModel::Mistral7B,
                    "llama2:7b" => crate::core::types::AIModel::Llama2_7B,
                    "llama2:13b" => crate::core::types::AIModel::Llama2_13B,
                    "llama2:70b" => crate::core::types::AIModel::Llama2_70B,
                    "codellama:7b" => crate::core::types::AIModel::CodeLlama,
                    _ => crate::core::types::AIModel::Custom(model_str.to_string()),
                }
            },
            api_key: self.config.api_key.clone(),
            base_url: self.config.base_url.clone(),
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
            timeout_seconds: 30,
        };

        let local_provider = crate::providers::local::LocalProvider::new(core_config);
        local_provider.generate_completion(prompt).await
            .map_err(|e| anyhow::anyhow!("Local provider error: {}", e))
    }
}

// Legacy OpenAI-specific client for backward compatibility
pub struct OpenAiProvider {
    client: Client<async_openai::config::OpenAIConfig>,
    model: OpenAIModel,
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

impl OpenAiProvider {
    #[allow(dead_code)]
    pub fn new(api_key: &str) -> Self {
        Self::with_model(api_key, OpenAIModel::default())
    }

    pub fn with_model(api_key: &str, model: OpenAIModel) -> Self {
        let client = Client::with_config(async_openai::config::OpenAIConfig::new().with_api_key(api_key));
        Self { client, model }
    }

    #[allow(dead_code)]
    pub fn set_model(&mut self, model: OpenAIModel) {
        self.model = model;
    }

    #[allow(dead_code)]
    pub fn get_model(&self) -> &OpenAIModel {
        &self.model
    }

    pub async fn generate_tests(&self, api_desc: &str) -> Result<Vec<String>> {
        self.generate_tests_with_context(api_desc, None, None, None).await
    }

    pub async fn generate_tests_with_context(
        &self, 
        api_desc: &str, 
        query_params: Option<&str>, 
        body_payload: Option<&str>,
        business_context: Option<&str>
    ) -> Result<Vec<String>> {
        let business_info = business_context
            .map(|ctx| format!("\n\nBusiness Context: {}", ctx))
            .unwrap_or_default();

        let prompt = if let Some(query) = query_params {
            // Generate query parameter variations
            format!(
                "As a professional API testing specialist, generate 6 comprehensive query parameter test scenarios for the endpoint: {}{}
                
                Current query parameters: {}
                
                Create test cases covering:
                1. Valid baseline scenario with typical business values
                2. Valid scenario with alternative realistic values
                3. Boundary testing with minimum/maximum allowed values
                4. Edge case with empty/null values where applicable
                5. Invalid data types to test validation (string for numbers, etc.)
                6. Missing required parameters or invalid combinations
                
                Requirements:
                - Each test case should be a complete query string (without the ? prefix)
                - One test case per line
                - No explanations or numbering, just the raw query parameters
                - Focus on realistic business scenarios and common validation issues
                - Consider the business context when generating realistic values
                
                Format: param1=value1&param2=value2&param3=value3",
                api_desc, business_info, query
            )
        } else if let Some(body) = body_payload {
            // Generate JSON body variations
            format!(
                "As a professional API testing specialist, generate 6 comprehensive JSON payload test scenarios for the endpoint: {}{}
                
                Base payload structure: {}
                
                Create test cases covering:
                1. Valid baseline scenario with typical business values
                2. Valid scenario with alternative realistic data
                3. Boundary testing with minimum/maximum field lengths and values
                4. Edge case with null/empty values for optional fields
                5. Invalid data types to test field validation (wrong types, formats)
                6. Missing required fields or invalid field combinations
                
                Requirements:
                - Each test case should be a complete, valid JSON object
                - One JSON object per line
                - No explanations or numbering, just the raw JSON
                - Maintain proper JSON syntax and structure
                - Focus on realistic business scenarios and common validation patterns
                - Consider the business context when generating realistic field values
                
                Return only the JSON objects:",
                api_desc, business_info, body
            )
        } else {
            // Default generation for endpoints without specific query/body context
            format!(
                "As a professional API testing specialist, generate 6 comprehensive test data scenarios for the API endpoint: {}{}
                
                Create test cases covering:
                1. Valid baseline scenario with typical business values
                2. Valid scenario with alternative realistic data  
                3. Boundary testing with edge values
                4. Empty/null value scenarios
                5. Invalid data types and formats
                6. Missing or invalid parameter combinations
                
                Requirements:
                - Generate appropriate format based on HTTP method (JSON for POST/PUT/PATCH, query params for GET/DELETE)
                - One test case per line
                - No explanations or numbering
                - Focus on realistic business scenarios and validation testing
                - Consider the business context when generating values
                
                Return the test data in the appropriate format:",
                api_desc, business_info
            )
        };

        let req = CreateChatCompletionRequest {
            model: self.model.as_str().into(),
            messages: vec![ChatCompletionRequestMessage::User(
                ChatCompletionRequestUserMessage {
                    content: ChatCompletionRequestUserMessageContent::Text(prompt),
                    name: None,
                }
            )],
            ..Default::default()
        };

        let resp = self.client.chat().create(req).await?;
        let content = resp.choices[0].message.content.clone().unwrap_or_default();

        // Determine if we're expecting JSON or query parameters based on the prompt
        let expecting_json = body_payload.is_some();
        
        let mut results = Vec::new();

        if expecting_json {
            // Parse JSON objects from the response
            let mut current_json = String::new();
            let mut brace_count = 0;
            let mut in_json = false;

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                
                // Skip lines that don't start with { and aren't part of a JSON object
                if !in_json && !trimmed.starts_with('{') {
                    continue;
                }
                
                current_json.push_str(line);
                current_json.push('\n');
                
                // Count braces to detect complete JSON objects
                for ch in line.chars() {
                    match ch {
                        '{' => {
                            brace_count += 1;
                            in_json = true;
                        }
                        '}' => {
                            brace_count -= 1;
                            if brace_count == 0 && in_json {
                                // Complete JSON object found
                                let json_str = current_json.trim().to_string();
                                if !json_str.is_empty() {
                                    results.push(json_str);
                                }
                                current_json.clear();
                                in_json = false;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Fallback: if no complete JSON objects found, try to extract lines that look like JSON
            if results.is_empty() {
                results = content
                    .lines()
                    .filter(|line| {
                        let trimmed = line.trim();
                        !trimmed.is_empty() && 
                        (trimmed.starts_with('{') || trimmed.contains(':'))
                    })
                    .map(|s| s.trim().to_string())
                    .collect();
            }
        } else {
            // Parse query parameter strings
            results = content
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    // Look for lines that contain query parameter patterns
                    !trimmed.is_empty() && 
                    !trimmed.starts_with('#') &&
                    !trimmed.starts_with("Example") &&
                    !trimmed.starts_with("1.") &&
                    !trimmed.starts_with("2.") &&
                    !trimmed.starts_with("3.") &&
                    (trimmed.contains('=') || trimmed.contains('&'))
                })
                .map(|s| s.trim().to_string())
                .collect();
        }

        Ok(results)
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
