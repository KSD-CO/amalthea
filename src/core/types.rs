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
            
            // Unknown model - treat as custom
            _ => {
                if s.contains(':') || s.len() > 3 {
                    Some(AIModel::Custom(s.to_string()))
                } else {
                    None
                }
            }
        }
    }
}

// Helper functions for backward compatibility and convenience
pub fn detect_provider_from_model(model: &AIModel) -> AIProvider {
    model.provider()
}

pub fn string_to_ai_model(model_str: &str) -> AIModel {
    AIModel::from_str(model_str).unwrap_or_else(|| {
        eprintln!("⚠️  Unknown model '{}', using GPT-4", model_str);
        AIModel::Gpt4
    })
}
