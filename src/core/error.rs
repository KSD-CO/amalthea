use thiserror::Error;

#[derive(Error, Debug)]
pub enum AmaltheaError {
    #[error("AI provider error: {0}")]
    ProviderError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("API specification error: {0}")]
    SpecError(String),
    
    #[error("Test generation error: {0}")]
    TestGenerationError(String),
    
    #[error("Test execution error: {0}")]
    TestExecutionError(String),
    
    #[error("HTTP error: {0}")]
    HttpError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AmaltheaError>;
