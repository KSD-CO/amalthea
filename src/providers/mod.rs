pub mod openai;
pub mod anthropic;
pub mod gemini;
pub mod local;
pub mod universal;
pub mod legacy;  // Legacy compatibility layer

// Specific exports to avoid conflicts
pub use openai::OpenAiProvider;
pub use anthropic::AnthropicProvider;
pub use gemini::GeminiProvider;
pub use local::LocalProvider;
pub use universal::UniversalAIClient;
