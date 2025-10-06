use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Input file (OpenAPI spec or Postman collection)
    #[clap(short, long)]
    pub file: String,

    /// API key for AI provider (overrides environment variables)
    #[clap(long)]
    pub api_key: Option<String>,

    /// AI provider to use (openai, anthropic, gemini, local)
    #[clap(long)]
    pub provider: Option<String>,

    /// Base URL for AI provider (for local/custom endpoints)
    #[clap(long)]
    pub base_url: Option<String>,

    /// AI model to use
    #[clap(short, long, default_value = "gpt-4")]
    pub model: String,

    /// Output file for test results
    #[clap(short, long)]
    pub output: Option<String>,

    /// Export format
    #[clap(long, default_value = "json")]
    pub format: String,

    /// Generate test suite only (no execution)
    #[clap(long)]
    pub generate_only: bool,

    /// Knowledge base file path
    #[clap(long)]
    pub kb: Option<String>,

    /// Interactive mode
    #[clap(short, long)]
    pub interactive: bool,

    /// Temperature for AI model (0.0 to 1.0)
    #[clap(long, default_value = "0.7")]
    pub temperature: f32,

    /// Maximum tokens for AI response
    #[clap(long)]
    pub max_tokens: Option<u32>,

    /// Timeout for HTTP requests (seconds)
    #[clap(long, default_value = "30")]
    pub timeout: u32,
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
