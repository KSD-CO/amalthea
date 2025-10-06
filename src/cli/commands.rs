use crate::cli::Args;
use crate::ai::{AIConfig, string_to_ai_model, detect_provider_from_model, ai_model_to_openai_model};
use crate::specs::{load_openapi_spec, load_postman_collection};
use crate::testing::{TestSuiteGenerator, ExportFormat};
use crate::utils::knowledge_base::load_knowledge_base;
use anyhow::Result;
use colored::*;

pub async fn run_app(args: Args) -> Result<()> {
    // Convert string model to AIModel enum
    let ai_model = string_to_ai_model(&args.model);
    
    // Create AI configuration
    let mut ai_config = AIConfig::new(ai_model.clone());
    
    // Set API key if provided
    if let Some(api_key) = args.api_key {
        ai_config = ai_config.with_api_key(api_key);
    }
    
    // Set provider if provided, otherwise auto-detect from model
    let provider = if let Some(provider_str) = args.provider {
        // For now, use string representation
        provider_str
    } else {
        detect_provider_from_model(&ai_model).as_str().to_string()
    };
    
    // Set base URL if provided
    if let Some(base_url) = args.base_url {
        ai_config = ai_config.with_base_url(base_url);
    }
    
    // Set temperature and other options
    ai_config = ai_config.with_temperature(args.temperature);
    if let Some(max_tokens) = args.max_tokens {
        ai_config = ai_config.with_max_tokens(max_tokens);
    }

    println!("{}", "🌋 Amalthea - AI-powered API Testing Tool".bright_red().bold());
    println!("{} Multi-provider AI support (OpenAI, Claude, Gemini, Local)", "✨".yellow());
    println!("{} Provider: {} | Model: {} | Temp: {}", "🤖".cyan(), 
             provider.bright_blue(), 
             ai_model.as_str().green(),
             args.temperature.to_string().bright_magenta());

    if args.interactive {
        run_interactive_mode(&args.file, &ai_model, &ai_config).await?;
    } else if args.generate_only {
        generate_test_suite_only(&args.file, &ai_model, args.output.as_deref(), args.kb.as_deref()).await?;
    } else {
        let format = match args.format.as_str() {
            "json" => ExportFormat::Json,
            "csv" => ExportFormat::Csv,
            "both" => ExportFormat::Both,
            _ => {
                eprintln!("⚠️  Unknown format '{}', using JSON", args.format);
                ExportFormat::Json
            }
        };
        generate_and_run_tests(&args.file, &ai_model, args.output.as_deref(), format, args.kb.as_deref()).await?;
    }

    Ok(())
}

async fn generate_and_run_tests(
    spec_file: &str, 
    model: &crate::ai::AIModel, 
    output_file: Option<&str>, 
    _format: ExportFormat,
    kb_file: Option<&str>
) -> Result<()> {
    println!("{}", "🔄 Full Test Generation & Execution Mode".bright_green().bold());
    println!("{} Using model: {} ({})", "🤖".yellow(), 
             model.as_str().cyan(), 
             model.provider().as_str().bright_blue());
    
    // Load knowledge base if provided
    let kb = if let Some(kb_path) = kb_file {
        println!("{} Loading knowledge base from: {}", "📚".blue(), kb_path);
        Some(load_knowledge_base(kb_path)?)
    } else {
        None
    };

    // Convert AIModel to OpenAIModel for TestSuiteGenerator (backward compatibility)
    let openai_model = ai_model_to_openai_model(model);

    // Detect file type by reading the content
    let content = std::fs::read_to_string(spec_file)?;
    
    if is_postman_collection(&content) {
        println!("{} Detected Postman collection", "📋".cyan());
        let collection = load_postman_collection(spec_file)?;
        
        let generator = TestSuiteGenerator::with_model(openai_model)?;
        let test_results = generator.generate_postman_test_suite_with_kb(&collection, kb.as_ref()).await?;
        
        // Save results to file
        let output_path = output_file.unwrap_or("postman_test_results.json");
        let results_json = serde_json::to_string_pretty(&test_results)?;
        std::fs::write(output_path, results_json)?;
        println!("{} Results exported to: {}", "💾".green(), output_path);
    } else {
        println!("{} Detected OpenAPI specification", "📄".cyan());
        let spec = load_openapi_spec(spec_file)?;
        
        let generator = TestSuiteGenerator::with_model(openai_model)?;
        let test_results = generator.generate_full_test_suite_with_kb(&spec, kb.as_ref()).await?;
        
        // Save results to file
        let output_path = output_file.unwrap_or("openapi_test_results.json");
        let results_json = serde_json::to_string_pretty(&test_results)?;
        std::fs::write(output_path, results_json)?;
        println!("{} Results exported to: {}", "💾".green(), output_path);
    }
    
    Ok(())
}

async fn generate_test_suite_only(
    spec_file: &str, 
    model: &crate::ai::AIModel, 
    output_file: Option<&str>, 
    kb_file: Option<&str>
) -> Result<()> {
    println!("{}", "🏭 Test Suite Generation Mode (No Execution)".bright_yellow().bold());
    println!("{} Using model: {} ({})", "🤖".yellow(), 
             model.as_str().cyan(), 
             model.provider().as_str().bright_blue());
    
    // Load knowledge base if provided
    let kb = if let Some(kb_path) = kb_file {
        println!("{} Loading knowledge base from: {}", "📚".blue(), kb_path);
        Some(load_knowledge_base(kb_path)?)
    } else {
        None
    };
    
    // Convert AIModel to OpenAIModel for TestSuiteGenerator
    let openai_model = ai_model_to_openai_model(model);
    
    // Detect file type by reading the content
    let content = std::fs::read_to_string(spec_file)?;
    
    if is_postman_collection(&content) {
        return Err(anyhow::anyhow!("Postman collections not supported in generate-only mode yet"));
    }
    
    println!("{} Detected OpenAPI specification", "📄".cyan());
    let spec = load_openapi_spec(spec_file)?;
    
    let generator = TestSuiteGenerator::with_model(openai_model)?;
    let test_suite = generator.generate_test_suite_definition(&spec, kb.as_ref()).await?;
    
    // Export test suite definition
    let output_path = output_file.unwrap_or("test_suite_definition.json");
    println!("{} Exporting test suite to: {}", "💾".green(), output_path);
    
    let test_suite_json = serde_json::to_string_pretty(&test_suite)?;
    std::fs::write(output_path, test_suite_json)?;
    
    println!("{} Test suite generation completed!", "✅".green());
    
    Ok(())
}

async fn run_interactive_mode(spec_file: &str, model: &crate::ai::AIModel, _ai_config: &AIConfig) -> Result<()> {
    println!("{}", "🎮 Interactive Mode".bright_magenta().bold());
    println!("{} Using model: {} ({})", "🤖".yellow(), 
             model.as_str().cyan(), 
             model.provider().as_str().bright_blue());
    
    let content = std::fs::read_to_string(spec_file)?;
    
    if is_postman_collection(&content) {
        println!("{} Detected Postman collection", "📋".cyan());
        println!("{} Interactive mode for Postman collections coming soon!", "🚧".yellow());
        println!("{} For now, running full test suite generation", "ℹ️".blue());
        
        let collection = load_postman_collection(spec_file)?;
        let openai_model = ai_model_to_openai_model(model);
        let generator = TestSuiteGenerator::with_model(openai_model)?;
        let _test_results = generator.generate_postman_test_suite_with_kb(&collection, None).await?;
        println!("{} All tests completed!", "✅".green());
    } else {
        println!("{} Detected OpenAPI specification", "📄".cyan());
        println!("{} Interactive mode for OpenAPI specs coming soon!", "🚧".yellow());
        println!("{} For now, running full test suite generation", "ℹ️".blue());
        
        let spec = load_openapi_spec(spec_file)?;
        let openai_model = ai_model_to_openai_model(model);
        let generator = TestSuiteGenerator::with_model(openai_model)?;
        let _test_results = generator.generate_full_test_suite_with_kb(&spec, None).await?;
        println!("{} All tests completed!", "✅".green());
    }
    
    println!("{} Interactive session ended", "👋".blue());
    Ok(())
}

fn is_postman_collection(content: &str) -> bool {
    content.contains("\"info\"") && 
    content.contains("\"item\"") && 
    (content.contains("\"postman_id\"") || content.contains("\"schema\""))
}
