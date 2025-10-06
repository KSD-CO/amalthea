use anyhow::Result;
use dialoguer::{Select, Input, Confirm, MultiSelect};
use colored::*;
use std::collections::HashMap;

pub struct ApiRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub payload: Option<String>,
    pub business_description: Option<String>,
}

impl ApiRequest {
    pub fn to_description(&self) -> String {
        let mut desc = format!("{} {}", self.method, self.url);
        
        if !self.headers.is_empty() {
            desc.push_str("\nHeaders: ");
            for (key, value) in &self.headers {
                desc.push_str(&format!("{}: {}, ", key, value));
            }
        }
        
        if let Some(payload) = &self.payload {
            desc.push_str(&format!("\nPayload: {}", payload));
        }
        
        desc
    }

    pub fn get_query_params(&self) -> Option<String> {
        if let Some(query_start) = self.url.find('?') {
            Some(self.url[(query_start + 1)..].to_string())
        } else {
            None
        }
    }

    pub fn get_base_url(&self) -> String {
        if let Some(query_start) = self.url.find('?') {
            self.url[..query_start].to_string()
        } else {
            self.url.clone()
        }
    }
}

pub fn get_user_input() -> Result<ApiRequest> {
    println!("{}", "=== API Test Configuration ===".cyan().bold());
    
    // Select HTTP method
    let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH"];
    let method_selection = Select::new()
        .with_prompt("Select HTTP method")
        .items(&methods)
        .default(1) // Default to POST
        .interact()?;
    let method = methods[method_selection].to_string();

    // Get URL
    let url: String = Input::new()
        .with_prompt("Enter API URL")
        .with_initial_text("https://")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.starts_with("http://") || input.starts_with("https://") {
                Ok(())
            } else {
                Err("URL must start with http:// or https://")
            }
        })
        .interact_text()?;

    // Ask for headers
    println!("\n{}", "=== Headers Configuration ===".cyan().bold());
    let mut headers = HashMap::new();
    println!("💡 Tip: Type 'y' for yes, 'n' for no, then press Enter");
    let add_headers = Confirm::new()
        .with_prompt("Do you want to add custom headers?")
        .default(false)
        .show_default(true)
        .interact()?;

    if add_headers {
        // Common headers selection
        let common_headers = vec![
            "Content-Type: application/json",
            "Authorization: Bearer <token>",
            "Accept: application/json",
            "User-Agent: AI-Test-API/1.0",
            "Custom header",
        ];

        let header_selections = MultiSelect::new()
            .with_prompt("Select headers (use Space to select, Enter to confirm)")
            .items(&common_headers)
            .interact()?;

        for &index in &header_selections {
            if index == common_headers.len() - 1 {
                // Custom header
                loop {
                    let custom_header: String = Input::new()
                        .with_prompt("Enter custom header (format: Key: Value)")
                        .interact_text()?;
                    
                    if let Some((key, value)) = custom_header.split_once(':') {
                        headers.insert(key.trim().to_string(), value.trim().to_string());
                        break;
                    } else {
                        println!("{}", "Invalid format. Use 'Key: Value'".red());
                    }
                }
            } else {
                let header = common_headers[index];
                if let Some((key, value)) = header.split_once(':') {
                    let key = key.trim().to_string();
                    let mut value = value.trim().to_string();
                    
                    if value.contains("<token>") {
                        value = Input::new()
                            .with_prompt(&format!("Enter value for {}", key))
                            .interact_text()?;
                    }
                    
                    headers.insert(key, value);
                }
            }
        }
    } else {
        // Add default Content-Type for POST/PUT/PATCH
        if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }
    }

    // Get payload for methods that support body
    let payload = if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
        println!("\n{}", "=== Request Body Configuration ===".cyan().bold());
        println!("💡 Tip: Type 'y' for yes, 'n' for no, then press Enter");
        let add_payload = Confirm::new()
            .with_prompt("Do you want to add a request body/payload?")
            .default(true)
            .show_default(true)
            .interact()?;

        if add_payload {
            let payload_text: String = Input::new()
                .with_prompt("Enter JSON payload")
                .with_initial_text("{}")
                .validate_with(|input: &String| -> Result<(), &str> {
                    if input.trim().is_empty() {
                        return Ok(());
                    }
                    match serde_json::from_str::<serde_json::Value>(input) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("Invalid JSON format"),
                    }
                })
                .interact_text()?;
            
            if payload_text.trim().is_empty() {
                None
            } else {
                Some(payload_text)
            }
        } else {
            None
        }
    } else {
        None
    };

    // Get business description for better AI test generation
    println!("\n{}", "=== Business Context (Optional) ===".cyan().bold());
    println!("{}", "ℹ️  This helps AI understand your API better and generate more relevant test cases".bright_blue());
    println!("💡 Tip: Type 'y' for yes, 'n' for no, then press Enter");
    let add_business_desc = Confirm::new()
        .with_prompt("🤖 Would you like to provide business context to help AI generate more relevant test cases?")
        .default(false)
        .show_default(true)
        .interact()?;

    let business_description = if add_business_desc {
        println!("📝 Examples: 'E-commerce order management', 'User authentication system', 'Payment processing API'");
        let desc: String = Input::new()
            .with_prompt("Enter business context/description")
            .with_initial_text("")
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.trim().len() > 500 {
                    Err("Description should be less than 500 characters")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;
        
        if desc.trim().is_empty() {
            println!("ℹ️  No business context provided - AI will generate generic test cases");
            None
        } else {
            println!("✅ Business context added successfully!");
            Some(desc.trim().to_string())
        }
    } else {
        println!("ℹ️  Skipping business context - AI will generate generic test cases");
        None
    };

    Ok(ApiRequest {
        method,
        url,
        headers,
        payload,
        business_description,
    })
}

pub fn display_request_summary(request: &ApiRequest) {
    println!("\n{}", "=== Request Summary ===".green().bold());
    println!("{} {}", request.method.yellow().bold(), request.url.blue());
    
    if let Some(desc) = &request.business_description {
        println!("{} {}", "Business Context:".cyan(), desc.bright_white());
    }
    
    if !request.headers.is_empty() {
        println!("{}", "Headers:".cyan());
        for (key, value) in &request.headers {
            println!("  {}: {}", key.yellow(), value);
        }
    }
    
    if let Some(payload) = &request.payload {
        println!("{}", "Payload:".cyan());
        // Pretty print JSON if possible
        match serde_json::from_str::<serde_json::Value>(payload) {
            Ok(json) => println!("{}", serde_json::to_string_pretty(&json).unwrap_or_else(|_| payload.clone())),
            Err(_) => println!("{}", payload),
        }
    }
    println!();
}
