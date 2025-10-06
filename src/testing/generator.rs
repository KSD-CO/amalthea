use crate::specs::openapi::{OpenAPISpec, EndpointInfo};
use crate::specs::postman::{PostmanCollection, PostmanEndpoint};
use crate::ai::{OpenAIClient, OpenAIModel};
use crate::utils::http::send_request_with_response;
use crate::testing::export::ExportFormat;
use crate::utils::knowledge_base::KnowledgeBase;
use anyhow::Result;
use colored::*;
use serde_json::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use csv::Writer;
use chrono;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub payload: Option<String>,
    pub expected_status: Option<u16>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub api_title: String,
    pub api_version: String,
    pub base_url: String,
    pub total_endpoints: usize,
    pub test_cases: Vec<TestCase>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuiteResult {
    pub api_title: String,
    pub api_version: String,
    pub total_endpoints: usize,
    pub total_test_cases: usize,
    pub test_cases: Vec<TestCaseResult>,
    pub summary: TestSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseResult {
    pub test_case: TestCase,
    pub status: u16,
    pub response_body: String,
    pub success: bool,
    pub error: Option<String>,
    pub response_time_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub success_rate: f64,
}

// CSV Export Structure
#[derive(Debug, Serialize)]
pub struct TestCaseCSVRecord {
    pub api_name: String,
    pub api_version: String,
    pub endpoint_method: String,
    pub endpoint_url: String,
    pub test_name: String,
    pub test_description: String,
    pub expected_status: String,
    pub actual_status: u16,
    pub result: String,
    pub success: String,
    pub response_time_ms: u128,
    pub error_message: String,
    pub request_headers: String,
    pub request_payload: String,
    pub response_preview: String,
}

pub struct TestSuiteGenerator {
    openai_client: OpenAIClient,
}

impl TestSuiteGenerator {
    pub fn new() -> Result<Self> {
        Self::with_model(OpenAIModel::default())
    }

    pub fn with_model(model: OpenAIModel) -> Result<Self> {
        let openai_client = OpenAIClient::with_model(model)?;
        Ok(Self { openai_client })
    }

    #[allow(dead_code)]
    pub async fn generate_full_test_suite(&self, spec: &OpenAPISpec) -> Result<TestSuiteResult> {
        self.generate_full_test_suite_with_kb(spec, None).await
    }

    // Generate test suite definition only (without running tests) - saves AI costs
    pub async fn generate_test_suite_definition(&self, spec: &OpenAPISpec, kb: Option<&KnowledgeBase>) -> Result<TestSuite> {
        println!("🚀 {}", "Generating test suite definition only (no test execution)...".bright_green().bold());
        
        let endpoints = spec.extract_endpoints();
        let total_endpoints = endpoints.len();
        
        println!("📋 Processing {} endpoints:", total_endpoints.to_string().yellow().bold());
        
        let mut all_test_cases = Vec::new();

        for (idx, endpoint) in endpoints.iter().enumerate() {
            println!(
                "\n📍 [{}/{}] {} {}", 
                (idx + 1).to_string().cyan(),
                total_endpoints.to_string().cyan(),
                endpoint.method.yellow().bold(),
                endpoint.path.blue()
            );

            let test_cases = self.generate_test_cases_for_endpoint_with_kb(endpoint, kb).await?;
            println!("   ✅ Generated {} test cases", test_cases.len().to_string().green());

            all_test_cases.extend(test_cases);
        }

        let test_suite = TestSuite {
            api_title: spec.info.title.clone(),
            api_version: spec.info.version.clone(),
            base_url: spec.servers.as_ref()
                .and_then(|servers| servers.first())
                .map(|s| s.url.clone())
                .unwrap_or_else(|| "http://localhost".to_string()),
            total_endpoints,
            test_cases: all_test_cases,
            generated_at: chrono::Utc::now().to_rfc3339(),
        };

        println!("\n{}", "🎯 TEST SUITE GENERATION COMPLETE".bright_green().bold());
        println!("📖 API: {}", test_suite.api_title.cyan());
        println!("🧪 Total Test Cases: {}", test_suite.test_cases.len().to_string().yellow());
        
        Ok(test_suite)
    }

    // Run tests from pre-generated test suite file (no AI calls needed)
    pub async fn run_test_suite_from_file(&self, suite_file: &str) -> Result<TestSuiteResult> {
        println!("🔄 {}", "Running tests from pre-generated test suite...".bright_cyan().bold());
        
        // Load test suite from file
        let suite_content = fs::read_to_string(suite_file)?;
        let test_suite: TestSuite = serde_json::from_str(&suite_content)?;
        
        println!("📖 Loaded test suite: {}", test_suite.api_title.cyan());
        println!("🧪 Total test cases: {}", test_suite.test_cases.len().to_string().yellow());
        println!("📅 Generated at: {}", test_suite.generated_at.dimmed());
        
        let mut test_results = Vec::new();

        // Execute all test cases
        for (idx, test_case) in test_suite.test_cases.iter().enumerate() {
            print!("🧪 Running test {}/{}: {} ... ", 
                (idx + 1).to_string().cyan(),
                test_suite.test_cases.len().to_string().cyan(),
                test_case.name.bright_white()
            );

            let start_time = std::time::Instant::now();
            let result = self.execute_test_case(test_case).await;
            let response_time = start_time.elapsed().as_millis();

            match result {
                Ok((status, response_body)) => {
                    let success = status == test_case.expected_status.unwrap_or(200);
                    if success {
                        println!("{}", "PASS".green().bold());
                    } else {
                        println!("{} (expected {}, got {})", 
                            "FAIL".red().bold(), 
                            test_case.expected_status.unwrap_or(200).to_string().yellow(),
                            status.to_string().yellow()
                        );
                    }
                    
                    test_results.push(TestCaseResult {
                        test_case: test_case.clone(),
                        status,
                        response_body,
                        success,
                        error: None,
                        response_time_ms: response_time,
                    });
                }
                Err(e) => {
                    println!("{}: {}", "ERROR".red().bold(), e.to_string().red());
                    test_results.push(TestCaseResult {
                        test_case: test_case.clone(),
                        status: 0,
                        response_body: "".to_string(),
                        success: false,
                        error: Some(e.to_string()),
                        response_time_ms: response_time,
                    });
                }
            }
        }

        // Calculate summary
        let passed = test_results.iter().filter(|r| r.success).count();
        let failed = test_results.len() - passed;
        let success_rate = if test_results.is_empty() { 0.0 } else { (passed as f32 / test_results.len() as f32) * 100.0 };

        let summary = TestSummary {
            total: test_results.len(),
            passed,
            failed,
            success_rate: success_rate.into(),
        };

        let result = TestSuiteResult {
            api_title: test_suite.api_title.clone(),
            api_version: test_suite.api_version.clone(),
            total_endpoints: test_suite.total_endpoints,
            total_test_cases: test_results.len(),
            test_cases: test_results,
            summary,
        };

        self.print_final_summary(&result);
        
        Ok(result)
    }

    pub async fn generate_full_test_suite_with_kb(&self, spec: &OpenAPISpec, kb: Option<&KnowledgeBase>) -> Result<TestSuiteResult> {
        println!("🚀 {}", "Starting comprehensive test suite generation...".bright_green().bold());
        
        let endpoints = spec.extract_endpoints();
        let total_endpoints = endpoints.len();
        
        println!("📋 Processing {} endpoints:", total_endpoints.to_string().yellow().bold());
        
        let mut all_test_cases = Vec::new();
        let mut test_results = Vec::new();

        for (idx, endpoint) in endpoints.iter().enumerate() {
            println!(
                "\n📍 [{}/{}] {} {}", 
                (idx + 1).to_string().cyan(),
                total_endpoints.to_string().cyan(),
                endpoint.method.yellow().bold(),
                endpoint.path.blue()
            );

            let test_cases = self.generate_test_cases_for_endpoint_with_kb(endpoint, kb).await?;
            println!("   ✅ Generated {} test cases", test_cases.len().to_string().green());

            // Execute test cases
            for (test_idx, test_case) in test_cases.iter().enumerate() {
                print!("   🧪 Running test {}/{}: {} ... ", 
                    (test_idx + 1).to_string().cyan(),
                    test_cases.len().to_string().cyan(),
                    test_case.name.bright_white()
                );

                let start_time = std::time::Instant::now();
                let result = self.execute_test_case(test_case).await;
                let response_time = start_time.elapsed().as_millis();

                match result {
                    Ok((status, response_body)) => {
                        let success = status == test_case.expected_status.unwrap_or(200);
                        if success {
                            println!("{}", "PASS".green().bold());
                        } else {
                            println!("{} (expected {}, got {})", 
                                "FAIL".red().bold(), 
                                test_case.expected_status.unwrap_or(200).to_string().yellow(),
                                status.to_string().yellow()
                            );
                        }
                        
                        test_results.push(TestCaseResult {
                            test_case: test_case.clone(),
                            status,
                            response_body,
                            success,
                            error: None,
                            response_time_ms: response_time,
                        });
                    }
                    Err(e) => {
                        println!("{} ({})", "ERROR".red().bold(), e.to_string().bright_red());
                        test_results.push(TestCaseResult {
                            test_case: test_case.clone(),
                            status: 0,
                            response_body: String::new(),
                            success: false,
                            error: Some(e.to_string()),
                            response_time_ms: response_time,
                        });
                    }
                }
            }

            all_test_cases.extend(test_cases);
        }

        let summary = self.calculate_summary(&test_results);
        
        let result = TestSuiteResult {
            api_title: spec.info.title.clone(),
            api_version: spec.info.version.clone(),
            total_endpoints,
            total_test_cases: all_test_cases.len(),
            test_cases: test_results,
            summary,
        };

        self.print_final_summary(&result);
        
        Ok(result)
    }

    #[allow(dead_code)]
    pub async fn generate_postman_test_suite(&self, collection: &PostmanCollection) -> Result<TestSuiteResult> {
        self.generate_postman_test_suite_with_kb(collection, None).await
    }

    pub async fn generate_postman_test_suite_with_kb(&self, collection: &PostmanCollection, kb: Option<&KnowledgeBase>) -> Result<TestSuiteResult> {
        println!("🚀 {}", "Starting Postman collection test suite generation...".bright_magenta().bold());
        
        let endpoints = collection.extract_endpoints();
        let total_endpoints = endpoints.len();
        
        println!("📋 Processing {} requests from Postman collection:", total_endpoints.to_string().yellow().bold());
        println!("📦 Collection: {}", collection.info.name.bright_blue().bold());
        
        let mut all_test_cases = Vec::new();
        let mut test_results = Vec::new();

        for (idx, endpoint) in endpoints.iter().enumerate() {
            println!(
                "\n📍 [{}/{}] {} {}", 
                (idx + 1).to_string().cyan(),
                total_endpoints.to_string().cyan(),
                endpoint.method.yellow().bold(),
                endpoint.url.blue()
            );

            let test_cases = self.generate_test_cases_for_postman_endpoint_with_kb(endpoint, kb).await?;
            println!("   ✅ Generated {} test cases", test_cases.len().to_string().green());

            // Execute test cases
            for (test_idx, test_case) in test_cases.iter().enumerate() {
                print!("   🧪 Running test {}/{}: {} ... ", 
                    (test_idx + 1).to_string().cyan(),
                    test_cases.len().to_string().cyan(),
                    test_case.name.bright_white()
                );

                let start_time = std::time::Instant::now();
                let result = self.execute_test_case(test_case).await;
                let response_time = start_time.elapsed().as_millis();

                match result {
                    Ok((status, response_body)) => {
                        let success = status == test_case.expected_status.unwrap_or(200);
                        if success {
                            println!("{}", "PASS".green().bold());
                        } else {
                            println!("{} (expected {}, got {})", 
                                "FAIL".red().bold(), 
                                test_case.expected_status.unwrap_or(200).to_string().yellow(),
                                status.to_string().yellow()
                            );
                        }

                        test_results.push(TestCaseResult {
                            test_case: test_case.clone(),
                            status,
                            response_body,
                            success,
                            error: None,
                            response_time_ms: response_time,
                        });
                    }
                    Err(e) => {
                        println!("{} ({})", "ERROR".red().bold(), e);
                        test_results.push(TestCaseResult {
                            test_case: test_case.clone(),
                            status: 0,
                            response_body: String::new(),
                            success: false,
                            error: Some(e.to_string()),
                            response_time_ms: response_time,
                        });
                    }
                }
            }

            all_test_cases.extend(test_cases);
        }

        let summary = self.calculate_summary(&test_results);
        
        let result = TestSuiteResult {
            api_title: collection.info.name.clone(),
            api_version: "Postman Collection".to_string(),
            total_endpoints,
            total_test_cases: all_test_cases.len(),
            test_cases: test_results,
            summary,
        };

        self.print_final_summary(&result);
        
        Ok(result)
    }

    #[allow(dead_code)]
    async fn generate_test_cases_for_endpoint(&self, endpoint: &EndpointInfo) -> Result<Vec<TestCase>> {
        self.generate_test_cases_for_endpoint_with_kb(endpoint, None).await
    }

    async fn generate_test_cases_for_endpoint_with_kb(&self, endpoint: &EndpointInfo, kb: Option<&KnowledgeBase>) -> Result<Vec<TestCase>> {
        let context = self.build_endpoint_context_with_kb(endpoint, kb);
        let prompt = self.build_test_generation_prompt(endpoint, &context);

        // Try to get AI response
        match self.openai_client.generate_tests(&prompt).await {
            Ok(ai_response) => {
                match self.parse_ai_test_cases(&ai_response, endpoint) {
                    Ok(test_cases) => Ok(test_cases),
                    Err(e) => {
                        println!("   ⚠️  AI parsing failed: {}, generating fallback test cases", e.to_string().yellow());
                        Ok(self.generate_fallback_test_cases(endpoint, kb))
                    }
                }
            },
            Err(e) => {
                println!("   ⚠️  AI generation failed: {}, generating fallback test cases", e.to_string().yellow());
                Ok(self.generate_fallback_test_cases(endpoint, kb))
            }
        }
    }

    #[allow(dead_code)]
    async fn generate_test_cases_for_postman_endpoint(&self, endpoint: &PostmanEndpoint) -> Result<Vec<TestCase>> {
        self.generate_test_cases_for_postman_endpoint_with_kb(endpoint, None).await
    }

    async fn generate_test_cases_for_postman_endpoint_with_kb(&self, endpoint: &PostmanEndpoint, kb: Option<&KnowledgeBase>) -> Result<Vec<TestCase>> {
        let context = self.build_postman_endpoint_context_with_kb(endpoint, kb);
        let prompt = self.build_postman_test_generation_prompt(endpoint, &context);

        // Try to get AI response
        match self.openai_client.generate_tests(&prompt).await {
            Ok(ai_response) => {
                match self.parse_ai_postman_test_cases(&ai_response, endpoint) {
                    Ok(test_cases) => Ok(test_cases),
                    Err(e) => {
                        println!("   ⚠️  AI parsing failed: {}, generating fallback test cases", e.to_string().yellow());
                        Ok(self.generate_fallback_postman_test_cases(endpoint))
                    }
                }
            },
            Err(e) => {
                println!("   ⚠️  AI generation failed: {}, generating fallback test cases", e.to_string().yellow());
                Ok(self.generate_fallback_postman_test_cases(endpoint))
            }
        }
    }

    #[allow(dead_code)]
    fn build_endpoint_context(&self, endpoint: &EndpointInfo) -> String {
        self.build_endpoint_context_with_kb(endpoint, None)
    }

    fn build_endpoint_context_with_kb(&self, endpoint: &EndpointInfo, kb: Option<&KnowledgeBase>) -> String {
        let mut context = String::new();
        
        context.push_str(&format!("Endpoint: {} {}\n", endpoint.method, endpoint.path));
        
        if let Some(summary) = &endpoint.summary {
            context.push_str(&format!("Summary: {}\n", summary));
        }
        
        if let Some(description) = &endpoint.description {
            context.push_str(&format!("Description: {}\n", description));
        }

        // Parameters
        if !endpoint.parameters.is_empty() {
            context.push_str("\nParameters:\n");
            for param in &endpoint.parameters {
                let required = if param.required.unwrap_or(false) { " (required)" } else { " (optional)" };
                context.push_str(&format!("- {} ({}){}: {}\n", 
                    param.name, 
                    param.location,
                    required,
                    param.description.as_ref().unwrap_or(&"No description".to_string())
                ));
            }
        }

        // Request body
        if let Some(body) = &endpoint.request_body {
            context.push_str("\nRequest Body:\n");
            if let Some(desc) = &body.description {
                context.push_str(&format!("Description: {}\n", desc));
            }
            context.push_str("Content-Type: application/json\n");
            
            // Add schema information if available
            if let Some(content) = body.content.get("application/json") {
                if let Some(schema) = &content.schema {
                    context.push_str("Schema:\n");
                    
                    // Handle schema reference
                    if let Some(ref_path) = &schema.reference {
                        if ref_path == "#/components/schemas/PublishOrderEventUseCaseRequest" {
                            // Special handling for E-Invoice API
                            context.push_str("Required fields: OrderNumber, OrderStatus, PaymentStatus, PaymentStatusDate, OrderStatusAction, PaymentMethod, OrderStatusDate, PaymentCheckoutId, PaymentType, BuyerId, WarehouseCode, DeliveryStatus, DeliveryStatusName, TrackingNumber, DeliveryStatusDate, ExpectedDeliveryDate\n");
                            context.push_str("Properties:\n");
                            context.push_str("  - OrderNumber: string (REQUIRED)\n");
                            context.push_str("  - OrderStatus: integer (REQUIRED)\n");
                            context.push_str("  - PaymentStatus: integer (REQUIRED)\n");
                            context.push_str("  - PaymentStatusDate: string (date-time) (REQUIRED)\n");
                            context.push_str("  - OrderStatusAction: integer (REQUIRED)\n");
                            context.push_str("  - PaymentMethod: integer (REQUIRED)\n");
                            context.push_str("  - OrderStatusDate: string (date-time) (REQUIRED)\n");
                            context.push_str("  - PaymentCheckoutId: string (REQUIRED)\n");
                            context.push_str("  - PaymentType: integer (REQUIRED)\n");
                            context.push_str("  - BuyerId: string (REQUIRED)\n");
                            context.push_str("  - WarehouseCode: string (REQUIRED)\n");
                            context.push_str("  - DeliveryStatus: string (REQUIRED)\n");
                            context.push_str("  - DeliveryStatusName: string (REQUIRED)\n");
                            context.push_str("  - TrackingNumber: string (REQUIRED)\n");
                            context.push_str("  - DeliveryStatusDate: string (date-time) (REQUIRED)\n");
                            context.push_str("  - ExpectedDeliveryDate: string (date-time) (REQUIRED)\n");
                        }
                    } else {
                        // Normal schema processing
                        if let Some(required_fields) = &schema.required {
                            context.push_str(&format!("Required fields: {}\n", required_fields.join(", ")));
                        }
                        if let Some(properties) = &schema.properties {
                            context.push_str("Properties:\n");
                            for (field_name, field_schema) in properties {
                                let unknown_type = "unknown".to_string();
                                let field_type = field_schema.schema_type.as_ref().unwrap_or(&unknown_type);
                                let is_required = schema.required.as_ref()
                                    .map(|req| req.contains(field_name))
                                    .unwrap_or(false);
                                let required_text = if is_required { " (REQUIRED)" } else { "" };
                                context.push_str(&format!("  - {}: {}{}\n", field_name, field_type, required_text));
                            }
                        }
                    }
                }
            }
        }

        // Responses
        if !endpoint.responses.is_empty() {
            context.push_str("\nResponses:\n");
            for (status, response) in &endpoint.responses {
                context.push_str(&format!("- {}: {}\n", status, response.description));
            }
        }

        // Add knowledge base context if available
        if let Some(knowledge_base) = kb {
            context.push_str(&knowledge_base.build_context_for_ai(&endpoint.path));
        }

        context
    }

    fn build_test_generation_prompt(&self, _endpoint: &EndpointInfo, context: &str) -> String {
        format!(
            r#"You are a professional API testing expert. Generate comprehensive test cases for this API endpoint.

ENDPOINT INFORMATION:
{}

IMPORTANT INSTRUCTIONS:
1. **CAREFULLY READ THE SCHEMA**: If there are Properties listed with REQUIRED fields, you MUST use those exact field names in your request body
2. **USE EXACT FIELD NAMES**: Do not guess or invent field names - use only the field names specified in the Properties section
3. **RESPECT REQUIRED FIELDS**: All fields marked as (REQUIRED) must be included in valid test cases
4. **USE PROPER DATA TYPES**: Follow the data types specified (string, integer, etc.)

REQUIREMENTS:
1. Generate 4-6 diverse test cases covering different scenarios  
2. Include positive (happy path) and negative test cases
3. Test edge cases, boundary conditions, and error scenarios
4. For parameters: test required/optional, valid/invalid values, boundary values
5. For request bodies: use EXACT field names from the schema, test missing required fields
6. Consider real-world usage patterns

OUTPUT FORMAT (JSON only, no other text):
{{
  "test_cases": [
    {{
      "name": "Clear descriptive test name",
      "description": "What this test validates", 
      "scenario": "positive|negative|edge_case|boundary",
      "parameters": {{"param_name": "value"}},
      "request_body": {{"field_name": "value"}} or null,
      "expected_status": 200,
      "notes": "Additional testing notes"
    }}
  ]
}}

Focus on realistic, practical test cases using the EXACT schema field names provided."#,
            context
        )
    }

    fn parse_ai_test_cases(&self, ai_response: &str, endpoint: &EndpointInfo) -> Result<Vec<TestCase>> {
        let mut test_cases = Vec::new();
        
        // Try to extract JSON from AI response
        let json_str = if let Some(start) = ai_response.find('{') {
            if let Some(end) = ai_response.rfind('}') {
                &ai_response[start..=end]
            } else {
                ai_response
            }
        } else {
            ai_response
        };

        // Try to fix common JSON issues
        let cleaned_json = json_str
            .replace("```json", "")
            .replace("```", "")
            .trim()
            .to_string();

        let parsed: Value = serde_json::from_str(&cleaned_json)
            .map_err(|e| {
                println!("AI Response that failed to parse: {}", ai_response);
                anyhow::anyhow!("Failed to parse AI response as JSON: {}", e)
            })?;

        if let Some(cases) = parsed["test_cases"].as_array() {
            for case in cases {
                let name = case["name"].as_str().unwrap_or("Unnamed Test").to_string();
                let description = case["description"].as_str().unwrap_or("No description").to_string();
                
                // Build URL with parameters
                let mut url = format!("{}{}", endpoint.base_url, endpoint.path);
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());

                // Handle parameters
                if let Some(params) = case["parameters"].as_object() {
                    let mut query_params = Vec::new();
                    for (key, value) in params {
                        // For path parameters, replace in URL
                        if endpoint.path.contains(&format!("{{{}}}", key)) {
                            url = url.replace(&format!("{{{}}}", key), &value.to_string().trim_matches('"'));
                        } else {
                            // For query parameters
                            query_params.push(format!("{}={}", key, value.to_string().trim_matches('"')));
                        }
                    }
                    if !query_params.is_empty() {
                        url = format!("{}?{}", url, query_params.join("&"));
                    }
                }

                // Handle request body
                let payload = if let Some(body) = case.get("request_body") {
                    if body.is_null() {
                        None
                    } else {
                        Some(body.to_string())
                    }
                } else {
                    None
                };

                let expected_status = case["expected_status"].as_u64().map(|s| s as u16);

                test_cases.push(TestCase {
                    name,
                    method: endpoint.method.clone(),
                    url,
                    headers,
                    payload,
                    expected_status,
                    description,
                });
            }
        }

        Ok(test_cases)
    }

    async fn execute_test_case(&self, test_case: &TestCase) -> Result<(u16, String)> {
        send_request_with_response(
            &test_case.method,
            &test_case.url,
            &test_case.headers,
            test_case.payload.as_deref(),
        ).await
    }

    fn calculate_summary(&self, results: &[TestCaseResult]) -> TestSummary {
        let total = results.len();
        let passed = results.iter().filter(|r| r.success).count();
        let failed = total - passed;
        let success_rate = if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 };

        TestSummary {
            total,
            passed,
            failed,
            success_rate,
        }
    }

    fn print_final_summary(&self, result: &TestSuiteResult) {
        println!("\n{}", "=".repeat(80).bright_blue());
        println!("{}", "🎯 TEST SUITE SUMMARY".bright_blue().bold());
        println!("{}", "=".repeat(80).bright_blue());
        
        println!("{} {} v{}", "📖 API:".bright_white(), result.api_title.bright_blue().bold(), result.api_version.green());
        println!("{} {}", "🔗 Endpoints:".bright_white(), result.total_endpoints.to_string().yellow().bold());
        println!("{} {}", "🧪 Test Cases:".bright_white(), result.total_test_cases.to_string().yellow().bold());
        
        println!("\n{}", "📊 Results:".bright_white().bold());
        println!("   {} {} tests", "✅ Passed:".green(), result.summary.passed.to_string().green().bold());
        println!("   {} {} tests", "❌ Failed:".red(), result.summary.failed.to_string().red().bold());
        println!("   {} {:.1}%", "📈 Success Rate:".bright_white(), result.summary.success_rate.to_string().bright_green().bold());
    }

    pub fn export_results(&self, result: &TestSuiteResult, output_path: &str, format: &ExportFormat) -> Result<()> {
        match format {
            ExportFormat::Json => {
                let json_output = serde_json::to_string_pretty(result)?;
                fs::write(output_path, json_output)?;
                println!("\n💾 Test results exported to JSON: {}", output_path.cyan());
            },
            ExportFormat::Csv => {
                let csv_path = if output_path.ends_with(".json") {
                    output_path.replace(".json", ".csv")
                } else {
                    format!("{}.csv", output_path)
                };
                self.export_csv(result, &csv_path)?;
                println!("\n📊 Test results exported to CSV: {}", csv_path.cyan());
            },
            ExportFormat::Both => {
                // Export JSON
                let json_path = if output_path.ends_with(".json") {
                    output_path.to_string()
                } else {
                    format!("{}.json", output_path)
                };
                let json_output = serde_json::to_string_pretty(result)?;
                fs::write(&json_path, json_output)?;
                println!("\n💾 Test results exported to JSON: {}", json_path.cyan());

                // Export CSV 
                let csv_path = if output_path.ends_with(".json") {
                    output_path.replace(".json", ".csv")
                } else {
                    format!("{}.csv", output_path)
                };
                self.export_csv(result, &csv_path)?;
                println!("📊 Test results exported to CSV: {}", csv_path.cyan());
            }
        }
        
        Ok(())
    }

    // Export test suite definition (without results)
    pub fn export_test_suite(&self, suite: &TestSuite, output_path: &str) -> Result<()> {
        let json_output = serde_json::to_string_pretty(suite)?;
        fs::write(output_path, json_output)?;
        println!("\n💾 Test suite definition exported to: {}", output_path.cyan());
        println!("💡 Use --run-tests {} to execute these tests later", output_path.yellow());
        
        Ok(())
    }

    pub fn export_csv(&self, result: &TestSuiteResult, csv_path: &str) -> Result<()> {
        let mut writer = Writer::from_path(csv_path)?;
        
        for test_result in &result.test_cases {
            let record = TestCaseCSVRecord {
                api_name: result.api_title.clone(),
                api_version: result.api_version.clone(),
                endpoint_method: test_result.test_case.method.clone(),
                endpoint_url: test_result.test_case.url.clone(),
                test_name: test_result.test_case.name.clone(),
                test_description: test_result.test_case.description.clone(),
                expected_status: test_result.test_case.expected_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Any".to_string()),
                actual_status: test_result.status,
                result: if test_result.success { "PASS".to_string() } else { "FAIL".to_string() },
                success: test_result.success.to_string(),
                response_time_ms: test_result.response_time_ms,
                error_message: test_result.error.clone().unwrap_or_else(|| "".to_string()),
                request_headers: serde_json::to_string(&test_result.test_case.headers)
                    .unwrap_or_else(|_| "{}".to_string())
                    .replace('"', "'"),
                request_payload: test_result.test_case.payload.clone()
                    .unwrap_or_else(|| "".to_string())
                    .replace('\n', " ")
                    .replace('"', "'"),
                response_preview: if test_result.response_body.len() > 200 {
                    test_result.response_body[..200].replace('\n', " ").replace('"', "'")
                } else {
                    test_result.response_body.replace('\n', " ").replace('"', "'")
                },
            };
            writer.serialize(&record)?;
        }
        
        writer.flush()?;
        Ok(())
    }

    fn generate_fallback_test_cases(&self, endpoint: &EndpointInfo, _kb: Option<&KnowledgeBase>) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        // Basic successful test case
        let mut url = format!("{}{}", endpoint.base_url, endpoint.path);
        
        // Replace path parameters with sample values
        url = url.replace("{id}", "1");
        
        test_cases.push(TestCase {
            name: format!("Basic {} test", endpoint.method),
            method: endpoint.method.clone(),
            url: url.clone(),
            headers: headers.clone(),
            payload: if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                Some(r#"{"name": "Test User", "email": "test@example.com"}"#.to_string())
            } else {
                None
            },
            expected_status: Some(200),
            description: format!("Basic test for {} {}", endpoint.method, endpoint.path),
        });

        // Edge case - invalid data
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            test_cases.push(TestCase {
                name: "Invalid data test".to_string(),
                method: endpoint.method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                payload: Some(r#"{"invalid": "data"}"#.to_string()),
                expected_status: Some(400),
                description: "Test with invalid request data".to_string(),
            });
        }

        // Not found test for resources with ID
        if endpoint.path.contains("{id}") {
            let not_found_url = url.replace("1", "99999");
            test_cases.push(TestCase {
                name: "Resource not found test".to_string(),
                method: endpoint.method.clone(),
                url: not_found_url,
                headers: headers.clone(),
                payload: None,
                expected_status: Some(404),
                description: "Test with non-existent resource ID".to_string(),
            });
        }

        test_cases
    }

    // Postman-specific methods
    #[allow(dead_code)]
    fn build_postman_endpoint_context(&self, endpoint: &PostmanEndpoint) -> String {
        self.build_postman_endpoint_context_with_kb(endpoint, None)
    }

    fn build_postman_endpoint_context_with_kb(&self, endpoint: &PostmanEndpoint, kb: Option<&KnowledgeBase>) -> String {
        let mut context = String::new();
        
        context.push_str(&format!("Request: {} {}\n", endpoint.method, endpoint.url));
        context.push_str(&format!("Name: {}\n", endpoint.name));
        
        if let Some(description) = &endpoint.description {
            context.push_str(&format!("Description: {}\n", description));
        }

        // Headers
        if !endpoint.headers.is_empty() {
            context.push_str("\nHeaders:\n");
            for (key, value) in &endpoint.headers {
                context.push_str(&format!("- {}: {}\n", key, value));
            }
        }

        // Body
        if let Some(body) = &endpoint.body {
            context.push_str("\nRequest Body:\n");
            context.push_str(body);
            context.push('\n');
        }

        // Add knowledge base context if available
        if let Some(knowledge_base) = kb {
            context.push_str(&knowledge_base.build_context_for_ai(&endpoint.url));
        }

        context
    }

    fn build_postman_test_generation_prompt(&self, _endpoint: &PostmanEndpoint, context: &str) -> String {
        format!(
            r#"Based on the following Postman request information, generate 6 comprehensive test cases for API testing:

{}

Generate the following types of test cases:
1. Happy Path: Valid request with expected success
2. Validation Test: Test required fields and data validation
3. Edge Case: Test boundary conditions and edge cases
4. Error Handling: Test with invalid/missing data
5. Authentication: Test authentication scenarios if applicable
6. Performance: Test with large payloads or specific conditions

Format each test case as JSON with these fields:
- "name": descriptive test case name
- "description": what this test validates
- "method": HTTP method (GET, POST, PUT, DELETE, etc.)
- "url": the full URL for the request
- "headers": object with header key-value pairs
- "payload": request body as JSON string (null if not applicable)
- "expected_status": expected HTTP status code

Return the response as a JSON array of test case objects."#,
            context
        )
    }

    fn parse_ai_postman_test_cases(&self, ai_response: &str, endpoint: &PostmanEndpoint) -> Result<Vec<TestCase>> {
        // Try to parse AI response as JSON array
        let parsed_value: Value = serde_json::from_str(ai_response)?;
        
        if let Some(tests_array) = parsed_value.as_array() {
            let mut test_cases = Vec::new();
            
            for test_value in tests_array {
                if let Ok(mut test_case) = serde_json::from_value::<TestCase>(test_value.clone()) {
                    // Ensure URL is properly formatted
                    if test_case.url.is_empty() {
                        test_case.url = endpoint.url.clone();
                    }
                    
                    // Ensure method matches
                    if test_case.method.is_empty() {
                        test_case.method = endpoint.method.clone();
                    }
                    
                    // Copy headers from endpoint if not specified
                    if test_case.headers.is_empty() {
                        test_case.headers = endpoint.headers.clone();
                    }
                    
                    test_cases.push(test_case);
                }
            }
            
            if test_cases.is_empty() {
                return Err(anyhow::anyhow!("No valid test cases found in AI response"));
            }
            
            Ok(test_cases)
        } else {
            Err(anyhow::anyhow!("AI response is not a JSON array"))
        }
    }

    fn generate_fallback_postman_test_cases(&self, endpoint: &PostmanEndpoint) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Basic success test
        test_cases.push(TestCase {
            name: format!("{} - Success Test", endpoint.name),
            method: endpoint.method.clone(),
            url: endpoint.url.clone(),
            headers: endpoint.headers.clone(),
            payload: endpoint.body.clone(),
            expected_status: Some(200),
            description: format!("Basic success test for {}", endpoint.name),
        });

        // Modified request test for POST/PUT/PATCH
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            // Try to modify the original payload or create a simple one
            let modified_payload = if let Some(original_body) = &endpoint.body {
                // Try to parse and modify existing JSON
                if let Ok(mut json_value) = serde_json::from_str::<Value>(original_body) {
                    if let Some(obj) = json_value.as_object_mut() {
                        obj.insert("test_field".to_string(), Value::String("test_value".to_string()));
                    }
                    serde_json::to_string(&json_value).unwrap_or_else(|_| original_body.to_string())
                } else {
                    original_body.to_string()
                }
            } else {
                r#"{"test": "data", "name": "Test User"}"#.to_string()
            };

            test_cases.push(TestCase {
                name: format!("{} - Modified Data Test", endpoint.name),
                method: endpoint.method.clone(),
                url: endpoint.url.clone(),
                headers: endpoint.headers.clone(),
                payload: Some(modified_payload),
                expected_status: Some(200),
                description: "Test with modified request data".to_string(),
            });

            // Invalid data test
            test_cases.push(TestCase {
                name: format!("{} - Invalid Data Test", endpoint.name),
                method: endpoint.method.clone(),
                url: endpoint.url.clone(),
                headers: endpoint.headers.clone(),
                payload: Some(r#"{"invalid": "format"}"#.to_string()),
                expected_status: Some(400),
                description: "Test with invalid request data format".to_string(),
            });
        }

        // Error test with modified URL (if it has parameters)
        if endpoint.url.contains("?") || endpoint.url.contains("/") {
            let error_url = if endpoint.url.contains("?") {
                format!("{}?invalid=param", endpoint.url.split('?').next().unwrap_or(&endpoint.url))
            } else {
                format!("{}/invalid", endpoint.url)
            };

            test_cases.push(TestCase {
                name: format!("{} - Error Test", endpoint.name),
                method: endpoint.method.clone(),
                url: error_url,
                headers: endpoint.headers.clone(),
                payload: endpoint.body.clone(),
                expected_status: Some(404),
                description: "Test error handling with invalid URL".to_string(),
            });
        }

        test_cases
    }
}
