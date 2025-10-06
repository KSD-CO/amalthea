use serde_json::{Value, Map};
use super::data_generator::{DataGenerator, FuzzingConfig};
use crate::utils::knowledge_base::KnowledgeBase;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

#[derive(Debug, Clone)]
pub enum FuzzingStrategy {
    Random,
    Boundary,
    Malicious,
    TypeConfusion,
    Overflow,
    Injection,
    Mixed,
}

#[derive(Debug, Clone)]
pub struct PayloadFuzzer {
    data_generator: DataGenerator,
    strategy: FuzzingStrategy,
}

impl PayloadFuzzer {
    pub fn new(config: FuzzingConfig, strategy: FuzzingStrategy) -> Self {
        Self {
            data_generator: DataGenerator::new(config),
            strategy,
        }
    }

    pub fn fuzz_json_payload(&self, original: &Value, kb: Option<&KnowledgeBase>) -> Vec<Value> {
        let mut payloads = Vec::new();
        let mut rng = thread_rng();

        // Generate different types of fuzzed payloads
        match &self.strategy {
            FuzzingStrategy::Random => {
                for _ in 0..5 {
                    payloads.push(self.randomize_payload(original));
                }
            },
            FuzzingStrategy::Boundary => {
                payloads.extend(self.generate_boundary_payloads(original));
            },
            FuzzingStrategy::Malicious => {
                payloads.extend(self.generate_malicious_payloads(original));
            },
            FuzzingStrategy::TypeConfusion => {
                payloads.extend(self.generate_type_confusion_payloads(original));
            },
            FuzzingStrategy::Overflow => {
                payloads.extend(self.generate_overflow_payloads(original));
            },
            FuzzingStrategy::Injection => {
                payloads.extend(self.generate_injection_payloads(original));
            },
            FuzzingStrategy::Mixed => {
                // Mix of all strategies
                payloads.push(self.randomize_payload(original));
                payloads.extend(self.generate_boundary_payloads(original));
                payloads.extend(self.generate_malicious_payloads(original));
                payloads.extend(self.generate_type_confusion_payloads(original));
                payloads.extend(self.generate_overflow_payloads(original));
                payloads.extend(self.generate_injection_payloads(original));
            },
        }

        // If knowledge base is available, generate domain-specific fuzz data
        if let Some(knowledge_base) = kb {
            payloads.extend(self.generate_kb_based_fuzz(original, knowledge_base));
        }

        // Ensure we have at least some payloads
        if payloads.is_empty() {
            for _ in 0..3 {
                payloads.push(self.randomize_payload(original));
            }
        }

        // Limit the number of payloads to avoid too many requests
        if payloads.len() > 5 {  // Giảm từ 20 xuống 5
            payloads.shuffle(&mut rng);
            payloads.truncate(5);
        }

        payloads
    }

    fn randomize_payload(&self, original: &Value) -> Value {
        match original {
            Value::Object(obj) => {
                let mut new_obj = Map::new();
                for (key, value) in obj {
                    let new_key = if thread_rng().gen_bool(0.1) {
                        self.data_generator.generate_fuzz_string()
                    } else {
                        key.clone()
                    };
                    let new_value = if thread_rng().gen_bool(0.3) {
                        self.fuzz_value(value)
                    } else {
                        value.clone()
                    };
                    new_obj.insert(new_key, new_value);
                }
                
                // Sometimes add random fields
                if thread_rng().gen_bool(0.2) {
                    new_obj.insert(
                        self.data_generator.generate_fuzz_string(),
                        self.data_generator.generate_fuzz_string().into()
                    );
                }
                
                Value::Object(new_obj)
            },
            Value::Array(arr) => {
                let mut new_arr = Vec::new();
                for item in arr {
                    if thread_rng().gen_bool(0.3) {
                        new_arr.push(self.fuzz_value(item));
                    } else {
                        new_arr.push(item.clone());
                    }
                }
                
                // Sometimes add random items
                if thread_rng().gen_bool(0.2) {
                    new_arr.push(self.data_generator.generate_fuzz_string().into());
                }
                
                Value::Array(new_arr)
            },
            _ => self.fuzz_value(original)
        }
    }

    fn fuzz_value(&self, value: &Value) -> Value {
        let mut rng = thread_rng();
        let strategy = rng.gen_range(0..10);

        match strategy {
            0 => Value::String(self.data_generator.generate_fuzz_string()),
            1 => self.data_generator.generate_fuzz_number(),
            2 => Value::Bool(!value.as_bool().unwrap_or(false)),
            3 => Value::Null,
            4 => self.data_generator.generate_fuzz_array(0),
            5 => self.data_generator.generate_fuzz_object(0),
            6 => Value::String("".to_string()),
            7 => Value::String(" ".repeat(1000)),
            8 => Value::String("🔥".repeat(100)),
            _ => value.clone(),
        }
    }

    fn generate_boundary_payloads(&self, original: &Value) -> Vec<Value> {
        let mut payloads = Vec::new();

        if let Value::Object(obj) = original {
            let mut boundary_obj = obj.clone();
            
            // Empty object
            payloads.push(Value::Object(Map::new()));
            
            // Object with one field removed
            if obj.len() > 1 {
                let keys: Vec<_> = obj.keys().collect();
                let key_to_remove = keys[0];
                boundary_obj.remove(key_to_remove);
                payloads.push(Value::Object(boundary_obj.clone()));
            }
            
            // Object with all string values set to boundary values
            let mut boundary_strings = obj.clone();
            for (_, value) in boundary_strings.iter_mut() {
                if value.is_string() {
                    *value = Value::String("".to_string());
                }
            }
            payloads.push(Value::Object(boundary_strings));
            
            // Object with very long strings
            let mut long_strings = obj.clone();
            for (_, value) in long_strings.iter_mut() {
                if value.is_string() {
                    *value = Value::String("A".repeat(10000));
                }
            }
            payloads.push(Value::Object(long_strings));
        }

        payloads
    }

    fn generate_malicious_payloads(&self, original: &Value) -> Vec<Value> {
        let mut payloads = Vec::new();

        if let Value::Object(obj) = original {
            // SQL Injection payloads
            let mut sql_obj = obj.clone();
            for (_, value) in sql_obj.iter_mut() {
                if value.is_string() {
                    *value = Value::String("' OR '1'='1".to_string());
                }
            }
            payloads.push(Value::Object(sql_obj));

            // XSS payloads
            let mut xss_obj = obj.clone();
            for (_, value) in xss_obj.iter_mut() {
                if value.is_string() {
                    *value = Value::String("<script>alert('XSS')</script>".to_string());
                }
            }
            payloads.push(Value::Object(xss_obj));

            // Path traversal payloads
            let mut path_obj = obj.clone();
            for (_, value) in path_obj.iter_mut() {
                if value.is_string() {
                    *value = Value::String("../../../etc/passwd".to_string());
                }
            }
            payloads.push(Value::Object(path_obj));

            // Command injection payloads
            let mut cmd_obj = obj.clone();
            for (_, value) in cmd_obj.iter_mut() {
                if value.is_string() {
                    *value = Value::String("; ls -la".to_string());
                }
            }
            payloads.push(Value::Object(cmd_obj));
        }

        payloads
    }

    fn generate_type_confusion_payloads(&self, original: &Value) -> Vec<Value> {
        let mut payloads = Vec::new();

        if let Value::Object(obj) = original {
            // String to number confusion
            let mut str_to_num = obj.clone();
            for (_, value) in str_to_num.iter_mut() {
                if value.is_string() {
                    *value = Value::Number(serde_json::Number::from(42));
                }
            }
            payloads.push(Value::Object(str_to_num));

            // Number to string confusion
            let mut num_to_str = obj.clone();
            for (_, value) in num_to_str.iter_mut() {
                if value.is_number() {
                    *value = Value::String("not_a_number".to_string());
                }
            }
            payloads.push(Value::Object(num_to_str));

            // Boolean to string confusion
            let mut bool_to_str = obj.clone();
            for (_, value) in bool_to_str.iter_mut() {
                if value.is_boolean() {
                    *value = Value::String("true".to_string());
                }
            }
            payloads.push(Value::Object(bool_to_str));

            // Array to object confusion
            let mut arr_to_obj = obj.clone();
            for (_, value) in arr_to_obj.iter_mut() {
                if value.is_array() {
                    *value = Value::Object(Map::new());
                }
            }
            payloads.push(Value::Object(arr_to_obj));
        }

        payloads
    }

    fn generate_overflow_payloads(&self, original: &Value) -> Vec<Value> {
        let mut payloads = Vec::new();

        if let Value::Object(obj) = original {
            // String overflow
            let mut str_overflow = obj.clone();
            for (_, value) in str_overflow.iter_mut() {
                if value.is_string() {
                    *value = Value::String("A".repeat(1000000));
                }
            }
            payloads.push(Value::Object(str_overflow));

            // Array overflow
            let mut arr_overflow = obj.clone();
            for (_, value) in arr_overflow.iter_mut() {
                if value.is_array() {
                    let large_array: Vec<Value> = (0..10000)
                        .map(|i| Value::String(format!("item_{}", i)))
                        .collect();
                    *value = Value::Array(large_array);
                }
            }
            payloads.push(Value::Object(arr_overflow));

            // Deep nesting overflow
            let mut deep_obj = obj.clone();
            let mut nested = Value::Object(Map::new());
            for _ in 0..100 {
                let mut temp_map = Map::new();
                temp_map.insert("nested".to_string(), nested);
                nested = Value::Object(temp_map);
            }
            deep_obj.insert("deep_nested".to_string(), nested);
            payloads.push(Value::Object(deep_obj));
        }

        payloads
    }

    fn generate_injection_payloads(&self, original: &Value) -> Vec<Value> {
        let mut payloads = Vec::new();

        let injection_payloads = [
            // SQL Injection
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "' OR 1=1 --",
            
            // NoSQL Injection
            "{ \"$gt\": \"\" }",
            "{ \"$ne\": null }",
            "{ \"$regex\": \".*\" }",
            
            // LDAP Injection
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            
            // XPath Injection
            "' or '1'='1",
            "x' or name()='username' or 'x'='y",
            
            // Template Injection
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            
            // Header Injection
            "test\r\nX-Injected: true",
            "test\nSet-Cookie: injected=true",
        ];

        if let Value::Object(obj) = original {
            for payload in &injection_payloads {
                let mut injection_obj = obj.clone();
                for (_, value) in injection_obj.iter_mut() {
                    if value.is_string() {
                        *value = Value::String(payload.to_string());
                    }
                }
                payloads.push(Value::Object(injection_obj));
            }
        }

        payloads
    }

    fn generate_kb_based_fuzz(&self, original: &Value, kb: &KnowledgeBase) -> Vec<Value> {
        let mut payloads = Vec::new();

        if let Value::Object(obj) = original {
            // Use knowledge base patterns to generate realistic but potentially malicious data
            for (field_name, data_set) in &kb.valid_data {
                if let Some(_pattern) = &data_set.pattern {
                    // Generate variations of the valid pattern
                    let mut kb_obj = obj.clone();
                    
                    // Pattern with malicious suffixes
                    if let Some(example) = data_set.examples.first() {
                        if let Some(example_str) = example.as_str() {
                            let malicious_variants = [
                                format!("{}'--", example_str),
                                format!("{}<script>", example_str),
                                format!("{}../../../", example_str),
                                format!("{}\x00", example_str),
                                format!("{}{}", example_str, "A".repeat(1000)),
                            ];
                            
                            for variant in &malicious_variants {
                                if kb_obj.contains_key(field_name) {
                                    kb_obj.insert(field_name.clone(), Value::String(variant.clone()));
                                    payloads.push(Value::Object(kb_obj.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }

        payloads
    }
}

#[derive(Debug, Clone)]
pub struct FuzzTestCase {
    pub name: String,
    pub payload: Value,
    pub strategy: FuzzingStrategy,
    pub description: String,
    pub expected_behavior: String,
}

impl FuzzTestCase {
    pub fn new(
        name: String,
        payload: Value,
        strategy: FuzzingStrategy,
        description: String,
        expected_behavior: String,
    ) -> Self {
        Self {
            name,
            payload,
            strategy,
            description,
            expected_behavior,
        }
    }
}

pub fn generate_fuzz_test_cases(
    original_payload: &Value,
    kb: Option<&KnowledgeBase>,
    config: FuzzingConfig,
) -> Vec<FuzzTestCase> {
    let mut test_cases = Vec::new();

    let strategies = [
        FuzzingStrategy::Random,
        FuzzingStrategy::Boundary,
        FuzzingStrategy::Malicious,
        FuzzingStrategy::TypeConfusion,
        FuzzingStrategy::Overflow,
        FuzzingStrategy::Injection,
    ];

    for strategy in &strategies {
        let fuzzer = PayloadFuzzer::new(config.clone(), strategy.clone());
        let payloads = fuzzer.fuzz_json_payload(original_payload, kb);

        for (i, payload) in payloads.into_iter().enumerate() {
            let (description, expected) = match strategy {
                FuzzingStrategy::Random => (
                    "Random data mutation test".to_string(),
                    "Should handle random data gracefully without crashes".to_string(),
                ),
                FuzzingStrategy::Boundary => (
                    "Boundary value testing".to_string(),
                    "Should validate boundary conditions properly".to_string(),
                ),
                FuzzingStrategy::Malicious => (
                    "Malicious payload injection test".to_string(),
                    "Should detect and reject malicious inputs".to_string(),
                ),
                FuzzingStrategy::TypeConfusion => (
                    "Type confusion attack test".to_string(),
                    "Should enforce proper type validation".to_string(),
                ),
                FuzzingStrategy::Overflow => (
                    "Buffer/data overflow test".to_string(),
                    "Should handle large inputs without memory issues".to_string(),
                ),
                FuzzingStrategy::Injection => (
                    "Code injection vulnerability test".to_string(),
                    "Should sanitize inputs and prevent code execution".to_string(),
                ),
                FuzzingStrategy::Mixed => (
                    "Mixed fuzzing strategy test".to_string(),
                    "Should handle various attack vectors robustly".to_string(),
                ),
            };

            test_cases.push(FuzzTestCase::new(
                format!("{:?}_fuzz_test_{}", strategy, i + 1),
                payload,
                strategy.clone(),
                description,
                expected,
            ));
        }
    }

    test_cases
}
