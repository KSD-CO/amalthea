use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::fs;
use std::collections::HashMap;
use colored::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KnowledgeBase {
    pub api_name: String,
    pub description: Option<String>,
    pub valid_data: HashMap<String, ValidDataSet>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ValidDataSet {
    pub description: String,
    pub examples: Vec<serde_json::Value>,
    pub data_type: String, // "string", "number", "object", "array"
    pub pattern: Option<String>, // regex pattern if applicable
}

impl KnowledgeBase {
    pub fn from_file(file_path: &str) -> Result<Self> {
        let content = fs::read_to_string(file_path)
            .context(format!("Failed to read knowledge base file: {}", file_path))?;

        serde_json::from_str(&content)
            .context("Failed to parse knowledge base file as JSON")
    }

    pub fn get_valid_value(&self, field_name: &str) -> Option<serde_json::Value> {
        // Try exact match first
        if let Some(data_set) = self.valid_data.get(field_name) {
            if !data_set.examples.is_empty() {
                return Some(data_set.examples[0].clone());
            }
        }

        // Try partial match (e.g., "orderNumber" matches "order_number")
        let field_lower = field_name.to_lowercase();
        for (key, data_set) in &self.valid_data {
            let key_lower = key.to_lowercase().replace("_", "").replace("-", "");
            let field_normalized = field_lower.replace("_", "").replace("-", "");
            
            if key_lower.contains(&field_normalized) || field_normalized.contains(&key_lower) {
                if !data_set.examples.is_empty() {
                    return Some(data_set.examples[0].clone());
                }
            }
        }

        None
    }

    #[allow(dead_code)]
    pub fn get_multiple_values(&self, field_name: &str, count: usize) -> Vec<serde_json::Value> {
        let mut values = Vec::new();
        
        if let Some(data_set) = self.valid_data.get(field_name) {
            let examples_len = data_set.examples.len();
            for i in 0..count.min(examples_len) {
                values.push(data_set.examples[i].clone());
            }
        } else {
            // Try partial match
            let field_lower = field_name.to_lowercase();
            for (key, data_set) in &self.valid_data {
                let key_lower = key.to_lowercase().replace("_", "").replace("-", "");
                let field_normalized = field_lower.replace("_", "").replace("-", "");
                
                if key_lower.contains(&field_normalized) || field_normalized.contains(&key_lower) {
                    let examples_len = data_set.examples.len();
                    for i in 0..count.min(examples_len) {
                        values.push(data_set.examples[i].clone());
                    }
                    break;
                }
            }
        }

        values
    }

    pub fn get_field_suggestions(&self, endpoint_path: &str) -> HashMap<String, serde_json::Value> {
        let mut suggestions = HashMap::new();
        
        // Extract potential field names from endpoint path
        let path_parts: Vec<&str> = endpoint_path.split('/').collect();
        
        for part in path_parts {
            if part.starts_with('{') && part.ends_with('}') {
                let field_name = part.trim_start_matches('{').trim_end_matches('}');
                if let Some(value) = self.get_valid_value(field_name) {
                    suggestions.insert(field_name.to_string(), value);
                }
            }
        }
        
        // Common field mappings
        let common_fields = [
            ("id", vec!["id", "ID"]),
            ("orderId", vec!["order_id", "orderId", "orderNumber", "order_number"]),
            ("userId", vec!["user_id", "userId", "userCode"]),
            ("productId", vec!["product_id", "productId", "sku", "productCode"]),
            ("customerId", vec!["customer_id", "customerId", "customerCode"]),
        ];
        
        for (standard_name, variants) in &common_fields {
            if endpoint_path.to_lowercase().contains(standard_name) {
                for variant in variants {
                    if let Some(value) = self.get_valid_value(variant) {
                        suggestions.insert(standard_name.to_string(), value);
                        break;
                    }
                }
            }
        }
        
        suggestions
    }

    pub fn build_context_for_ai(&self, endpoint_path: &str) -> String {
        let suggestions = self.get_field_suggestions(endpoint_path);
        
        if suggestions.is_empty() {
            return String::new();
        }
        
        let mut context = String::from("\n=== KNOWLEDGE BASE - Valid Test Data ===\n");
        context.push_str("Use these REAL, VALID values from the system instead of making up fake data:\n\n");
        
        for (field, value) in &suggestions {
            context.push_str(&format!("• {}: {} (REAL VALUE - use this!)\n", field, value));
        }
        
        // Add additional context from knowledge base
        context.push_str("\nAvailable data sets:\n");
        for (key, data_set) in &self.valid_data {
            if data_set.examples.len() > 1 {
                context.push_str(&format!("• {}: {} (has {} examples)\n", 
                    key, data_set.description, data_set.examples.len()));
            }
        }
        
        context.push_str("\nIMPORTANT: Always use the provided REAL values above instead of generating fake data!\n");
        context.push_str("===========================================\n");
        
        context
    }

    pub fn get_info(&self) -> String {
        format!(
            "{}\n{}\n📊 Data sets: {}",
            self.api_name.bright_blue().bold(),
            self.description.as_ref().unwrap_or(&"Knowledge base for valid test data".to_string()).bright_white(),
            self.valid_data.len().to_string().yellow().bold()
        )
    }
}

pub fn load_knowledge_base(file_path: &str) -> Result<KnowledgeBase> {
    println!("📚 Loading knowledge base from: {}", file_path.cyan());
    
    let kb = KnowledgeBase::from_file(file_path)?;
    
    println!("✅ Successfully loaded knowledge base:");
    println!("{}", kb.get_info());
    
    Ok(kb)
}
