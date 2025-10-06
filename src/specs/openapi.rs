use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, Context};
use std::fs;
use colored::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenAPISpec {
    pub openapi: Option<String>,
    pub swagger: Option<String>,
    pub info: Info,
    pub servers: Option<Vec<Server>>,
    pub paths: HashMap<String, PathItem>,
    pub components: Option<Components>,
    // Swagger 2.0 fields
    pub host: Option<String>,
    #[serde(rename = "basePath")]
    pub base_path: Option<String>,
    pub schemes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Info {
    pub title: String,
    pub version: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Server {
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathItem {
    pub get: Option<Operation>,
    pub post: Option<Operation>,
    pub put: Option<Operation>,
    pub delete: Option<Operation>,
    pub patch: Option<Operation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Operation {
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub parameters: Option<Vec<Parameter>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RequestBody>,
    pub responses: Option<HashMap<String, Response>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String, // query, path, header, etc.
    pub required: Option<bool>,
    pub schema: Option<Schema>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestBody {
    pub content: HashMap<String, MediaType>,
    pub required: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediaType {
    pub schema: Option<Schema>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Response {
    pub description: String,
    pub content: Option<HashMap<String, MediaType>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Schema {
    #[serde(rename = "type")]
    pub schema_type: Option<String>,
    pub format: Option<String>,
    pub example: Option<serde_json::Value>,
    pub properties: Option<HashMap<String, Schema>>,
    pub required: Option<Vec<String>>,
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Components {
    pub schemas: Option<HashMap<String, Schema>>,
}

#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub base_url: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
}

impl OpenAPISpec {
    pub fn from_file(file_path: &str) -> Result<Self> {
        let content = fs::read_to_string(file_path)
            .context(format!("Failed to read OpenAPI spec file: {}", file_path))?;

        // Try JSON first, then YAML
        if file_path.ends_with(".json") {
            serde_json::from_str(&content)
                .context("Failed to parse OpenAPI spec as JSON")
        } else if file_path.ends_with(".yaml") || file_path.ends_with(".yml") {
            serde_yaml::from_str(&content)
                .context("Failed to parse OpenAPI spec as YAML")
        } else {
            // Try both formats
            serde_json::from_str(&content)
                .or_else(|_| serde_yaml::from_str(&content))
                .context("Failed to parse OpenAPI spec as JSON or YAML")
        }
    }

    pub fn extract_endpoints(&self) -> Vec<EndpointInfo> {
        let mut endpoints = Vec::new();
        let base_url = self.get_base_url();

        for (path, path_item) in &self.paths {
            // Process each HTTP method
            if let Some(op) = &path_item.get {
                endpoints.push(self.create_endpoint_info(path, "GET", &base_url, op));
            }
            if let Some(op) = &path_item.post {
                endpoints.push(self.create_endpoint_info(path, "POST", &base_url, op));
            }
            if let Some(op) = &path_item.put {
                endpoints.push(self.create_endpoint_info(path, "PUT", &base_url, op));
            }
            if let Some(op) = &path_item.delete {
                endpoints.push(self.create_endpoint_info(path, "DELETE", &base_url, op));
            }
            if let Some(op) = &path_item.patch {
                endpoints.push(self.create_endpoint_info(path, "PATCH", &base_url, op));
            }
        }

        endpoints
    }

    fn get_base_url(&self) -> String {
        // Try OpenAPI 3.0 servers first
        if let Some(servers) = &self.servers {
            if let Some(first_server) = servers.first() {
                return first_server.url.clone();
            }
        }
        
        // Fall back to Swagger 2.0 host + schemes + basePath
        if let Some(host) = &self.host {
            let scheme = self.schemes.as_ref()
                .and_then(|schemes| schemes.first())
                .unwrap_or(&"https".to_string())
                .clone();
            
            let base_path = self.base_path.as_ref()
                .unwrap_or(&"".to_string())
                .clone();
            
            return format!("{}://{}{}", scheme, host, base_path);
        }
        
        "http://localhost".to_string()
    }

    fn create_endpoint_info(&self, path: &str, method: &str, base_url: &str, operation: &Operation) -> EndpointInfo {
        EndpointInfo {
            path: path.to_string(),
            method: method.to_string(),
            base_url: base_url.to_string(),
            summary: operation.summary.clone(),
            description: operation.description.clone(),
            parameters: operation.parameters.clone().unwrap_or_default(),
            request_body: operation.request_body.clone(),
            responses: operation.responses.clone().unwrap_or_default(),
        }
    }

    #[allow(dead_code)]
    pub fn resolve_schema_reference(&self, schema: &Schema) -> Option<Schema> {
        if let Some(ref_path) = &schema.reference {
            // Handle references like "#/components/schemas/SchemaName"
            if ref_path.starts_with("#/components/schemas/") {
                let schema_name = ref_path.trim_start_matches("#/components/schemas/");
                if let Some(components) = &self.components {
                    if let Some(schemas) = &components.schemas {
                        return schemas.get(schema_name).cloned();
                    }
                }
            }
        }
        None
    }

    pub fn get_info(&self) -> String {
        let base_url = self.get_base_url();
        format!(
            "{} v{}\n{}\n🔗 Base URL: {}",
            self.info.title.bright_blue().bold(),
            self.info.version.green(),
            self.info.description.as_ref().unwrap_or(&"No description".to_string()).bright_white(),
            base_url.cyan()
        )
    }
}

pub fn load_openapi_spec(file_path: &str) -> Result<OpenAPISpec> {
    println!("📖 Loading OpenAPI specification from: {}", file_path.cyan());
    
    let spec = OpenAPISpec::from_file(file_path)?;
    
    println!("✅ Successfully loaded OpenAPI spec:");
    println!("{}", spec.get_info());
    println!("📊 Found {} endpoints", spec.paths.len().to_string().yellow().bold());
    
    Ok(spec)
}
