use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, Context};
use std::fs;
use colored::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanCollection {
    pub info: PostmanInfo,
    pub item: Vec<PostmanItem>,
    pub auth: Option<PostmanAuth>,
    pub variable: Option<Vec<PostmanVariable>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanInfo {
    #[serde(rename = "_postman_id")]
    pub postman_id: Option<String>,
    pub name: String,
    pub schema: String,
    #[serde(rename = "_exporter_id")]
    pub exporter_id: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanItem {
    pub name: String,
    pub item: Option<Vec<PostmanItem>>,
    pub request: Option<PostmanRequest>,
    pub response: Option<Vec<PostmanResponse>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanRequest {
    pub method: String,
    pub header: Option<Vec<PostmanHeader>>,
    pub body: Option<PostmanBody>,
    pub url: PostmanUrl,
    pub auth: Option<PostmanAuth>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PostmanUrl {
    String(String),
    Object {
        raw: Option<String>,
        protocol: Option<String>,
        host: Option<Vec<String>>,
        path: Option<Vec<String>>,
        query: Option<Vec<PostmanQueryParam>>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanHeader {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub header_type: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanBody {
    pub mode: String,
    pub raw: Option<String>,
    #[serde(rename = "urlencoded")]
    pub url_encoded: Option<Vec<PostmanKeyValue>>,
    #[serde(rename = "formdata")]
    pub form_data: Option<Vec<PostmanKeyValue>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanKeyValue {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub param_type: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanQueryParam {
    pub key: String,
    pub value: String,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanAuth {
    #[serde(rename = "type")]
    pub auth_type: String,
    pub bearer: Option<Vec<PostmanKeyValue>>,
    pub basic: Option<Vec<PostmanKeyValue>>,
    pub apikey: Option<Vec<PostmanKeyValue>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanResponse {
    pub name: String,
    pub status: String,
    pub code: u16,
    pub header: Option<Vec<PostmanHeader>>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostmanVariable {
    pub key: String,
    pub value: String,
    #[serde(rename = "type")]
    pub var_type: Option<String>,
}

// Convert to our internal EndpointInfo format
#[derive(Debug, Clone)]
pub struct PostmanEndpoint {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub description: Option<String>,
}

impl PostmanCollection {
    pub fn from_file(file_path: &str) -> Result<Self> {
        let content = fs::read_to_string(file_path)
            .context(format!("Failed to read Postman collection file: {}", file_path))?;

        serde_json::from_str(&content)
            .context("Failed to parse Postman collection as JSON")
    }

    pub fn extract_endpoints(&self) -> Vec<PostmanEndpoint> {
        let mut endpoints = Vec::new();
        self.extract_items_recursive(&self.item, &mut endpoints, String::new());
        endpoints
    }

    fn extract_items_recursive(&self, items: &[PostmanItem], endpoints: &mut Vec<PostmanEndpoint>, parent_path: String) {
        for item in items {
            let current_path = if parent_path.is_empty() {
                item.name.clone()
            } else {
                format!("{}/{}", parent_path, item.name)
            };

            if let Some(request) = &item.request {
                // This is a request item
                let endpoint = self.convert_to_endpoint(item, request, &current_path);
                endpoints.push(endpoint);
            } else if let Some(sub_items) = &item.item {
                // This is a folder, recurse into it
                self.extract_items_recursive(sub_items, endpoints, current_path);
            }
        }
    }

    fn convert_to_endpoint(&self, _item: &PostmanItem, request: &PostmanRequest, path: &str) -> PostmanEndpoint {
        let url = self.extract_url(&request.url);
        let headers = self.extract_headers(&request.header);
        let body = self.extract_body(&request.body);

        PostmanEndpoint {
            name: format!("{} - {}", path, request.method),
            method: request.method.clone(),
            url,
            headers,
            body,
            description: Some(format!("Request from Postman collection: {}", path)),
        }
    }

    fn extract_url(&self, url: &PostmanUrl) -> String {
        match url {
            PostmanUrl::String(url_str) => url_str.clone(),
            PostmanUrl::Object { raw, protocol, host, path, query } => {
                if let Some(raw_url) = raw {
                    raw_url.clone()
                } else {
                    // Reconstruct URL from components
                    let mut constructed_url = String::new();
                    
                    if let Some(proto) = protocol {
                        constructed_url.push_str(proto);
                        constructed_url.push_str("://");
                    } else {
                        constructed_url.push_str("https://");
                    }
                    
                    if let Some(host_parts) = host {
                        constructed_url.push_str(&host_parts.join("."));
                    }
                    
                    if let Some(path_parts) = path {
                        if !path_parts.is_empty() {
                            constructed_url.push('/');
                            constructed_url.push_str(&path_parts.join("/"));
                        }
                    }
                    
                    if let Some(query_params) = query {
                        if !query_params.is_empty() {
                            constructed_url.push('?');
                            let query_string: Vec<String> = query_params.iter()
                                .filter(|q| !q.disabled.unwrap_or(false))
                                .map(|q| format!("{}={}", q.key, q.value))
                                .collect();
                            constructed_url.push_str(&query_string.join("&"));
                        }
                    }
                    
                    constructed_url
                }
            }
        }
    }

    fn extract_headers(&self, headers: &Option<Vec<PostmanHeader>>) -> HashMap<String, String> {
        let mut result = HashMap::new();
        
        if let Some(header_list) = headers {
            for header in header_list {
                if !header.disabled.unwrap_or(false) {
                    result.insert(header.key.clone(), header.value.clone());
                }
            }
        }
        
        result
    }

    fn extract_body(&self, body: &Option<PostmanBody>) -> Option<String> {
        if let Some(body_obj) = body {
            match body_obj.mode.as_str() {
                "raw" => body_obj.raw.clone(),
                "urlencoded" => {
                    if let Some(params) = &body_obj.url_encoded {
                        let encoded: Vec<String> = params.iter()
                            .filter(|p| !p.disabled.unwrap_or(false))
                            .map(|p| format!("{}={}", p.key, p.value))
                            .collect();
                        Some(encoded.join("&"))
                    } else {
                        None
                    }
                },
                "formdata" => {
                    if let Some(params) = &body_obj.form_data {
                        let form_data: Vec<String> = params.iter()
                            .filter(|p| !p.disabled.unwrap_or(false))
                            .map(|p| format!("{}: {}", p.key, p.value))
                            .collect();
                        Some(form_data.join("\n"))
                    } else {
                        None
                    }
                },
                _ => None
            }
        } else {
            None
        }
    }

    pub fn get_info(&self) -> String {
        format!(
            "{}\n{}",
            self.info.name.bright_blue().bold(),
            self.info.description.as_ref().unwrap_or(&"Postman Collection".to_string()).bright_white()
        )
    }
}

pub fn load_postman_collection(file_path: &str) -> Result<PostmanCollection> {
    println!("📖 Loading Postman collection from: {}", file_path.cyan());
    
    let collection = PostmanCollection::from_file(file_path)?;
    
    println!("✅ Successfully loaded Postman collection:");
    println!("{}", collection.get_info());
    
    let endpoints = collection.extract_endpoints();
    println!("📊 Found {} requests", endpoints.len().to_string().yellow().bold());
    
    Ok(collection)
}
