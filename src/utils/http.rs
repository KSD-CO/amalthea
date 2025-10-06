use anyhow::Result;
use reqwest::{Client, Response};
use serde_json::Value;
use std::collections::HashMap;

pub async fn send_request(
    method: &str, 
    url: &str, 
    headers: &HashMap<String, String>,
    payload: Option<&str>
) -> Result<Response> {
    let client = Client::new();
    let m = method.to_uppercase();

    let mut builder = match m.as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        _ => anyhow::bail!("Unsupported HTTP method: {}", m),
    };

    // Add headers
    for (key, value) in headers {
        builder = builder.header(key, value);
    }

    // Add payload if provided
    if let Some(p) = payload {
        builder = builder.body(p.to_string());
    }

    Ok(builder.send().await?)
}

pub async fn send_request_with_query(
    method: &str, 
    base_url: &str,
    query_params: Option<&str>,
    headers: &HashMap<String, String>,
    payload: Option<&str>
) -> Result<Response> {
    let url = if let Some(params) = query_params {
        format!("{}?{}", base_url, params)
    } else {
        base_url.to_string()
    };
    
    send_request(method, &url, headers, payload).await
}

pub async fn pretty_body(resp: Response) -> Result<Value> {
    let v: Value = resp.json().await?;
    Ok(v)
}

/// Send request and return status code and response body as string
pub async fn send_request_with_response(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    payload: Option<&str>,
) -> Result<(u16, String)> {
    let response = send_request(method, url, headers, payload).await?;
    let status = response.status().as_u16();
    let body = response.text().await?;
    Ok((status, body))
}
