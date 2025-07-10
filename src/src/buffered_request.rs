use anyhow::{Context, Result};
use bytes::Bytes;
use hyper::{Body, Request};
use hyper::body::to_bytes;
use serde_json::Value;

/// A request with a buffered body
pub struct BufferedRequest {
    /// The original request parts
    pub parts: hyper::http::request::Parts,
    /// The buffered body
    pub body: Bytes,
}

impl BufferedRequest {
    /// Create a new buffered request from a hyper Request
    pub async fn from_request(req: Request<Body>) -> Result<Self> {
        let (parts, body) = req.into_parts();
        let body = to_bytes(body)
            .await
            .context("Failed to buffer request body")?;

        Ok(Self { parts, body })
    }

    /// Create a new buffered request with an empty body
    pub fn from_parts(parts: hyper::http::request::Parts) -> Self {
        Self { 
            parts, 
            body: Bytes::new() 
        }
    }

    /// Convert the buffered request back to a hyper Request
    pub fn into_request(self) -> Request<Body> {
        let body = Body::from(self.body);
        Request::from_parts(self.parts, body)
    }

    /// Parse the body as JSON
    pub fn parse_json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .context("Failed to parse request body as JSON")
    }
}
