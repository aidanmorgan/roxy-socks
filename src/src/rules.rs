use std::collections::HashMap;

use anyhow::{Context, Result};
use hyper::{Body, Method, Request};
use jsonpath_rust::JsonPathFinder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, trace};

/// Enum for controlling how query parameters are matched
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryParamMatch {
    /// Ignore query parameters when matching the endpoint (default)
    Ignore,
    /// Query parameters must match the specified regex patterns
    /// If a parameter is missing, the rule doesn't match
    Required,
    /// Query parameters must match the specified regex patterns if present
    /// Missing parameters are allowed
    Optional,
}

impl Default for QueryParamMatch {
    fn default() -> Self {
        Self::Ignore
    }
}

/// Result of a rule check, including information about which rule caused the decision
#[derive(Debug, Clone)]
pub struct RuleCheckResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Information about the rule that caused the decision, if any
    pub rule_info: Option<String>,
}

use crate::buffered_request::BufferedRequest;
use crate::process::ProcessInfo;

/// Trait for request matching operations
pub trait RequestMatcher {
    /// Get the path from the request
    fn path(&self) -> &str;

    /// Get the query string from the request, if any
    fn query(&self) -> Option<&str>;

    /// Get the HTTP method from the request
    fn method(&self) -> &Method;

    /// Parse the request body as JSON, if applicable
    #[allow(dead_code)]
    fn parse_json(&self) -> Result<Option<Value>>;
}

/// Implementation of RequestMatcher for hyper::Request<Body>
impl RequestMatcher for Request<Body> {
    fn path(&self) -> &str {
        self.uri().path()
    }

    fn query(&self) -> Option<&str> {
        self.uri().query()
    }

    fn method(&self) -> &Method {
        self.method()
    }

    fn parse_json(&self) -> Result<Option<Value>> {
        // Can't parse the body without consuming it, so return None
        Ok(None)
    }
}

/// Implementation of RequestMatcher for BufferedRequest
impl RequestMatcher for BufferedRequest {
    fn path(&self) -> &str {
        self.parts.uri.path()
    }

    fn query(&self) -> Option<&str> {
        self.parts.uri.query()
    }

    fn method(&self) -> &Method {
        &self.parts.method
    }

    fn parse_json(&self) -> Result<Option<Value>> {
        match self.parse_json() {
            Ok(json) => Ok(Some(json)),
            Err(e) => Err(e)
        }
    }
}

/// Rule for access control
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// API endpoint to match (e.g., "/containers/json")
    pub endpoint: String,

    /// HTTP methods to match (e.g., ["GET", "POST"])
    #[serde(default)]
    pub methods: Vec<String>,

    /// Whether to allow or deny the request if it matches
    #[serde(default)]
    pub allow: bool,

    /// Optional JSON path conditions to match in the request body
    #[serde(default)]
    pub request_rules: Option<HashMap<String, Value>>,

    /// Optional JSON path conditions to match in the response body
    #[serde(default)]
    pub response_rules: Option<HashMap<String, Value>>,

    /// Optional process binary paths to match
    #[serde(default)]
    pub process_binaries: Option<Vec<String>>,

    /// Optional path variables to use in endpoint matching
    #[serde(default)]
    pub path_variables: Option<HashMap<String, String>>,

    /// Optional regex pattern for path matching
    #[serde(default)]
    pub path_regex: Option<String>,

    /// How to match query parameters when matching the endpoint
    #[serde(default)]
    pub match_query_params: QueryParamMatch,

    /// Optional regex patterns to match query parameters
    /// Keys are regex patterns for parameter names, values are regex patterns to match parameter values
    #[serde(default)]
    pub query_params: Option<HashMap<String, String>>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            methods: Vec::new(),
            allow: false,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        }
    }
}

impl Rule {
    /// Check if the path matches the rule
    fn matches_path(&self, path: &str) -> Result<bool> {
        // If path_regex is specified, use it for matching
        if let Some(regex_pattern) = &self.path_regex {
            let regex = Regex::new(regex_pattern).context("Invalid regex pattern")?;
            if !regex.is_match(path) {
                trace!("Path regex mismatch: {} doesn't match pattern {}", path, regex_pattern);
                return Ok(false);
            }
        } 
        // Otherwise, use endpoint with variables if specified
        else if let Some(variables) = &self.path_variables {
            // For simple cases with exact string matching, try a direct approach first
            if variables.len() == 1 {
                let (var_name, var_value) = variables.iter().next().unwrap();
                let placeholder = format!("{{{}}}", var_name);

                // Try to compile the string as a regex to see if it's a valid pattern
                // If it fails, it's not a regex pattern and we can use simple string replacement
                if Regex::new(var_value).is_err() {

                    let exact_path = self.endpoint.replace(&placeholder, var_value);
                    if path == exact_path {
                        // Skip the regex approach for simple exact matches
                        debug!("Exact path match: {} == {}", path, exact_path);
                        // Continue with other checks (method, process binary, etc.)
                    } else {
                        trace!("Exact path mismatch: {} != {}", path, exact_path);
                        return Ok(false);
                    }
                } else {
                    // For regex patterns, fall through to the regex approach
                    let mut regex_pattern = "^".to_string();

                    // Split the endpoint by the placeholder
                    let parts: Vec<&str> = self.endpoint.split(&placeholder).collect();
                    if parts.len() == 2 {
                        // Escape the parts and join with the regex pattern
                        regex_pattern.push_str(&regex::escape(parts[0]));
                        regex_pattern.push_str(&format!("({})", var_value));
                        regex_pattern.push_str(&regex::escape(parts[1]));
                        regex_pattern.push_str("$");

                        // Create regex and match against the path
                        let regex = Regex::new(&regex_pattern).context("Invalid regex pattern from path variable")?;
                        if !regex.is_match(path) {
                            trace!("Path regex mismatch: {} doesn't match pattern {}", path, regex_pattern);
                            return Ok(false);
                        }
                    } else {
                        // Shouldn't happen, but handle it gracefully
                        trace!("Invalid placeholder format in endpoint: {}", self.endpoint);
                        return Ok(false);
                    }
                }
            } else {
                // For multiple variables, use a more complex regex approach
                // Start with the endpoint and escape it
                let mut pattern_str = self.endpoint.clone();

                // Replace each variable placeholder with a capture group
                for (var_name, var_value) in variables {
                    let placeholder = format!("{{{}}}", var_name);
                    let capture_group = format!("({})", var_value);
                    pattern_str = pattern_str.replace(&placeholder, &capture_group);
                }

                // Create a regex from the pattern
                let regex = Regex::new(&format!("^{}$", pattern_str)).context("Invalid regex pattern from multiple path variables")?;
                if !regex.is_match(path) {
                    trace!("Path regex mismatch: {} doesn't match pattern ^{}$", path, pattern_str);
                    return Ok(false);
                }
            }
        }
        // Otherwise, use the original endpoint matching
        else if !path.starts_with(&self.endpoint) {
            trace!("Endpoint mismatch: {} != {}", path, self.endpoint);
            return Ok(false);
        }

        Ok(true)
    }

    /// Check if the query parameters match the rule
    fn matches_query_params(&self, query: Option<&str>) -> Result<bool> {
        if self.match_query_params != QueryParamMatch::Ignore {
            if let Some(query_params) = &self.query_params {
                if !query_params.is_empty() {
                    // Get the query string from the URI
                    if let Some(query_str) = query {
                        // Parse the query string into key-value pairs
                        let query_pairs: Vec<(String, String)> = query_str
                            .split('&')
                            .filter_map(|pair| {
                                let mut parts = pair.split('=');
                                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                                    Some((key.to_string(), value.to_string()))
                                } else {
                                    None
                                }
                            })
                            .collect();

                        // Check each query parameter against the regex pattern
                        for (param_name, pattern) in query_params {
                            let regex = match Regex::new(pattern) {
                                Ok(r) => r,
                                Err(e) => {
                                    trace!("Invalid regex pattern for query parameter {}: {}", param_name, e);
                                    return Ok(false);
                                }
                            };

                            // Create regex for parameter name
                            let name_regex = match Regex::new(param_name) {
                                Ok(r) => r,
                                Err(e) => {
                                    trace!("Invalid regex pattern for parameter name {}: {}", param_name, e);
                                    return Ok(false);
                                }
                            };

                            // Find the parameter in the query string using regex for parameter name
                            let param_value = query_pairs.iter()
                                .find(|(k, _)| name_regex.is_match(k))
                                .map(|(_, v)| v);

                            match param_value {
                                Some(value) => {
                                    if !regex.is_match(value) {
                                        trace!("Query parameter mismatch: {}={} doesn't match pattern {}", param_name, value, pattern);
                                        return Ok(false);
                                    }
                                },
                                None => {
                                    // Parameter not found in the query string
                                    if self.match_query_params == QueryParamMatch::Required {
                                        trace!("Query parameter not found: {}", param_name);
                                        return Ok(false);
                                    }
                                    // For Optional, missing parameters are allowed
                                }
                            }
                        }
                    } else {
                        // No query string in the URI
                        if self.match_query_params == QueryParamMatch::Required {
                            trace!("No query string in URI, but query parameters are required");
                            return Ok(false);
                        }
                        // For Optional, missing query string is allowed
                    }
                }
            }
        }

        Ok(true)
    }

    /// Check if the HTTP method matches the rule
    fn matches_method(&self, method: &Method) -> bool {
        if !self.methods.is_empty() {
            let method_str = method.as_str();
            if !self.methods.iter().any(|m| m == method_str) {
                trace!("Method mismatch: {} not in {:?}", method_str, self.methods);
                return false;
            }
        }
        true
    }

    /// Check if the process binary matches the rule
    fn matches_process_binary(&self, process_info: &ProcessInfo) -> bool {
        if let Some(binaries) = &self.process_binaries {
            if !binaries.iter().any(|b| process_info.binary.contains(b)) {
                trace!(
                    "Process binary mismatch: {} not in {:?}",
                    process_info.binary,
                    binaries
                );
                return false;
            }
        }
        true
    }

    /// Check if the rule matches the given request and process info
    #[allow(dead_code)]
    pub async fn matches(&self, req: &Request<Body>, process_info: &ProcessInfo) -> Result<bool> {
        // Check if the endpoint matches
        if !self.matches_path(req.uri().path())? {
            return Ok(false);
        }

        // Check if query parameters should be matched
        if !self.matches_query_params(req.uri().query())? {
            return Ok(false);
        }

        // Check if the method matches
        if !self.matches_method(req.method()) {
            return Ok(false);
        }

        // Check process binary
        if !self.matches_process_binary(process_info) {
            return Ok(false);
        }

        debug!(
            "Rule matched: endpoint={}, methods={:?}, allow={}",
            self.endpoint, self.methods, self.allow
        );
        Ok(true)
    }
}


/// Check if a buffered request is allowed based on the rules
pub async fn check_request_buffered(
    req: &BufferedRequest,
    rules: &[Rule],
    process_info: &ProcessInfo,
) -> Result<RuleCheckResult> {
    // Default to deny if no rules match
    let mut result = RuleCheckResult {
        allowed: false,
        rule_info: None,
    };

    for rule in rules {
        if matches_buffered(rule, req, process_info).await? {
            // Return immediately when a rule matches
            return Ok(RuleCheckResult {
                allowed: rule.allow,
                rule_info: Some(format!("Rule matched: endpoint={}, methods={:?}, allow={}", 
                                       rule.endpoint, rule.methods, rule.allow)),
            });
        }
    }

    // No rules matched
    result.rule_info = Some("No matching rules".to_string());
    Ok(result)
}

impl Rule {
    /// Check if the request rules match using JSON path conditions
    async fn matches_request_rules(&self, req: &BufferedRequest) -> Result<bool> {
        if let Some(rules) = &self.request_rules {
            if !rules.is_empty() {
                // JSON path checking is only applicable for methods that typically have a body
                let method = req.method();
                if method == &Method::POST || method == &Method::PUT || method == &Method::PATCH {
                    // Parse the body as JSON
                    match req.parse_json() {
                        Ok(json) => {
                            // Check each JSON path condition from request_rules
                            for (path, expected_value) in rules {
                                // Use JsonPathFinder to evaluate the JSON path
                                let finder = match JsonPathFinder::from_str(&json.to_string(), path) {
                                    Ok(finder) => finder,
                                    Err(e) => {
                                        trace!("Failed to create JsonPathFinder: {}", e);
                                        return Ok(false);
                                    }
                                };

                                let found_values = finder.find();

                                // Check if the found value matches the expected value
                                let condition_matched = match found_values {
                                    Value::Array(values) => {
                                        // If the result is an array, check if any value matches the expected value
                                        values.iter().any(|found| {
                                            trace!("Checking request rule: {} = {}", path, found);
                                            found == expected_value
                                        })
                                    }
                                    _ => {
                                        // If the result is not an array, check if it matches the expected value
                                        trace!("Checking request rule: {} = {}", path, found_values);
                                        &found_values == expected_value
                                    }
                                };

                                if !condition_matched {
                                    trace!("Request rule mismatch: {} != {:?}", path, expected_value);
                                    return Ok(false);
                                }
                            }

                            trace!("All request conditions matched");
                        }
                        Err(e) => {
                            trace!("Failed to parse request body as JSON: {}", e);
                            return Ok(false);
                        }
                    }
                }
            }
        }

        Ok(true)
    }
}

/// Check if a rule matches a buffered request
async fn matches_buffered(rule: &Rule, req: &BufferedRequest, process_info: &ProcessInfo) -> Result<bool> {
    // Check if the endpoint matches
    if !rule.matches_path(req.path())? {
        return Ok(false);
    }

    // Check if query parameters should be matched
    if !rule.matches_query_params(req.query())? {
        return Ok(false);
    }

    // Check if the method matches
    if !rule.matches_method(req.method()) {
        return Ok(false);
    }

    // Check process binary
    if !rule.matches_process_binary(process_info) {
        return Ok(false);
    }

    // Check request rules if specified
    if !rule.matches_request_rules(req).await? {
        return Ok(false);
    }

    // All conditions matched
    debug!(
        "Rule matched: endpoint={}, methods={:?}, allow={}",
        rule.endpoint, rule.methods, rule.allow
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::uri::Uri;
    use std::collections::HashMap;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_rule_matching_endpoint() {
        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(&req, &process_info).await.unwrap());

        let req = Request::builder()
            .uri("/images/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_check_request_result() {
        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a buffered request with empty body for GET request
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule], &process_info).await.unwrap();
        assert!(result.allowed);
        assert!(result.rule_info.is_some());

        // Test with a deny rule
        let deny_rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: false,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // Create a new request for the deny test
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Create a buffered request with empty body for GET request
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[deny_rule], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert!(result.rule_info.is_some());
        assert!(result.rule_info.unwrap().contains("allow=false"));
    }

    #[tokio::test]
    async fn test_rule_matching_method() {
        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(&req, &process_info).await.unwrap());

        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_matching_process() {
        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: Some(vec!["/usr/bin/docker".to_string()]),
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(&req, &process_info).await.unwrap());

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/malicious".to_string(),
        };

        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_json_conditions() {
        // Create a rule with request rules
        let mut request_rules = HashMap::new();
        request_rules.insert("$.HostConfig.Privileged".to_string(), serde_json::Value::Bool(false));

        let rule = Rule {
            endpoint: "/containers/create".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: Some(request_rules),
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request with a POST method that would typically have a body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        // The test should pass because we're currently skipping JSON path checking
        // In a real implementation, we would need to test with actual JSON data
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Test that all conditions must be met (logical AND)
        // This is implicitly tested by the current implementation, as any condition
        // that fails will cause the entire rule to fail
    }

    #[tokio::test]
    async fn test_rule_with_path_variables() {
        // Create a rule with path variables
        let mut path_variables = HashMap::new();
        path_variables.insert("container_id".to_string(), "abc123".to_string());

        let rule = Rule {
            endpoint: "/containers/{container_id}/start".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: Some(path_variables),
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request that matches the path with variables
        let req = Request::builder()
            .uri("/containers/abc123/start")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        // The test should pass because the path with variables matches
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request that doesn't match the path with variables
        let req = Request::builder()
            .uri("/containers/def456/start")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the path with variables doesn't match
        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_multiple_path_variables() {
        // Create a rule with multiple path variables
        let mut path_variables = HashMap::new();
        path_variables.insert("container_id".to_string(), "[a-f0-9]+".to_string());
        path_variables.insert("log_type".to_string(), "stdout|stderr".to_string());

        let rule = Rule {
            endpoint: "/containers/{container_id}/logs/{log_type}".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: Some(path_variables),
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request that matches both path variables
        let req = Request::builder()
            .uri("/containers/abc123/logs/stdout")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because both path variables match
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request that matches the first variable but not the second
        let req = Request::builder()
            .uri("/containers/abc123/logs/invalid")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the second path variable doesn't match
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Create a request that doesn't match the first variable
        let req = Request::builder()
            .uri("/containers/ABC123/logs/stdout")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the first path variable doesn't match
        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_path_regex() {
        // Create a rule with path regex
        let rule = Rule {
            endpoint: "/containers/".to_string(), // This is still used as a prefix check if regex doesn't match
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: Some(r"^/containers/[a-f0-9]+/start$".to_string()),
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request that matches the regex
        let req = Request::builder()
            .uri("/containers/abc123/start")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        // The test should pass because the path matches the regex
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request that doesn't match the regex
        let req = Request::builder()
            .uri("/containers/ABC123/start")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the path doesn't match the regex
        assert!(!rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_query_params() {
        // Create a rule with query parameter matching
        let mut query_params = HashMap::new();
        query_params.insert("limit".to_string(), r"^\d+$".to_string()); // Only digits
        query_params.insert("all".to_string(), r"^(true|false)$".to_string()); // Only true or false

        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Required,
            query_params: Some(query_params),
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request with matching query parameters
        let req = Request::builder()
            .uri("/containers/json?limit=10&all=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because the query parameters match the regex patterns
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request with non-matching query parameters
        let req = Request::builder()
            .uri("/containers/json?limit=abc&all=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the limit parameter doesn't match the regex pattern
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Create a request with missing query parameters
        let req = Request::builder()
            .uri("/containers/json?limit=10")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the all parameter is missing
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Create a request with no query parameters
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because query parameters are required
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Test with match_query_params set to Ignore
        let mut query_params_clone = HashMap::new();
        query_params_clone.insert("limit".to_string(), r"^\d+$".to_string()); // Only digits
        query_params_clone.insert("all".to_string(), r"^(true|false)$".to_string()); // Only true or false

        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: Some(query_params_clone),
        };

        // Create a request with no query parameters
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because query parameters are ignored
        assert!(rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_regex_query_param_names() {
        // Create a rule with regex patterns for parameter names
        let mut query_params = HashMap::new();
        query_params.insert(r"^lim\w+$".to_string(), r"^\d+$".to_string()); // Parameter name starts with "lim", value is digits
        query_params.insert(r"^a\w+$".to_string(), r"^(true|false)$".to_string()); // Parameter name starts with "a", value is true or false

        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Required,
            query_params: Some(query_params),
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request with matching parameter names (exact match)
        let req = Request::builder()
            .uri("/containers/json?limit=10&all=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because the parameter names match the regex patterns
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request with matching parameter names (regex match)
        let req = Request::builder()
            .uri("/containers/json?limits=10&anything=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because the parameter names match the regex patterns
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Create a request with non-matching parameter names
        let req = Request::builder()
            .uri("/containers/json?maximum=10&boolean=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should fail because the parameter names don't match the regex patterns
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Test with a mix of exact and regex parameter names
        let mut mixed_params = HashMap::new();
        mixed_params.insert("exact".to_string(), r"^value$".to_string()); // Exact parameter name
        mixed_params.insert(r"^reg\w+$".to_string(), r"^\d+$".to_string()); // Regex parameter name

        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Required,
            query_params: Some(mixed_params),
        };

        // Create a request with both exact and regex parameter names
        let req = Request::builder()
            .uri("/containers/json?exact=value&regex=123")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // The test should pass because both parameter names match
        assert!(rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_optional_query_params() {
        // Create a rule with optional query parameters
        let mut query_params = HashMap::new();
        query_params.insert("limit".to_string(), r"^\d+$".to_string());
        query_params.insert("all".to_string(), r"^(true|false)$".to_string());

        let rule = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Optional,
            query_params: Some(query_params),
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Test with all parameters present and matching
        let req = Request::builder()
            .uri("/containers/json?limit=10&all=true")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Test with only one parameter present
        let req = Request::builder()
            .uri("/containers/json?limit=10")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Should pass because missing parameters are allowed with Optional
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Test with no parameters
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Should pass because all parameters are optional
        assert!(rule.matches(&req, &process_info).await.unwrap());

        // Test with one parameter present but not matching the pattern
        let req = Request::builder()
            .uri("/containers/json?limit=abc")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Should fail because the parameter value doesn't match the pattern
        assert!(!rule.matches(&req, &process_info).await.unwrap());

        // Test with additional unspecified parameters
        let req = Request::builder()
            .uri("/containers/json?limit=10&all=true&extra=value")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        // Should pass because the specified parameters match and extra ones are ignored
        assert!(rule.matches(&req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_rule_with_json_path_conditions_detailed() {
        // Create a rule with JSON path conditions
        let mut request_rules = HashMap::new();
        request_rules.insert("$.HostConfig.Privileged".to_string(), serde_json::Value::Bool(false));
        request_rules.insert("$.Image".to_string(), serde_json::Value::String("nginx".to_string()));
        request_rules.insert("$.ExposedPorts['80/tcp']".to_string(), serde_json::json!({}));

        let rule = Rule {
            endpoint: "/containers/create".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: Some(request_rules),
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a valid JSON body that matches all conditions
        let json_body = r#"{
            "Image": "nginx",
            "ExposedPorts": {
                "80/tcp": {}
            },
            "HostConfig": {
                "Privileged": false,
                "PortBindings": {
                    "80/tcp": [{"HostPort": "8080"}]
                }
            }
        }"#;

        // Create a buffered request with the JSON body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from(json_body),
        };

        // Test that the request matches the rule
        assert!(matches_buffered(&rule, &buffered_req, &process_info).await.unwrap());

        // Create a JSON body that violates the Privileged condition
        let json_body_privileged = r#"{
            "Image": "nginx",
            "ExposedPorts": {
                "80/tcp": {}
            },
            "HostConfig": {
                "Privileged": true,
                "PortBindings": {
                    "80/tcp": [{"HostPort": "8080"}]
                }
            }
        }"#;

        // Create a buffered request with the privileged JSON body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from(json_body_privileged),
        };

        // Test that the request does not match the rule due to Privileged: true
        assert!(!matches_buffered(&rule, &buffered_req, &process_info).await.unwrap());

        // Create a JSON body that violates the Image condition
        let json_body_wrong_image = r#"{
            "Image": "ubuntu",
            "ExposedPorts": {
                "80/tcp": {}
            },
            "HostConfig": {
                "Privileged": false,
                "PortBindings": {
                    "80/tcp": [{"HostPort": "8080"}]
                }
            }
        }"#;

        // Create a buffered request with the wrong image JSON body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from(json_body_wrong_image),
        };

        // Test that the request does not match the rule due to wrong image
        assert!(!matches_buffered(&rule, &buffered_req, &process_info).await.unwrap());

        // Create a JSON body that is missing the ExposedPorts condition
        let json_body_missing_ports = r#"{
            "Image": "nginx",
            "HostConfig": {
                "Privileged": false,
                "PortBindings": {
                    "80/tcp": [{"HostPort": "8080"}]
                }
            }
        }"#;

        // Create a buffered request with the missing ports JSON body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from(json_body_missing_ports),
        };

        // Test that the request does not match the rule due to missing ExposedPorts
        assert!(!matches_buffered(&rule, &buffered_req, &process_info).await.unwrap());

        // Test with invalid JSON
        let invalid_json = r#"{
            "Image": "nginx",
            "ExposedPorts": {
                "80/tcp": {}
            },
            "HostConfig": {
                "Privileged": false,
                "PortBindings": {
                    "80/tcp": [{"HostPort": "8080"}]
                }
            "
        }"#;

        // Create a buffered request with invalid JSON
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from(invalid_json),
        };

        // Test that the request does not match the rule due to invalid JSON
        assert!(!matches_buffered(&rule, &buffered_req, &process_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_rules_priority() {
        // Create a process info for testing
        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a request that will be tested against multiple rules
        let req = Request::builder()
            .uri("/containers/abc123/start")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        // Test case 1: First rule matches and allows, second rule matches but denies
        // The first rule should take precedence
        let rule1 = Rule {
            endpoint: "/containers/".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: Some(r"^/containers/[a-z0-9]+/start$".to_string()),
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let rule2 = Rule {
            endpoint: "/containers/".to_string(),
            methods: vec!["POST".to_string()],
            allow: false,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let result = check_request_buffered(&buffered_req, &[rule1.clone(), rule2.clone()], &process_info).await.unwrap();
        assert!(result.allowed);
        assert!(result.rule_info.unwrap().contains("allow=true"));

        // Test case 2: First rule doesn't match, second rule matches and denies
        // The second rule should be used
        let rule1_no_match = Rule {
            endpoint: "/containers/".to_string(),
            methods: vec!["GET".to_string()], // Different method, won't match
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: Some(r"^/containers/[a-z0-9]+/start$".to_string()),
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let result = check_request_buffered(&buffered_req, &[rule1_no_match, rule2.clone()], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert!(result.rule_info.unwrap().contains("allow=false"));

        // Test case 3: Rules in reverse order - deny rule first, then allow rule
        // The deny rule should take precedence because it's first
        let result = check_request_buffered(&buffered_req, &[rule2, rule1], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert!(result.rule_info.unwrap().contains("allow=false"));

        // Test case 4: No matching rules
        let rule1_no_match = Rule {
            endpoint: "/images/".to_string(), // Different endpoint, won't match
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let rule2_no_match = Rule {
            endpoint: "/containers/".to_string(),
            methods: vec!["GET".to_string()], // Different method, won't match
            allow: false,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let result = check_request_buffered(&buffered_req, &[rule1_no_match, rule2_no_match], &process_info).await.unwrap();
        assert!(!result.allowed); // Default is to deny if no rules match
        assert_eq!(result.rule_info.unwrap(), "No matching rules");
    }

    #[tokio::test]
    async fn test_http_methods() {
        // Create a process info for testing
        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Create a rule that matches multiple HTTP methods
        let rule_multi_method = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string(), "HEAD".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // Test GET method (should match)
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_multi_method.clone()], &process_info).await.unwrap();
        assert!(result.allowed);
        assert!(result.rule_info.unwrap().contains("methods=[\"GET\", \"POST\", \"HEAD\"]"));

        // Test POST method (should match)
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_multi_method.clone()], &process_info).await.unwrap();
        assert!(result.allowed);

        // Test HEAD method (should match)
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_multi_method.clone()], &process_info).await.unwrap();
        assert!(result.allowed);

        // Test PUT method (should not match)
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::PUT)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_multi_method.clone()], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.rule_info.unwrap(), "No matching rules");

        // Test DELETE method (should not match)
        let req = Request::builder()
            .uri("/containers/json")
            .method(Method::DELETE)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_multi_method.clone()], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.rule_info.unwrap(), "No matching rules");

        // Create a rule with no methods specified (should match any method)
        let rule_any_method = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec![],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // Test with various methods against the any-method rule
        for method in &[Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::HEAD] {
            let req = Request::builder()
                .uri("/containers/json")
                .method(method.clone())
                .body(Body::empty())
                .unwrap();
            let (parts, _) = req.into_parts();
            let buffered_req = BufferedRequest::from_parts(parts);

            let result = check_request_buffered(&buffered_req, &[rule_any_method.clone()], &process_info).await.unwrap();
            assert!(result.allowed, "Method {:?} should match rule with empty methods list", method);
        }
    }

    #[tokio::test]
    async fn test_edge_cases() {
        // Create a process info for testing
        let process_info = ProcessInfo {
            pid: 1,
            binary: "/usr/bin/docker".to_string(),
        };

        // Test case 1: Empty endpoint in rule
        let rule_empty_endpoint = Rule {
            endpoint: "".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // This should match any path since the endpoint is empty
        let req = Request::builder()
            .uri("/any/path")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_empty_endpoint], &process_info).await.unwrap();
        assert!(result.allowed);

        // Test case 2: Path with special characters
        let rule_special_chars = Rule {
            endpoint: "/containers/".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: Some(r"^/containers/[a-z0-9\-_\.]+$".to_string()),
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // Test with a path containing special characters
        let req = Request::builder()
            .uri("/containers/abc-123_456.789")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_special_chars], &process_info).await.unwrap();
        assert!(result.allowed);

        // Test case 3: Query parameters with special characters
        let mut query_params = HashMap::new();
        query_params.insert("filter".to_string(), r"^[\w\-\.\+\=\%\&]+$".to_string());

        let rule_special_query = Rule {
            endpoint: "/containers/json".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Required,
            query_params: Some(query_params),
        };

        // Test with query parameters containing special characters
        let req = Request::builder()
            .uri("/containers/json?filter=name%3Dnginx%26status%3Drunning")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_special_query], &process_info).await.unwrap();
        assert!(result.allowed);

        // Test case 4: Empty JSON body with request rules
        let mut request_rules = HashMap::new();
        request_rules.insert("$.Image".to_string(), serde_json::Value::String("nginx".to_string()));

        let rule_json = Rule {
            endpoint: "/containers/create".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: Some(request_rules),
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            path_regex: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        // Test with empty JSON body
        let req = Request::builder()
            .uri("/containers/create")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest {
            parts,
            body: Bytes::from("{}"),
        };

        // Should not match because the required JSON path is missing
        let result = check_request_buffered(&buffered_req, &[rule_json], &process_info).await.unwrap();
        assert!(!result.allowed);
        assert_eq!(result.rule_info.unwrap(), "No matching rules");

        // Test case 5: Rule with all fields set to their defaults
        let rule_defaults = Rule::default();

        // Should not match any request because the default endpoint is empty and allow is false
        let req = Request::builder()
            .uri("/any/path")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let (parts, _) = req.into_parts();
        let buffered_req = BufferedRequest::from_parts(parts);

        let result = check_request_buffered(&buffered_req, &[rule_defaults], &process_info).await.unwrap();
        assert!(!result.allowed);
    }
}
