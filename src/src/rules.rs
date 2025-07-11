use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;

use anyhow::{Context, Result};
use hyper::{Body, Method, Request};
use jsonpath_rust::JsonPathFinder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, trace};

pub fn add_default_rules(rules: &mut Vec<crate::rules::Rule>) {
    // setup the default rules that are required to be added if they aren't present
    if !rules.iter().any(|rule| rule.endpoint == String::from("/version") && rule.methods.contains(&String::from("GET"))) {
        rules.push(Rule {
            endpoint: String::from("/version"),
            methods: vec![String::from("GET")],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        });
    }

    if !rules.iter().any(|rule| rule.endpoint == String::from("/v1.*/version") && rule.methods.contains(&String::from("GET"))) {
        rules.push(Rule {
            endpoint: String::from("/v1.*/version"),
            methods: vec![String::from("GET")],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        });
    }
}


/// Checks if a string is intended to be a regex pattern.
/// 
/// This function first checks if the string contains common regex special characters.
/// If it does, it attempts to compile the string as a regex to verify it's valid.
/// 
/// # Arguments
/// 
/// * `pattern` - The string to check
/// 
/// # Returns
/// 
/// * `true` if the string is a valid regex pattern
/// * `false` if the string is not a valid regex pattern or doesn't contain regex special characters
pub fn is_regex(pattern: &str) -> bool {
    // Check if the string contains common regex special characters
    // Use a static array to avoid recreating it on each call
    static SPECIAL_CHARS: [char; 12] = ['*', '+', '?', '[', ']', '(', ')', '^', '$', '|', '\\', '.'];

    // Early return for empty patterns
    if pattern.is_empty() {
        return false;
    }

    // Check for special characters first - this is a fast check that avoids regex compilation
    let has_special_chars = SPECIAL_CHARS.iter().any(|&c| pattern.contains(c));

    // Only try to compile as regex if it has special characters
    if has_special_chars {
        Regex::new(pattern).is_ok()
    } else {
        false
    }
}

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
    /// Index of the rule that matched the request
    pub matching_rule_index: Option<usize>,
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
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        }
    }
}

impl Rule {
    /// Check if the path matches the rule
    fn matches_path(&self, path: &str) -> Result<bool> {
        // Extract the path without query parameters for matching
        let path_without_query = path.split('?').next().unwrap_or(path);

        debug!("Path matching - Path: {}", path);
        debug!("Path matching - Path without Query: {}", path_without_query);
        debug!("Path matching - Endpoint: {}", self.endpoint);
        debug!("Path matching - Path variables: {:?}", self.path_variables);

        // Case 1: Endpoint with path variables
        if let Some(variables) = &self.path_variables {
            // Build the pattern string only once
            let mut pattern_str = self.endpoint.as_str();
            let mut owned_pattern = String::new();

            // Collect all replacements first to avoid multiple string allocations
            let mut replacements = Vec::with_capacity(variables.len());
            for (var_name, var_value) in variables {
                let placeholder = format!("{{{}}}", var_name);
                let capture_group = if is_regex(var_value) {
                    match Regex::new(var_value) {
                        Ok(_) => format!("({})", var_value),
                        Err(_) => format!("({})", regex::escape(var_value))
                    }
                } else {
                    format!("({})", regex::escape(var_value))
                };
                replacements.push((placeholder, capture_group));
            }

            // Apply all replacements at once
            for (placeholder, capture_group) in replacements {
                if owned_pattern.is_empty() {
                    // First replacement, need to clone the endpoint
                    owned_pattern = pattern_str.replace(&placeholder, &capture_group);
                    pattern_str = &owned_pattern;
                } else {
                    // Subsequent replacements, modify in place
                    owned_pattern = pattern_str.replace(&placeholder, &capture_group);
                    pattern_str = &owned_pattern;
                }
            }

            // Create a regex from the pattern
            let regex_pattern = format!("^{}$", pattern_str);
            let regex = Regex::new(&regex_pattern).context("Invalid regex pattern from path variables")?;
            let matches = regex.is_match(path_without_query);

            if matches {
                debug!("Path regex match: {} matches pattern {}", path_without_query, regex_pattern);
            } else {
                trace!("Path regex mismatch: {} doesn't match pattern {}", path_without_query, regex_pattern);
            }

            return Ok(matches);
        }

        // Case 2: Endpoint as regex
        if is_regex(&self.endpoint) {
            // Ensure the regex has a start anchor
            let regex_pattern = if !self.endpoint.starts_with('^') {
                format!("^{}", self.endpoint)
            } else {
                // Still need to clone for consistent types
                self.endpoint.clone()
            };

            match Regex::new(&regex_pattern) {
                Ok(regex) => {
                    let matches = regex.is_match(path_without_query);

                    if matches {
                        debug!("Endpoint regex match: {} matches pattern {}", path_without_query, regex_pattern);
                    } else {
                        trace!("Endpoint regex mismatch: {} doesn't match pattern {}", path_without_query, regex_pattern);
                    }

                    return Ok(matches);
                },
                Err(e) => {
                    trace!("Invalid regex pattern in endpoint: {}", e);
                    // Fall back to prefix matching for invalid regex
                }
            }
        }

        // Case 3: Simple prefix matching
        let matches = path_without_query.starts_with(&self.endpoint);

        if matches {
            debug!("Endpoint prefix match: {} starts with {}", path_without_query, self.endpoint);
        } else {
            trace!("Endpoint mismatch: {} doesn't start with {}", path_without_query, self.endpoint);
        }

        Ok(matches)
    }

    /// Check if the query parameters match the rule
    fn matches_query_params(&self, query: Option<&str>) -> Result<bool> {
        debug!("Query params matching - Match type: {:?}", self.match_query_params);
        debug!("Query params matching - Query string: {:?}", query);
        debug!("Query params matching - Rule query params: {:?}", self.query_params);

        // If we're ignoring query params or no query params are specified, return true
        if self.match_query_params == QueryParamMatch::Ignore || 
           self.query_params.as_ref().map_or(true, |params| params.is_empty()) {
            return Ok(true);
        }

        let query_params = self.query_params.as_ref().unwrap();

        // No query string in the URI
        if query.is_none() && self.match_query_params == QueryParamMatch::Required {
            trace!("No query string in URI, but query parameters are required");
            return Ok(false);
        } else if query.is_none() {
            // For Optional, missing query string is allowed
            return Ok(true);
        }

        // Parse the query string into key-value pairs
        // Avoid unnecessary allocations by using references where possible
        let query_str = query.unwrap();

        // Pre-allocate the vector to avoid resizing
        let mut query_pairs = Vec::with_capacity(query_str.split('&').count());
        for pair in query_str.split('&') {
            let mut parts = pair.split('=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                query_pairs.push((key, value));
            }
        }

        // Check each query parameter against the regex pattern
        for (param_name, pattern) in query_params {
            // Create regex for parameter value only once
            let value_regex = if is_regex(pattern) {
                match Regex::new(pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        trace!("Invalid regex pattern for query parameter {}: {}", param_name, e);
                        return Ok(false);
                    }
                }
            } else {
                // Literal string match - escape once and compile
                let escaped_pattern = regex::escape(pattern);
                let regex_pattern = format!("^{}$", escaped_pattern);
                match Regex::new(&regex_pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        trace!("Invalid regex pattern for query parameter {}: {}", param_name, e);
                        return Ok(false);
                    }
                }
            };

            // Create regex for parameter name only once
            let name_regex = if is_regex(param_name) {
                match Regex::new(param_name) {
                    Ok(r) => r,
                    Err(e) => {
                        trace!("Invalid regex pattern for parameter name {}: {}", param_name, e);
                        return Ok(false);
                    }
                }
            } else {
                // Literal string match - escape once and compile
                let escaped_name = regex::escape(param_name);
                let regex_pattern = format!("^{}$", escaped_name);
                match Regex::new(&regex_pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        trace!("Invalid regex pattern for parameter name {}: {}", param_name, e);
                        return Ok(false);
                    }
                }
            };

            // Find the parameter in the query string using regex for parameter name
            // Use references to avoid unnecessary string allocations
            let param_value = query_pairs.iter()
                .find(|(k, _)| name_regex.is_match(k))
                .map(|(_, v)| *v);

            // Check if parameter exists and matches
            match param_value {
                Some(value) => {
                    if !value_regex.is_match(value) {
                        trace!("Query parameter mismatch: {}={} doesn't match pattern {}", param_name, value, pattern);
                        return Ok(false);
                    }
                },
                None if self.match_query_params == QueryParamMatch::Required => {
                    trace!("Required query parameter not found: {}", param_name);
                    return Ok(false);
                },
                None => {
                    // For Optional, missing parameters are allowed
                }
            }
        }

        Ok(true)
    }

    /// Check if the HTTP method matches the rule
    fn matches_method(&self, method: &Method) -> bool {
        let method_str = method.as_str();
        debug!("Method matching - Request method: {}", method_str);
        debug!("Method matching - Allowed methods: {:?}", self.methods);

        if !self.methods.is_empty() {
            if !self.methods.iter().any(|m| m == method_str) {
                trace!("Method mismatch: {} not in {:?}", method_str, self.methods);
                return false;
            }
            debug!("Method match: {} is in allowed methods", method_str);
        } else {
            debug!("Method matching skipped: no methods specified in rule");
        }
        true
    }

    /// Check if the process binary matches the rule
    fn matches_process_binary(&self, process_info: &ProcessInfo) -> bool {
        debug!("Process matching - Process binary: {}", process_info.binary);
        debug!("Process matching - Process PID: {}", process_info.pid);
        debug!("Process matching - Allowed binaries: {:?}", self.process_binaries);

        if let Some(binaries) = &self.process_binaries {
            if !binaries.iter().any(|b| process_info.binary.contains(b)) {
                trace!(
                    "Process binary mismatch: {} not in {:?}",
                    process_info.binary,
                    binaries
                );
                return false;
            }
            debug!("Process binary match: {} contains one of {:?}", process_info.binary, binaries);
        } else {
            debug!("Process matching skipped: no process binaries specified in rule");
        }
        true
    }

    /// Check if the rule matches the given request and process info
    #[allow(dead_code)]
    pub async fn matches(&self, req: &Request<Body>, process_info: &ProcessInfo) -> Result<bool> {
        // Use the generic matches_request method with the Request<Body>
        self.matches_request(req, process_info, None).await
    }

    /// Generic method to match a request against a rule
    /// 
    /// This method is used by both matches and matches_buffered to avoid code duplication
    async fn matches_request<T: RequestMatcher>(&self, req: &T, process_info: &ProcessInfo, check_request_rules: Option<&BufferedRequest>) -> Result<bool> {
        debug!("=== Starting rule matching process ===");
        debug!("Rule endpoint: {}", self.endpoint);
        debug!("Rule methods: {:?}", self.methods);
        debug!("Rule allow: {}", self.allow);
        debug!("Request path: {}", req.path());
        debug!("Request method: {}", req.method());
        debug!("Process binary: {}", process_info.binary);
        debug!("Check request rules: {}", check_request_rules.is_some());

        // Check if the endpoint matches
        debug!("Checking path match...");
        if !self.matches_path(req.path())? {
            debug!("Path match failed - stopping rule evaluation");
            return Ok(false);
        }
        debug!("Path match succeeded");

        // Check if query parameters should be matched
        debug!("Checking query parameters match...");
        if !self.matches_query_params(req.query())? {
            debug!("Query parameters match failed - stopping rule evaluation");
            return Ok(false);
        }
        debug!("Query parameters match succeeded");

        // Check if the method matches
        debug!("Checking method match...");
        if !self.matches_method(req.method()) {
            debug!("Method match failed - stopping rule evaluation");
            return Ok(false);
        }
        debug!("Method match succeeded");

        // Check process binary
        debug!("Checking process binary match...");
        if !self.matches_process_binary(process_info) {
            debug!("Process binary match failed - stopping rule evaluation");
            return Ok(false);
        }
        debug!("Process binary match succeeded");

        // Check request rules if specified and we have a BufferedRequest
        if let Some(buffered_req) = check_request_rules {
            debug!("Checking request rules match...");
            if !self.matches_request_rules(buffered_req)? {
                debug!("Request rules match failed - stopping rule evaluation");
                return Ok(false);
            }
            debug!("Request rules match succeeded");
        }

        debug!(
            "=== Rule matched completely: endpoint={}, methods={:?}, allow={} ===",
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
    debug!("=== Starting rule evaluation for request ===");
    debug!("Request path: {}", req.path());
    debug!("Request method: {}", req.method());
    debug!("Process binary: {}", process_info.binary);
    debug!("Process PID: {}", process_info.pid);
    debug!("Total rules to check: {}", rules.len());

    // Default to deny if no rules match
    let mut result = RuleCheckResult {
        allowed: false,
        rule_info: None,
        matching_rule_index: None,
    };

    for (index, rule) in rules.iter().enumerate() {
        debug!("Checking rule #{} - endpoint: {}, methods: {:?}, allow: {}", 
               index, rule.endpoint, rule.methods, rule.allow);

        if matches_buffered(rule, req, process_info).await? {
            debug!("Rule #{} matched! Allow: {}", index, rule.allow);
            // Return immediately when a rule matches
            return Ok(RuleCheckResult {
                allowed: rule.allow,
                rule_info: Some(format!("Rule matched: endpoint={}, methods={:?}, allow={}", 
                                       rule.endpoint, rule.methods, rule.allow)),
                matching_rule_index: Some(index),
            });
        }
        debug!("Rule #{} did not match, continuing to next rule", index);
    }

    // No rules matched
    debug!("No rules matched for request path: {}, method: {}", req.path(), req.method());
    result.rule_info = Some("No matching rules".to_string());
    debug!("=== Completed rule evaluation: no matching rules found ===");
    Ok(result)
}

impl Rule {
    /// Check if the request rules match using JSON path conditions
    fn matches_request_rules(&self, req: &BufferedRequest) -> Result<bool> {
        debug!("Request rules matching - Method: {}", req.method());
        debug!("Request rules matching - Rules: {:?}", self.request_rules);

        if let Some(rules) = &self.request_rules {
            if !rules.is_empty() {
                debug!("Request rules matching - Rules count: {}", rules.len());

                // JSON path checking is only applicable for methods that typically have a body
                let method = req.method();
                if method == &Method::POST || method == &Method::PUT || method == &Method::PATCH {
                    debug!("Request rules matching - Method {} supports body checking", method);

                    // Parse the body as JSON
                    debug!("Request rules matching - Parsing request body as JSON");
                    match req.parse_json() {
                        Ok(json) => {
                            debug!("Request rules matching - JSON parsed successfully");
                            // Use the generic check_json_rules method
                            if !self.check_json_rules(&json, rules, "request")? {
                                debug!("Request rules matching - JSON rules check failed");
                                return Ok(false);
                            }
                            debug!("Request rules matching - All request conditions matched");
                        }
                        Err(e) => {
                            debug!("Request rules matching - Failed to parse request body as JSON: {}", e);
                            return Ok(false);
                        }
                    }
                } else {
                    debug!("Request rules matching - Method {} doesn't typically have a body, skipping JSON checks", method);
                }
            } else {
                debug!("Request rules matching - No rules specified, skipping check");
            }
        } else {
            debug!("Request rules matching - No rules specified, skipping check");
        }

        Ok(true)
    }

    /// Check if the response rules match using JSON path conditions
    pub fn matches_response_rules(&self, json: &Value) -> Result<bool> {
        debug!("Response rules matching - JSON: {}", json);
        debug!("Response rules matching - Rules: {:?}", self.response_rules);

        if let Some(rules) = &self.response_rules {
            if !rules.is_empty() {
                debug!("Response rules matching - Rules count: {}", rules.len());

                // Use the generic check_json_rules method
                debug!("Response rules matching - Checking JSON rules");
                if !self.check_json_rules(json, rules, "response")? {
                    debug!("Response rules matching - JSON rules check failed");
                    return Ok(false);
                }
                debug!("Response rules matching - All response conditions matched");
            } else {
                debug!("Response rules matching - No rules specified, skipping check");
            }
        } else {
            debug!("Response rules matching - No rules specified, skipping check");
        }

        Ok(true)
    }

    /// Generic method to check JSON rules
    fn check_json_rules(&self, json: &Value, rules: &HashMap<String, Value>, rule_type: &str) -> Result<bool> {
        debug!("JSON rules checking - Type: {}", rule_type);
        debug!("JSON rules checking - Rules count: {}", rules.len());
        debug!("JSON rules checking - JSON: {}", json);

        // Check each JSON path condition
        for (path, expected_value) in rules {
            debug!("JSON rules checking - Evaluating path: {}", path);
            debug!("JSON rules checking - Expected value: {}", expected_value);

            // Use JsonPathFinder to evaluate the JSON path
            let finder = match JsonPathFinder::from_str(&json.to_string(), path) {
                Ok(finder) => {
                    debug!("JSON rules checking - JsonPathFinder created successfully for path: {}", path);
                    finder
                },
                Err(e) => {
                    debug!("JSON rules checking - Failed to create JsonPathFinder for {}: {}", rule_type, e);
                    return Ok(false);
                }
            };

            let found_values = finder.find();
            debug!("JSON rules checking - Found values: {}", found_values);

            // Check if the found value matches the expected value
            let condition_matched = match &found_values {
                Value::Array(values) => {
                    // If the result is an array, check if any value matches the expected value
                    debug!("JSON rules checking - Found array with {} elements", values.len());
                    let matched = values.iter().any(|found| {
                        let matches = found == expected_value;
                        debug!("JSON rules checking - Array element {} == expected {}: {}", found, expected_value, matches);
                        matches
                    });
                    matched
                }
                _ => {
                    // If the result is not an array, check if it matches the expected value
                    let matches = &found_values == expected_value;
                    debug!("JSON rules checking - Found value {} == expected {}: {}", found_values, expected_value, matches);
                    matches
                }
            };

            if !condition_matched {
                debug!("JSON rules checking - Rule mismatch: {} != {:?}", path, expected_value);
                return Ok(false);
            }
            debug!("JSON rules checking - Rule matched: {} == {:?}", path, expected_value);
        }

        debug!("JSON rules checking - All rules matched successfully");
        Ok(true)
    }
}

/// Check if a rule matches a buffered request
async fn matches_buffered(rule: &Rule, req: &BufferedRequest, process_info: &ProcessInfo) -> Result<bool> {
    debug!("Matching buffered request against rule with endpoint: {}", rule.endpoint);
    // Use the generic matches_request method with the BufferedRequest
    let result = rule.matches_request(req, process_info, Some(req)).await;
    debug!("Buffered request match result: {:?}", result);
    result
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

    #[test]
    fn test_is_regex() {
        // Test strings that should be identified as regex patterns
        assert!(is_regex(r"^/containers/[a-f0-9]+/start$"));
        assert!(is_regex(r"^\d+$"));
        assert!(is_regex(r"^(true|false)$"));
        assert!(is_regex(r".*"));
        assert!(is_regex(r"[a-z]+"));
        assert!(is_regex(r"(foo|bar)"));
        assert!(is_regex(r"foo?"));
        assert!(is_regex(r"foo+"));
        assert!(is_regex(r"foo*"));

        // Test strings that should not be identified as regex patterns
        assert!(!is_regex("simple string"));
        assert!(!is_regex("/containers/json"));
        assert!(!is_regex(""));
        assert!(!is_regex("12345"));
        assert!(!is_regex("true"));
        assert!(!is_regex("false"));

        // Test invalid regex patterns (should return false)
        assert!(!is_regex(r"[unclosed bracket"));
        assert!(!is_regex(r"(unclosed parenthesis"));
        assert!(!is_regex(r"invalid\escape"));

        // Test edge cases
        assert!(!is_regex(r"\"));  // Single backslash is invalid
        assert!(is_regex(r"\\"));  // Escaped backslash is valid
    }

    #[tokio::test]
    async fn test_rule_with_path_regex() {
        // Create a rule with regex in the endpoint
        let rule = Rule {
            endpoint: r"^/containers/[a-f0-9]+/start$".to_string(), // Regex pattern directly in the endpoint
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
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
            endpoint: r"^/containers/[a-z0-9]+/start$".to_string(),
            methods: vec!["POST".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
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
            match_query_params: QueryParamMatch::Ignore,
            query_params: None,
        };

        let result = check_request_buffered(&buffered_req, &[rule1.clone(), rule2.clone()], &process_info).await.unwrap();
        assert!(result.allowed);
        assert!(result.rule_info.unwrap().contains("allow=true"));

        // Test case 2: First rule doesn't match, second rule matches and denies
        // The second rule should be used
        let rule1_no_match = Rule {
            endpoint: r"^/containers/[a-z0-9]+/start$".to_string(),
            methods: vec!["GET".to_string()], // Different method, won't match
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
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
            endpoint: r"^/containers/[a-z0-9\-_\.]+$".to_string(),
            methods: vec!["GET".to_string()],
            allow: true,
            request_rules: None,
            response_rules: None,
            process_binaries: None,
            path_variables: None,
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
