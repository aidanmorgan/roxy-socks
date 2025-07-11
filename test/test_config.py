import pytest
from typing import Any
from config_model import RoxyConfig, Rule, QueryParamMatch


def test_config_generation() -> None:
    """Test that the configuration generation mechanism works correctly."""
    # Create a sample RoxyConfig model for testing
    config_model = RoxyConfig(rules=[
        Rule(
            endpoint="/containers/json",
            methods=["GET"],
            allow=True
        )
    ])

    # Verify that the configuration is a valid RoxyConfig object
    assert isinstance(config_model, RoxyConfig)

    # Verify that the configuration has at least one rule
    assert len(config_model.rules) > 0

    # Verify that the configuration can be converted to YAML
    yaml_str = config_model.to_yaml()
    assert isinstance(yaml_str, str)
    assert "rules:" in yaml_str

    # Verify that the configuration can be parsed back from YAML
    config_from_yaml = RoxyConfig.from_yaml(yaml_str)
    assert isinstance(config_from_yaml, RoxyConfig)
    assert len(config_from_yaml.rules) == len(config_model.rules)


def test_query_param_match() -> None:
    """Test that the query parameter matching functionality works correctly."""
    # Create a rule with required query parameters
    rule_required = Rule(
        endpoint="/containers/json",
        methods=["GET"],
        allow=True,
        match_query_params=QueryParamMatch.REQUIRED,
        query_params={"limit": r"^\d+$", "all": r"^(true|false)$"}
    )

    # Verify that the rule has the correct match_query_params value
    assert rule_required.match_query_params == QueryParamMatch.REQUIRED

    # Verify that the rule has the correct query_params
    assert rule_required.query_params is not None
    assert "limit" in rule_required.query_params
    assert "all" in rule_required.query_params

    # Create a rule with optional query parameters
    rule_optional = Rule(
        endpoint="/containers/json",
        methods=["GET"],
        allow=True,
        match_query_params=QueryParamMatch.OPTIONAL,
        query_params={"limit": r"^\d+$", "all": r"^(true|false)$"}
    )

    # Verify that the rule has the correct match_query_params value
    assert rule_optional.match_query_params == QueryParamMatch.OPTIONAL

    # Create a rule with ignored query parameters (default)
    rule_ignore = Rule(
        endpoint="/containers/json",
        methods=["GET"],
        allow=True
    )

    # Verify that the rule has the default match_query_params value
    assert rule_ignore.match_query_params == QueryParamMatch.IGNORE
    assert rule_ignore.query_params is None

    # Test serialization and deserialization of rules with query parameter matching
    config_model = RoxyConfig(rules=[rule_required, rule_optional, rule_ignore])
    yaml_str = config_model.to_yaml()

    # Verify that the YAML contains the query parameter matching settings
    assert "match_query_params: required" in yaml_str
    assert "match_query_params: optional" in yaml_str
    assert "limit: ^\\d+$" in yaml_str
    assert "all: ^(true|false)$" in yaml_str

    # Parse the YAML back into a RoxyConfig object
    config_from_yaml = RoxyConfig.from_yaml(yaml_str)

    # Verify that the parsed rules have the correct query parameter matching settings
    assert config_from_yaml.rules[0].match_query_params == QueryParamMatch.REQUIRED
    assert config_from_yaml.rules[1].match_query_params == QueryParamMatch.OPTIONAL
    assert config_from_yaml.rules[2].match_query_params == QueryParamMatch.IGNORE

    # Verify that the parsed rules have the correct query parameters
    assert config_from_yaml.rules[0].query_params is not None
    assert "limit" in config_from_yaml.rules[0].query_params
    assert "all" in config_from_yaml.rules[0].query_params
    assert config_from_yaml.rules[1].query_params is not None
    assert "limit" in config_from_yaml.rules[1].query_params
    assert "all" in config_from_yaml.rules[1].query_params
    assert config_from_yaml.rules[2].query_params is None
