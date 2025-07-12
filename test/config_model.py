from typing import Dict, List, Optional, Union, Any, Literal
from pydantic import BaseModel, Field
from enum import Enum
import yaml


class QueryParamMatch(str, Enum):
    """Enum for controlling how query parameters are matched."""
    IGNORE = "ignore"
    REQUIRED = "required"
    OPTIONAL = "optional"


# Add a custom YAML representer for the QueryParamMatch enum
def represent_query_param_match(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data.value)

yaml.SafeDumper.add_representer(QueryParamMatch, represent_query_param_match)


class Rule(BaseModel):
    """Model for a single rule in the roxy-socks configuration."""
    endpoint: str
    methods: List[str]
    allow: bool = True
    process_binaries: Optional[List[str]] = None
    path_variables: Optional[Dict[str, str]] = None
    request_rules: Optional[Dict[str, Any]] = None
    response_rules: Optional[Dict[str, Any]] = None
    match_query_params: QueryParamMatch = QueryParamMatch.IGNORE
    query_params: Optional[Dict[str, str]] = None


class RoxyConfig(BaseModel):
    """Model for the roxy-socks configuration file."""
    rules: List[Rule] = Field(default_factory=list)
    timeout: int = 30  # Default to 30 seconds for tests

    def __init__(self, **data):
        """Initialize the configuration"""
        super().__init__(**data)


    def to_yaml(self) -> str:
        """Convert the configuration to YAML format."""
        import yaml
        # Use safe_dump to avoid any potential security issues
        return yaml.safe_dump(self.model_dump(exclude_none=True), sort_keys=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "RoxyConfig":
        """Create a configuration from a YAML string."""
        import yaml
        data = yaml.safe_load(yaml_str)
        return cls.model_validate(data)
