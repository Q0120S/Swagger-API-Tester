#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
yaml_lite.py - A minimal YAML parser for Jython
This is a fallback when PyYAML is not available.
Supports basic YAML features needed for Swagger/OpenAPI specs.
"""

import re
import json

class YamlLiteParser:
    """
    Minimal YAML parser that handles basic Swagger/OpenAPI structures.
    Does not support all YAML features, but covers common use cases.
    """
    
    def __init__(self):
        self.lines = []
        self.current_line = 0
        
    def load(self, yaml_string):
        """Parse YAML string and return dictionary"""
        self.lines = yaml_string.strip().split('\n')
        self.current_line = 0
        return self._parse_document()
        
    def _parse_document(self):
        """Parse the entire YAML document"""
        result = {}
        
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line].rstrip()
            
            # Skip empty lines and comments
            if not line or line.strip().startswith('#'):
                self.current_line += 1
                continue
                
            # Parse key-value pairs
            indent = len(line) - len(line.lstrip())
            key, value = self._parse_line(line.strip())
            
            if key:
                if value is not None:
                    result[key] = value
                else:
                    # Value is on next lines (nested structure)
                    self.current_line += 1
                    result[key] = self._parse_nested(indent + 2)
                    continue
                    
            self.current_line += 1
            
        return result
        
    def _parse_line(self, line):
        """Parse a single line for key-value pair"""
        # Handle key: value format
        match = re.match(r'^([^:]+):\s*(.*)$', line)
        if not match:
            return None, None
            
        key = match.group(1).strip()
        value_str = match.group(2).strip()
        
        # Empty value means nested content follows
        if not value_str:
            return key, None
            
        # Parse the value
        value = self._parse_value(value_str)
        return key, value
        
    def _parse_value(self, value_str):
        """Parse a value string into appropriate type"""
        # Remove quotes if present
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]
            
        # Check for boolean
        if value_str.lower() == 'true':
            return True
        elif value_str.lower() == 'false':
            return False
            
        # Check for null
        if value_str.lower() in ['null', 'none', '~']:
            return None
            
        # Check for number
        try:
            if '.' in value_str:
                return float(value_str)
            else:
                return int(value_str)
        except ValueError:
            pass
            
        # Check for array (inline)
        if value_str.startswith('[') and value_str.endswith(']'):
            return self._parse_inline_array(value_str)
            
        # Check for object (inline)
        if value_str.startswith('{') and value_str.endswith('}'):
            return self._parse_inline_object(value_str)
            
        # Default to string
        return value_str
        
    def _parse_nested(self, expected_indent):
        """Parse nested structure (object or array)"""
        if self.current_line >= len(self.lines):
            return {}
            
        first_line = self.lines[self.current_line].rstrip()
        if not first_line:
            return {}
            
        # Check if it's an array
        if first_line.lstrip().startswith('- '):
            return self._parse_array(expected_indent)
        else:
            return self._parse_object(expected_indent)
            
    def _parse_object(self, expected_indent):
        """Parse nested object"""
        result = {}
        
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line].rstrip()
            
            # Skip empty lines
            if not line:
                self.current_line += 1
                continue
                
            indent = len(line) - len(line.lstrip())
            
            # If indent is less than expected, we're done with this object
            if indent < expected_indent:
                break
                
            # Skip lines with wrong indentation
            if indent != expected_indent:
                self.current_line += 1
                continue
                
            # Parse the line
            key, value = self._parse_line(line.strip())
            
            if key:
                if value is not None:
                    result[key] = value
                else:
                    # Nested content
                    self.current_line += 1
                    result[key] = self._parse_nested(indent + 2)
                    continue
                    
            self.current_line += 1
            
        return result
        
    def _parse_array(self, expected_indent):
        """Parse array structure"""
        result = []
        
        while self.current_line < len(self.lines):
            line = self.lines[self.current_line].rstrip()
            
            # Skip empty lines
            if not line:
                self.current_line += 1
                continue
                
            indent = len(line) - len(line.lstrip())
            
            # If indent is less than expected, we're done
            if indent < expected_indent:
                break
                
            # Check for array item
            if line.lstrip().startswith('- '):
                item_str = line.lstrip()[2:].strip()
                
                if item_str:
                    # Inline value
                    result.append(self._parse_value(item_str))
                else:
                    # Nested structure follows
                    self.current_line += 1
                    nested = self._parse_nested(indent + 2)
                    result.append(nested)
                    continue
                    
            self.current_line += 1
            
        return result
        
    def _parse_inline_array(self, value_str):
        """Parse inline array like [1, 2, 3]"""
        content = value_str[1:-1].strip()
        if not content:
            return []
            
        # Simple split by comma (doesn't handle nested structures)
        items = []
        for item in content.split(','):
            item = item.strip()
            items.append(self._parse_value(item))
        return items
        
    def _parse_inline_object(self, value_str):
        """Parse inline object like {key: value}"""
        # This is a simplified version
        return {}

def load_yaml(yaml_string):
    """
    Load YAML string and return dictionary.
    This is the main entry point that mimics yaml.safe_load()
    """
    parser = YamlLiteParser()
    return parser.load(yaml_string)

def load_yaml_file(filepath):
    """Load YAML from file"""
    with open(filepath, 'r') as f:
        return load_yaml(f.read())

# Make it compatible with PyYAML interface
safe_load = load_yaml

if __name__ == "__main__":
    # Test the parser
    test_yaml = """
swagger: "2.0"
info:
  title: Test API
  version: 1.0.0
  description: A test API
host: api.example.com
basePath: /v1
schemes:
  - https
  - http
paths:
  /users:
    get:
      summary: Get users
      parameters:
        - name: limit
          in: query
          type: integer
          default: 10
      responses:
        200:
          description: Success
    """
    
    result = load_yaml(test_yaml)
    print(json.dumps(result, indent=2))
