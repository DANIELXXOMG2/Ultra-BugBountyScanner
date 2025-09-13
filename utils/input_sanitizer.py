#!/usr/bin/env python3
"""Input Sanitization Module for Ultra-BugBountyScanner.

Author: danielxxomg2
Description: Comprehensive input validation and sanitization for security compliance.
"""

import re
import os
from pathlib import Path
from typing import List, Optional, Union
from urllib.parse import urlparse

from .logger import get_logger

logger = get_logger()


class InputSanitizer:
    """Comprehensive input sanitization and validation class."""

    # Security patterns to detect and block
    DANGEROUS_PATTERNS = [
        r'[;&|`$(){}\[\]<>]',  # Shell injection characters
        r'\.\./',  # Path traversal
        r'\\\\',  # UNC paths
        r'file://',  # File protocol
        r'javascript:',  # JavaScript protocol
        r'data:',  # Data protocol
        r'vbscript:',  # VBScript protocol
        r'<script',  # Script tags
        r'</script>',  # Script tags
        r'eval\(',  # Code execution
        r'exec\(',  # Code execution
        r'system\(',  # System calls
        r'__import__',  # Python imports
        r'subprocess',  # Subprocess calls
    ]

    # Valid domain pattern (RFC compliant)
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )

    # Valid IP pattern (IPv4)
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    # Valid CIDR pattern
    CIDR_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
    )

    @classmethod
    def sanitize_string(cls, input_str: str, max_length: int = 256) -> str:
        """Sanitize a general string input.
        
        Args:
            input_str: The string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
            
        Raises:
            ValueError: If input contains dangerous patterns
        """
        if not isinstance(input_str, str):
            raise ValueError("Input must be a string")
            
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                logger.error(f"🚨 SECURITY: Dangerous pattern detected in input: {pattern}")
                raise ValueError(f"Input contains dangerous pattern: {pattern}")
        
        # Limit length
        if len(input_str) > max_length:
            logger.warning(f"⚠️  Input truncated from {len(input_str)} to {max_length} characters")
            input_str = input_str[:max_length]
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
        
        # Strip whitespace
        sanitized = sanitized.strip()
        
        return sanitized

    @classmethod
    def validate_domain(cls, domain: str) -> str:
        """Validate and sanitize a domain name.
        
        Args:
            domain: The domain to validate
            
        Returns:
            Validated domain
            
        Raises:
            ValueError: If domain is invalid
        """
        if not isinstance(domain, str):
            raise ValueError("Domain must be a string")
            
        # Basic sanitization
        domain = cls.sanitize_string(domain, max_length=253)  # RFC limit
        
        # Convert to lowercase
        domain = domain.lower()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(f"http://{domain}" if not domain.startswith('http') else domain)
            domain = parsed.netloc or parsed.path
        
        # Validate format
        if not cls.DOMAIN_PATTERN.match(domain) and not cls.IP_PATTERN.match(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Additional security checks
        if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            logger.warning(f"⚠️  Local/loopback domain detected: {domain}")
        
        # Check for private IP ranges
        if cls.IP_PATTERN.match(domain):
            octets = [int(x) for x in domain.split('.')]
            if (octets[0] == 10 or 
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168)):
                logger.warning(f"⚠️  Private IP address detected: {domain}")
        
        return domain

    @classmethod
    def validate_domains(cls, domains: List[str]) -> List[str]:
        """Validate a list of domains.
        
        Args:
            domains: List of domains to validate
            
        Returns:
            List of validated domains
        """
        if not isinstance(domains, list):
            raise ValueError("Domains must be a list")
            
        if len(domains) > 50:  # Reasonable limit
            logger.warning(f"⚠️  Large number of domains ({len(domains)}), limiting to 50")
            domains = domains[:50]
        
        validated_domains = []
        for domain in domains:
            try:
                validated_domain = cls.validate_domain(domain)
                validated_domains.append(validated_domain)
            except ValueError as e:
                logger.error(f"❌ Invalid domain '{domain}': {e}")
                continue
        
        if not validated_domains:
            raise ValueError("No valid domains provided")
            
        return validated_domains

    @classmethod
    def validate_output_path(cls, output_path: str) -> Path:
        """Validate and sanitize output path.
        
        Args:
            output_path: The output path to validate
            
        Returns:
            Validated Path object
            
        Raises:
            ValueError: If path is invalid or dangerous
        """
        if not isinstance(output_path, str):
            raise ValueError("Output path must be a string")
            
        # Basic sanitization
        output_path = cls.sanitize_string(output_path, max_length=4096)
        
        # Convert to Path object
        try:
            path = Path(output_path).resolve()
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid path: {e}")
        
        # Security checks
        path_str = str(path)
        
        # Check for path traversal attempts
        if '..' in path.parts:
            raise ValueError("Path traversal detected")
        
        # Check for system directories (basic protection)
        dangerous_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', 
                          'C:\\Windows', 'C:\\Program Files', 'C:\\System32']
        
        for dangerous in dangerous_paths:
            if path_str.lower().startswith(dangerous.lower()):
                raise ValueError(f"Access to system directory denied: {dangerous}")
        
        # Ensure path is within reasonable bounds
        if len(path.parts) > 20:  # Reasonable depth limit
            raise ValueError("Path too deep")
        
        return path

    @classmethod
    def validate_environment_variables(cls) -> dict:
        """Validate critical environment variables.
        
        Returns:
            Dictionary of validated environment variables
        """
        env_vars = {}
        
        # Discord webhook validation
        discord_webhook = os.getenv('DISCORD_WEBHOOK_URL', '').strip()
        if discord_webhook:
            if not discord_webhook.startswith('https://discord.com/api/webhooks/'):
                logger.warning("⚠️  Invalid Discord webhook URL format")
                discord_webhook = ''
            else:
                # Sanitize webhook URL
                try:
                    discord_webhook = cls.sanitize_string(discord_webhook, max_length=512)
                    env_vars['DISCORD_WEBHOOK_URL'] = discord_webhook
                except ValueError:
                    logger.error("❌ Discord webhook URL contains dangerous patterns")
        
        # Gemini API key validation
        gemini_key = os.getenv('GEMINI_API_KEY', '').strip()
        if gemini_key:
            if not gemini_key.startswith('AIza'):
                logger.warning("⚠️  Invalid Gemini API key format")
                gemini_key = ''
            else:
                # Basic validation - should be alphanumeric
                if re.match(r'^[A-Za-z0-9_-]+$', gemini_key):
                    env_vars['GEMINI_API_KEY'] = gemini_key
                else:
                    logger.error("❌ Gemini API key contains invalid characters")
        
        # Output directory validation
        output_dir = os.getenv('OUTPUT_DIR', 'output').strip()
        try:
            validated_output = cls.validate_output_path(output_dir)
            env_vars['OUTPUT_DIR'] = str(validated_output)
        except ValueError as e:
            logger.warning(f"⚠️  Invalid OUTPUT_DIR: {e}, using default 'output'")
            env_vars['OUTPUT_DIR'] = 'output'
        
        # Verbose mode validation
        verbose = os.getenv('VERBOSE', 'false').strip().lower()
        if verbose in ['true', '1', 'yes', 'on']:
            env_vars['VERBOSE'] = 'true'
        else:
            env_vars['VERBOSE'] = 'false'
        
        return env_vars

    @classmethod
    def validate_command_args(cls, args) -> dict:
        """Validate command line arguments.
        
        Args:
            args: Parsed arguments from argparse
            
        Returns:
            Dictionary of validated arguments
        """
        validated = {}
        
        # Validate domains
        if hasattr(args, 'domain') and args.domain:
            validated['domains'] = cls.validate_domains(args.domain)
        else:
            raise ValueError("No domains provided")
        
        # Validate output directory
        if hasattr(args, 'output') and args.output:
            validated['output_dir'] = cls.validate_output_path(args.output)
        else:
            validated['output_dir'] = Path('output')
        
        # Validate boolean flags
        validated['quick_mode'] = bool(getattr(args, 'quick', False))
        validated['verbose'] = bool(getattr(args, 'verbose', False))
        
        return validated