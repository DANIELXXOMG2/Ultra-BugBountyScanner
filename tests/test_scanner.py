#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ultra-BugBountyScanner Test Suite
Author: danielxxomg2
Version: 1.0.0
Description: Comprehensive test suite for security and functionality validation
"""

import os
import sys
import json
import time
import unittest
import subprocess
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from typing import Dict, List, Any

# Add utils to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'utils'))

try:
    from logger import UltraLogger, SecurityLogger, PerformanceLogger
except ImportError:
    print("Warning: Could not import logger module. Some tests will be skipped.")
    UltraLogger = None
    SecurityLogger = None
    PerformanceLogger = None


class TestUltraLogger(unittest.TestCase):
    """
    Test cases for the UltraLogger system
    """
    
    def setUp(self):
        """Set up test environment"""
        if UltraLogger is None:
            self.skipTest("Logger module not available")
        
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, 'test.log')
        self.logger = UltraLogger('test-scanner')
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_logger_initialization(self):
        """Test logger initialization"""
        self.assertIsNotNone(self.logger)
        self.assertIsNotNone(self.logger.logger)
        self.assertEqual(self.logger.name, 'test-scanner')
    
    def test_basic_logging_methods(self):
        """Test basic logging methods"""
        # Test that methods don't raise exceptions
        self.logger.debug("Test debug message")
        self.logger.info("Test info message")
        self.logger.warning("Test warning message")
        self.logger.error("Test error message")
        self.logger.critical("Test critical message")
    
    def test_scan_logging(self):
        """Test scan-specific logging methods"""
        target = "example.com"
        scan_type = "subdomain"
        options = {"threads": 10, "timeout": 30}
        
        # Test scan start logging
        self.logger.log_scan_start(target, scan_type, options)
        
        # Test scan completion logging
        self.logger.log_scan_complete(target, scan_type, 15.5, 25)
    
    def test_vulnerability_logging(self):
        """Test vulnerability logging"""
        vulnerability = {
            'type': 'XSS',
            'severity': 'HIGH',
            'target': 'example.com',
            'description': 'Test vulnerability'
        }
        
        self.logger.log_vulnerability_found('example.com', vulnerability)
    
    def test_api_call_logging(self):
        """Test API call logging"""
        self.logger.log_api_call('shodan', '/search', True, 0.5)
        self.logger.log_api_call('virustotal', '/domain', False, 2.0)


class TestSecurityLogger(unittest.TestCase):
    """
    Test cases for the SecurityLogger
    """
    
    def setUp(self):
        """Set up test environment"""
        if SecurityLogger is None:
            self.skipTest("SecurityLogger not available")
        
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, 'security.log')
        self.security_logger = SecurityLogger(self.log_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_api_key_usage_logging(self):
        """Test API key usage logging"""
        self.security_logger.log_api_key_usage('shodan', 'abcd1234hash', True)
        self.security_logger.log_api_key_usage('virustotal', 'efgh5678hash', False)
    
    def test_suspicious_activity_logging(self):
        """Test suspicious activity logging"""
        details = {
            'ip': '192.168.1.100',
            'user_agent': 'suspicious-scanner',
            'requests_per_second': 1000
        }
        self.security_logger.log_suspicious_activity('High request rate', details)
    
    def test_authentication_logging(self):
        """Test authentication logging"""
        self.security_logger.log_authentication_attempt('admin', True, '192.168.1.1')
        self.security_logger.log_authentication_attempt('guest', False, '10.0.0.1')


class TestDockerIntegration(unittest.TestCase):
    """
    Test cases for Docker integration
    """
    
    def test_dockerfile_exists(self):
        """Test that Dockerfile exists and is valid"""
        dockerfile_path = os.path.join(os.path.dirname(__file__), '..', 'Dockerfile')
        self.assertTrue(os.path.exists(dockerfile_path), "Dockerfile not found")
        
        with open(dockerfile_path, 'r') as f:
            content = f.read()
            
        # Check for essential Dockerfile components
        self.assertIn('FROM debian:bookworm-slim', content)
        self.assertIn('RUN apt-get update', content)
        self.assertIn('WORKDIR /app', content)
        self.assertIn('USER scanner', content)
    
    def test_docker_compose_exists(self):
        """Test that docker-compose.yml exists and is valid"""
        compose_path = os.path.join(os.path.dirname(__file__), '..', 'docker-compose.yml')
        self.assertTrue(os.path.exists(compose_path), "docker-compose.yml not found")
        
        with open(compose_path, 'r') as f:
            content = f.read()
            
        # Check for essential compose components
        self.assertIn('version:', content)
        self.assertIn('services:', content)
        self.assertIn('ultra-bugbounty-scanner:', content)
    
    def test_dockerignore_exists(self):
        """Test that .dockerignore exists"""
        dockerignore_path = os.path.join(os.path.dirname(__file__), '..', '.dockerignore')
        self.assertTrue(os.path.exists(dockerignore_path), ".dockerignore not found")


class TestConfigurationFiles(unittest.TestCase):
    """
    Test cases for configuration files
    """
    
    def test_env_example_exists(self):
        """Test that .env.example exists and contains required variables"""
        env_path = os.path.join(os.path.dirname(__file__), '..', '.env.example')
        self.assertTrue(os.path.exists(env_path), ".env.example not found")
        
        with open(env_path, 'r') as f:
            content = f.read()
        
        # Check for essential environment variables
        required_vars = [
            'SHODAN_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'TELEGRAM_BOT_TOKEN',
            'MAX_THREADS',
            'OUTPUT_DIR'
        ]
        
        for var in required_vars:
            self.assertIn(var, content, f"Required variable {var} not found in .env.example")
    
    def test_logging_config_exists(self):
        """Test that logging configuration exists"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'logging.conf')
        self.assertTrue(os.path.exists(config_path), "logging.conf not found")


class TestScannerScript(unittest.TestCase):
    """
    Test cases for the main scanner script
    """
    
    def test_scanner_script_exists(self):
        """Test that the main scanner script exists"""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'ultra-scanner.sh')
        self.assertTrue(os.path.exists(script_path), "ultra-scanner.sh not found")
    
    def test_scanner_script_executable(self):
        """Test that the scanner script has execute permissions"""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'ultra-scanner.sh')
        if os.path.exists(script_path):
            # Check if file is executable (Unix-like systems)
            if hasattr(os, 'access'):
                self.assertTrue(os.access(script_path, os.X_OK), "Scanner script is not executable")
    
    def test_scanner_help_option(self):
        """Test that scanner script responds to help option"""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'ultra-scanner.sh')
        if os.path.exists(script_path) and shutil.which('bash'):
            try:
                result = subprocess.run(
                    ['bash', script_path, '--help'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Should not return error code for help
                self.assertEqual(result.returncode, 0, "Help option failed")
                self.assertIn('Usage:', result.stdout, "Help output doesn't contain usage information")
            except subprocess.TimeoutExpired:
                self.fail("Scanner script help option timed out")
            except FileNotFoundError:
                self.skipTest("Bash not available for testing")


class TestSecurityValidation(unittest.TestCase):
    """
    Test cases for security validation
    """
    
    def test_no_hardcoded_secrets(self):
        """Test that no hardcoded secrets exist in code"""
        project_root = os.path.join(os.path.dirname(__file__), '..')
        
        # Patterns that might indicate hardcoded secrets
        secret_patterns = [
            r'api[_-]?key[\s]*=[\s]*["\'][a-zA-Z0-9]{20,}["\']',
            r'password[\s]*=[\s]*["\'][^"\']',
            r'token[\s]*=[\s]*["\'][a-zA-Z0-9]{20,}["\']',
            r'secret[\s]*=[\s]*["\'][^"\']'
        ]
        
        # Files to check
        files_to_check = []
        for root, dirs, files in os.walk(project_root):
            # Skip test directory and hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'tests']
            
            for file in files:
                if file.endswith(('.py', '.sh', '.yml', '.yaml', '.json')):
                    files_to_check.append(os.path.join(root, file))
        
        import re
        
        for file_path in files_to_check:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Allow example/placeholder values
                        for match in matches:
                            if not any(placeholder in match.lower() for placeholder in 
                                     ['example', 'placeholder', 'your_', 'xxx', 'yyy', 'zzz']):
                                self.fail(f"Potential hardcoded secret found in {file_path}: {match}")
            except Exception as e:
                # Skip files that can't be read
                continue
    
    def test_file_permissions(self):
        """Test that sensitive files have appropriate permissions"""
        project_root = os.path.join(os.path.dirname(__file__), '..')
        
        # Files that should have restricted permissions
        sensitive_files = [
            '.env',
            'config/secrets.conf',
            'logs/security.log'
        ]
        
        for file_path in sensitive_files:
            full_path = os.path.join(project_root, file_path)
            if os.path.exists(full_path):
                # Check permissions (Unix-like systems only)
                if hasattr(os, 'stat'):
                    import stat
                    file_stat = os.stat(full_path)
                    mode = file_stat.st_mode
                    
                    # Check that file is not world-readable
                    world_readable = bool(mode & stat.S_IROTH)
                    self.assertFalse(world_readable, f"Sensitive file {file_path} is world-readable")


class TestInstallationScripts(unittest.TestCase):
    """
    Test cases for installation scripts
    """
    
    def test_scoop_installer_exists(self):
        """Test that Scoop installer script exists"""
        installer_path = os.path.join(os.path.dirname(__file__), '..', 'install-scoop.ps1')
        self.assertTrue(os.path.exists(installer_path), "install-scoop.ps1 not found")
    
    def test_scoop_installer_syntax(self):
        """Test basic PowerShell syntax in Scoop installer"""
        installer_path = os.path.join(os.path.dirname(__file__), '..', 'install-scoop.ps1')
        if os.path.exists(installer_path):
            with open(installer_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Basic PowerShell syntax checks
            self.assertIn('param(', content, "PowerShell parameters not found")
            self.assertIn('function ', content, "PowerShell functions not found")
            self.assertIn('Write-Host', content, "PowerShell output commands not found")


class TestPerformanceMetrics(unittest.TestCase):
    """
    Test cases for performance monitoring
    """
    
    def setUp(self):
        """Set up test environment"""
        if PerformanceLogger is None:
            self.skipTest("PerformanceLogger not available")
        
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, 'performance.log')
        self.perf_logger = PerformanceLogger(self.log_file)
    
    def tearDown(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_execution_time_logging(self):
        """Test execution time logging"""
        self.perf_logger.log_execution_time('test_operation', 1.5, {'param': 'value'})
        
        # Give some time for async logging
        time.sleep(0.1)
    
    def test_scan_metrics_logging(self):
        """Test scan metrics logging"""
        self.perf_logger.log_scan_metrics('subdomain', 100, 50, 30.5)
        
        # Give some time for async logging
        time.sleep(0.1)


def run_security_tests():
    """
    Run security-focused tests
    """
    suite = unittest.TestSuite()
    
    # Add security test cases
    suite.addTest(unittest.makeSuite(TestSecurityValidation))
    suite.addTest(unittest.makeSuite(TestSecurityLogger))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_functionality_tests():
    """
    Run functionality tests
    """
    suite = unittest.TestSuite()
    
    # Add functionality test cases
    suite.addTest(unittest.makeSuite(TestUltraLogger))
    suite.addTest(unittest.makeSuite(TestDockerIntegration))
    suite.addTest(unittest.makeSuite(TestConfigurationFiles))
    suite.addTest(unittest.makeSuite(TestScannerScript))
    suite.addTest(unittest.makeSuite(TestInstallationScripts))
    suite.addTest(unittest.makeSuite(TestPerformanceMetrics))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_all_tests():
    """
    Run all tests
    """
    print("\n" + "="*60)
    print("Ultra-BugBountyScanner Test Suite")
    print("="*60)
    
    # Discover and run all tests
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.dirname(__file__), pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("="*60)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Ultra-BugBountyScanner Test Suite')
    parser.add_argument('--security', action='store_true', help='Run only security tests')
    parser.add_argument('--functionality', action='store_true', help='Run only functionality tests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.security:
        success = run_security_tests()
    elif args.functionality:
        success = run_functionality_tests()
    else:
        success = run_all_tests()
    
    sys.exit(0 if success else 1)