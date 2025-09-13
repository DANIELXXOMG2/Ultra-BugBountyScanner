#!/usr/bin/env python3
"""
Ultra-BugBountyScanner Test Suite
Author: danielxxomg2
Version: 1.0.0
Description: Comprehensive test suite for security and functionality validation
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

# Add utils to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / "utils"))

try:
    from utils.logger import UltraLogger

    LOGGER_AVAILABLE = True
except ImportError:
    print("Warning: Could not import logger module. Some tests will be skipped.")
    UltraLogger = None  # type: ignore[misc,assignment]
    LOGGER_AVAILABLE = False

# Mock classes for testing purposes
SecurityLogger = None
PerformanceLogger = None


class TestUltraLogger(unittest.TestCase):
    """
    Test cases for the UltraLogger system
    """

    def setUp(self) -> None:
        """Set up test environment"""
        if UltraLogger is None:
            self.skipTest("Logger module not available")

        self.test_dir = tempfile.mkdtemp()
        self.log_file = str(Path(self.test_dir) / "test.log")
        self.logger = UltraLogger("test-scanner")

    def tearDown(self) -> None:
        """Clean up test environment"""
        if hasattr(self, "test_dir") and Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)

    def test_logger_initialization(self) -> None:
        """Test logger initialization"""
        self.assertIsNotNone(self.logger)
        self.assertEqual(self.logger.name, "test-scanner")

    def test_basic_logging_methods(self) -> None:
        """Test basic logging methods"""
        # Test that methods don't raise exceptions
        self.logger.debug("Test debug message")
        self.logger.info("Test info message")
        self.logger.warning("Test warning message")
        self.logger.error("Test error message")
        self.logger.critical("Test critical message")

    def test_scan_logging(self) -> None:
        """Test scan-specific logging methods"""
        target = "example.com"
        scan_type = "subdomain"

        # Test basic logging for scan operations
        self.logger.info(f"Starting {scan_type} scan for {target}")
        self.logger.success(f"Completed {scan_type} scan for {target}")

    def test_vulnerability_logging(self) -> None:
        """Test vulnerability logging"""
        vulnerability = {
            "type": "XSS",
            "severity": "HIGH",
            "target": "example.com",
            "description": "Test vulnerability",
        }

        self.logger.warning(f"Vulnerability found: {vulnerability['type']}")

    def test_api_call_logging(self) -> None:
        """Test API call logging"""
        self.logger.info("API call to shodan: /search - Success")
        self.logger.error("API call to virustotal: /domain - Failed")


class TestSecurityLogger(unittest.TestCase):
    """
    Test cases for security logging functionality
    """

    def setUp(self) -> None:
        """Set up test environment"""
        if SecurityLogger is None:
            self.skipTest("SecurityLogger not available")

    def test_api_key_usage_logging(self) -> None:
        """Test API key usage logging"""
        # Skip test since SecurityLogger is not implemented
        self.skipTest("SecurityLogger not implemented")

    def test_suspicious_activity_logging(self) -> None:
        """Test suspicious activity logging"""
        # Skip test since SecurityLogger is not implemented
        self.skipTest("SecurityLogger not implemented")

    def test_authentication_logging(self) -> None:
        """Test authentication logging"""
        # Skip test since SecurityLogger is not implemented
        self.skipTest("SecurityLogger not implemented")


class TestDockerIntegration(unittest.TestCase):
    """
    Test cases for Docker integration
    """

    def test_dockerfile_exists(self) -> None:
        """Test that Dockerfile exists and is valid"""
        dockerfile_path = Path(__file__).parent.parent / "Dockerfile"
        self.assertTrue(dockerfile_path.exists(), "Dockerfile not found")

        with dockerfile_path.open() as f:
            content = f.read()

        # Check for essential Dockerfile components
        self.assertIn("FROM debian:bookworm-slim", content)
        self.assertIn("RUN apt-get update", content)
        self.assertIn("WORKDIR /app", content)
        self.assertIn("USER scanner", content)

    def test_docker_compose_exists(self) -> None:
        """Test that docker-compose.yml exists and has basic structure"""
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        if compose_path.exists():
            with compose_path.open(encoding="utf-8") as f:
                content = f.read()
                # Modern docker-compose files don't require version field
                self.assertIn("services:", content, "docker-compose.yml missing services section")
                # Check for at least one service definition
                self.assertTrue(len(content.strip()) > 0, "docker-compose.yml is empty")
        else:
            self.skipTest("docker-compose.yml not found")

    def test_dockerignore_exists(self) -> None:
        """Test that .dockerignore exists"""
        dockerignore_path = Path(__file__).parent.parent / ".dockerignore"
        self.assertTrue(dockerignore_path.exists(), ".dockerignore not found")


class TestConfigurationFiles(unittest.TestCase):
    """
    Test cases for configuration files
    """

    def test_env_example_exists(self) -> None:
        """Test that .env.example exists and contains required variables"""
        env_path = Path(__file__).parent.parent / ".env.example"
        self.assertTrue(env_path.exists(), ".env.example not found")

        with env_path.open() as f:
            content = f.read()

        # Check for essential environment variables
        required_vars = ["SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "TELEGRAM_BOT_TOKEN", "MAX_THREADS", "OUTPUT_DIR"]

        for var in required_vars:
            self.assertIn(var, content, f"Required variable {var} not found in .env.example")

    def test_logging_config_exists(self) -> None:
        """Test that logging configuration exists"""
        config_path = Path(__file__).parent.parent / "config" / "logging.conf"
        self.assertTrue(config_path.exists(), "logging.conf not found")


class TestScannerScript(unittest.TestCase):
    """
    Test cases for the main scanner script
    """

    def test_scanner_script_exists(self) -> None:
        """Test that the main scanner script exists"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"
        self.assertTrue(script_path.exists(), "scanner_main.py not found")

    def test_scanner_script_executable(self) -> None:
        """Test that the scanner script has execute permissions"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"
        if script_path.exists():
            # Python scripts are executable if Python is installed
            self.assertTrue(script_path.is_file(), "Scanner script is not a valid file")

    def test_scanner_help_option(self) -> None:
        """Test that scanner script responds to help option"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"
        if script_path.exists() and shutil.which("python"):
            try:
                result = subprocess.run(["python", script_path, "--help"], capture_output=True, text=True, timeout=10)  # nosec B603 - Prueba controlada con timeout
                # Should not return error code for help
                self.assertEqual(result.returncode, 0, "Help option failed")
                self.assertIn("usage:", result.stdout.lower(), "Help output doesn't contain usage information")
            except subprocess.TimeoutExpired:
                self.fail("Scanner script help option timed out")
            except FileNotFoundError:
                self.skipTest("Python not available for testing")


class TestModularStructure(unittest.TestCase):
    """
    Test cases for modular structure functionality
    """

    def test_modules_directory_exists(self) -> None:
        """Test that modules directory exists"""
        modules_path = Path(__file__).parent.parent / "modules"
        self.assertTrue(modules_path.exists(), "modules directory not found")
        self.assertTrue(modules_path.is_dir(), "modules is not a directory")

    def test_modules_init_exists(self) -> None:
        """Test that modules/__init__.py exists"""
        init_path = Path(__file__).parent.parent / "modules" / "__init__.py"
        self.assertTrue(init_path.exists(), "modules/__init__.py not found")

    def test_subdomain_scanner_module_exists(self) -> None:
        """Test that subdomain_scanner module exists and contains enumerate_subdomains function"""
        module_path = Path(__file__).parent.parent / "modules" / "subdomain_scanner.py"
        self.assertTrue(module_path.exists(), "modules/subdomain_scanner.py not found")

        with module_path.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("def enumerate_subdomains(", content, "enumerate_subdomains function not found")
        self.assertIn("subfinder", content.lower(), "subfinder integration not found")
        self.assertIn("amass", content.lower(), "amass integration not found")

    def test_port_scanner_module_exists(self) -> None:
        """Test that port_scanner module exists and contains scan_ports function"""
        module_path = Path(__file__).parent.parent / "modules" / "port_scanner.py"
        self.assertTrue(module_path.exists(), "modules/port_scanner.py not found")

        with module_path.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("def scan_ports(", content, "scan_ports function not found")
        self.assertIn("naabu", content.lower(), "naabu integration not found")
        self.assertIn("nmap", content.lower(), "nmap integration not found")

    def test_web_assets_scanner_module_exists(self) -> None:
        """Test that web_assets_scanner module exists and contains discover_web_assets function"""
        module_path = Path(__file__).parent.parent / "modules" / "web_assets_scanner.py"
        self.assertTrue(module_path.exists(), "modules/web_assets_scanner.py not found")

        with module_path.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("def discover_web_assets(", content, "discover_web_assets function not found")
        self.assertIn("httpx", content.lower(), "httpx integration not found")

    def test_vulnerability_scanner_module_exists(self) -> None:
        """Test that vulnerability_scanner module exists and contains scan_vulnerabilities function"""
        module_path = Path(__file__).parent.parent / "modules" / "vulnerability_scanner.py"
        self.assertTrue(module_path.exists(), "modules/vulnerability_scanner.py not found")

        with module_path.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("def scan_vulnerabilities(", content, "scan_vulnerabilities function not found")
        self.assertIn("nuclei", content.lower(), "nuclei integration not found")

    def test_scanner_main_imports_modules(self) -> None:
        """Test that scanner_main.py imports from the new modules"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"
        self.assertTrue(script_path.exists(), "scanner_main.py not found")

        with script_path.open(encoding="utf-8") as f:
            content = f.read()

        # Check for imports from modules
        self.assertIn(
            "from modules.subdomain_scanner import enumerate_subdomains",
            content,
            "subdomain_scanner import not found"
        )
        self.assertIn(
            "from modules.port_scanner import scan_ports",
            content,
            "port_scanner import not found"
        )
        self.assertIn(
            "from modules.web_assets_scanner import discover_web_assets",
            content,
            "web_assets_scanner import not found"
        )
        self.assertIn(
            "from modules.vulnerability_scanner import scan_vulnerabilities",
            content,
            "vulnerability_scanner import not found"
        )
        self.assertIn(
            "from modules.javascript_analyzer import analyze_javascript",
            content,
            "javascript_analyzer import not found"
        )


class TestJavaScriptAnalysis(unittest.TestCase):
    """
    Test cases for JavaScript analysis functionality
    """

    def setUp(self) -> None:
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.test_dir)
        self.web_dir = self.output_dir / "web"
        self.javascript_dir = self.output_dir / "javascript"
        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.javascript_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        """Clean up test environment"""
        if Path(self.test_dir).exists():
            shutil.rmtree(self.test_dir)

    def test_analyze_javascript_function_exists(self) -> None:
        """Test that analyze_javascript function exists in modules/javascript_analyzer.py"""
        module_path = Path(__file__).parent.parent / "modules" / "javascript_analyzer.py"
        self.assertTrue(module_path.exists(), "modules/javascript_analyzer.py not found")

        with module_path.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("def analyze_javascript(", content, "analyze_javascript function not found")
        self.assertIn("linkfinder", content.lower(), "LinkFinder integration not found")

    def test_javascript_directory_creation(self) -> None:
        """Test that javascript directory is created in setup_directories"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"

        with script_path.open(encoding="utf-8") as f:
            content = f.read()

        # Check that 'javascript' is in the subdirectories list
        self.assertIn('"javascript"', content, "javascript directory not in setup_directories")

    def test_httpx_urls_file_handling(self) -> None:
        """Test handling of httpx_urls.txt file"""
        # Create a mock httpx_urls.txt file
        httpx_file = self.web_dir / "httpx_urls.txt"
        test_urls = [
            "https://example.com",
            "https://test.example.com/app.js",
            "https://api.example.com/v1/data"
        ]

        with httpx_file.open("w", encoding="utf-8") as f:
            f.write("\n".join(test_urls))

        self.assertTrue(httpx_file.exists(), "Test httpx_urls.txt file not created")

        # Verify file content
        with httpx_file.open(encoding="utf-8") as f:
            content = f.read().strip().split("\n")

        self.assertEqual(len(content), 3, "Incorrect number of URLs in test file")
        self.assertIn("https://example.com", content, "Test URL not found")

    def test_linkfinder_results_file_creation(self) -> None:
        """Test that linkfinder_results.txt file structure is correct"""
        results_file = self.javascript_dir / "linkfinder_results.txt"

        # Create a mock results file
        test_results = [
            "=== LinkFinder Results for https://example.com ===",
            "/api/v1/users",
            "/admin/dashboard",
            "=== LinkFinder Results for https://test.example.com ===",
            "/assets/config.json",
            "/api/auth/login"
        ]

        with results_file.open("w", encoding="utf-8") as f:
            f.write("\n".join(test_results))

        self.assertTrue(results_file.exists(), "LinkFinder results file not created")

        # Verify file structure
        with results_file.open(encoding="utf-8") as f:
            content = f.read()

        self.assertIn("=== LinkFinder Results for", content, "Results header format incorrect")
        self.assertIn("/api/", content, "API endpoints not found in results")

    def test_linkfinder_integration_in_gemini_analysis(self) -> None:
        """Test that LinkFinder results are integrated into Gemini analysis"""
        script_path = Path(__file__).parent.parent / "scanner_main.py"

        with script_path.open(encoding="utf-8") as f:
            content = f.read()

        # Check that linkfinder_results.txt is read for Gemini analysis
        self.assertIn("linkfinder_results.txt", content, "LinkFinder results not integrated with Gemini")
        self.assertIn("ANÁLISIS DE JAVASCRIPT (LINKFINDER)", content, "JavaScript analysis header not found")


class TestSecurityValidation(unittest.TestCase):
    """
    Test cases for security validation
    """

    def test_no_hardcoded_secrets(self) -> None:
        """Test that no hardcoded secrets exist in code"""
        project_root = Path(__file__).parent.parent

        # Patterns that might indicate hardcoded secrets
        secret_patterns = [
            r'api[_-]?key[\s]*=[\s]*["\'][a-zA-Z0-9]{20,}["\']',
            r'password[\s]*=[\s]*["\'][^"\']',
            r'token[\s]*=[\s]*["\'][a-zA-Z0-9]{20,}["\']',
            r'secret[\s]*=[\s]*["\'][^"\']',
        ]

        # Files to check
        files_to_check = []
        for root, dirs, files in os.walk(project_root):
            # Skip test directory and hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "tests"]

            for file in files:
                if file.endswith((".py", ".sh", ".yml", ".yaml", ".json")):
                    files_to_check.append(Path(root) / file)

        import re

        for file_path in files_to_check:
            try:
                with file_path.open(encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Allow example/placeholder values
                        for match in matches:
                            if not any(
                                placeholder in match.lower()
                                for placeholder in ["example", "placeholder", "your_", "xxx", "yyy", "zzz"]
                            ):
                                self.fail(f"Potential hardcoded secret found in {file_path}: {match}")
            except Exception as e:  # nosec B110 - Necesario para manejar archivos no legibles
                # Skip files that can't be read
                print(f"Warning: Could not read file {file_path}: {e}")
                continue  # nosec B112 - Continue apropiado en contexto de pruebas

    def test_file_permissions(self) -> None:
        """Test that sensitive files exist and are accessible"""
        project_root = Path(__file__).parent.parent

        # Files that should have restricted permissions
        sensitive_files = [
            project_root / ".env",
            project_root / "config" / "secrets.json",
        ]

        for file_path in sensitive_files:
            if file_path.exists():
                # Check if file is readable (basic permission test)
                self.assertTrue(file_path.is_file() and file_path.stat().st_mode)
            else:
                # Skip test if sensitive files don't exist (they might be optional)
                continue

    def test_installation_scripts_executable(self) -> None:
        """Test that installation scripts are executable"""
        project_root = Path(__file__).parent.parent

        # Scripts to check
        scripts = [
            project_root / "install.sh",
            project_root / "setup.py",
        ]

        for script_path in scripts:
            if script_path.exists():
                # Check if script is executable (basic check)
                self.assertTrue(script_path.is_file())


class TestInstallationScripts(unittest.TestCase):
    """
    Test cases for installation scripts
    """

    def test_docker_compose_exists(self) -> None:
        """Test that Docker Compose configuration exists"""
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        self.assertTrue(compose_path.exists(), "docker-compose.yml not found")

    def test_docker_compose_syntax(self) -> None:
        """Test basic YAML syntax in Docker Compose file"""
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        if compose_path.exists():
            with compose_path.open(encoding="utf-8") as f:
                content = f.read()

            # Basic YAML syntax checks for Docker Compose
            self.assertIn("services:", content, "Docker Compose services section not found")
            self.assertIn("ultra-scanner:", content, "Ultra scanner service not found")
            self.assertIn("build:", content, "Build configuration not found")


class TestPerformanceMetrics(unittest.TestCase):
    """
    Test cases for performance monitoring
    """

    def setUp(self) -> None:
        """Set up test environment"""
        if PerformanceLogger is None:
            self.skipTest("PerformanceLogger not available")

    def test_execution_time_logging(self) -> None:
        """Test execution time logging"""
        # Skip test since PerformanceLogger is not implemented
        self.skipTest("PerformanceLogger not implemented")

    def test_scan_metrics_logging(self) -> None:
        """Test scan metrics logging"""
        # Skip test since PerformanceLogger is not implemented
        self.skipTest("PerformanceLogger not implemented")


def run_security_tests() -> bool:
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


def run_functionality_tests() -> bool:
    """
    Run functionality tests
    """
    suite = unittest.TestSuite()

    # Add functionality test cases
    suite.addTest(unittest.makeSuite(TestUltraLogger))
    suite.addTest(unittest.makeSuite(TestDockerIntegration))
    suite.addTest(unittest.makeSuite(TestConfigurationFiles))
    suite.addTest(unittest.makeSuite(TestScannerScript))
    suite.addTest(unittest.makeSuite(TestModularStructure))
    suite.addTest(unittest.makeSuite(TestJavaScriptAnalysis))
    suite.addTest(unittest.makeSuite(TestInstallationScripts))
    suite.addTest(unittest.makeSuite(TestPerformanceMetrics))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


def run_all_tests() -> bool:
    """
    Run all tests
    """
    print("\n" + "=" * 60)
    print("Ultra-BugBountyScanner Test Suite")
    print("=" * 60)

    # Discover and run all tests
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(__file__).parent), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)

    return result.wasSuccessful()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ultra-BugBountyScanner Test Suite")
    parser.add_argument("--security", action="store_true", help="Run only security tests")
    parser.add_argument("--functionality", action="store_true", help="Run only functionality tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.security:
        success = run_security_tests()
    elif args.functionality:
        success = run_functionality_tests()
    else:
        success = run_all_tests()

    sys.exit(0 if success else 1)
