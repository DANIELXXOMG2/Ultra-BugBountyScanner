#!/usr/bin/env python3
"""Tests for secrets_scanner module."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, mock_open, patch

from modules.secrets_scanner import scan_secrets


class TestSecretsScanner(unittest.TestCase):
    """Test cases for secrets_scanner module."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_domain = "example.com"
        self.test_output_dir = Path(tempfile.gettempdir()) / "test_output"
        self.secrets_dir = self.test_output_dir / self.test_domain / "secrets"

    @patch("modules.secrets_scanner.run_command")
    @patch("modules.secrets_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_secrets_success(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test successful secrets scanning."""
        # Mock successful github-dorks output
        mock_run_command.side_effect = [
            None,  # github-dorks call
            None   # trufflehog call
        ]
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock file operations and return repositories from github-dorks
        def mock_find_repositories(*args: object, **kwargs: object) -> list[str]:
            return ["https://github.com/example/repo1", "https://github.com/example/repo2"]
        
        with patch("builtins.open", mock_open()), \
             patch("tempfile.NamedTemporaryFile") as mock_temp, \
             patch("pathlib.Path.unlink") as mock_unlink, \
             patch("modules.secrets_scanner._find_repositories_with_github_dorks", side_effect=mock_find_repositories):
            
            # Mock temporary file
            mock_temp_instance = mock_temp.return_value.__enter__.return_value
            mock_temp_instance.name = "/tmp/temp_results.json"
            
            scan_secrets(self.test_domain, self.test_output_dir)

            # Verify trufflehog was called (github-dorks is mocked separately)
            trufflehog_called = any("trufflehog" in str(call) for call in mock_run_command.call_args_list)
            self.assertTrue(trufflehog_called)

            # Verify calls were made
            self.assertTrue(len(mock_run_command.call_args_list) >= 1)

    @patch("modules.secrets_scanner.run_command")
    @patch("modules.secrets_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_secrets_missing_tools(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test handling of missing tools."""
        # Mock missing tools (run_command raises FileNotFoundError)
        mock_exists.return_value = True
        mock_run_command.side_effect = FileNotFoundError("Tool not found")
        
        # Mock directory operations
        mock_exists.return_value = True

        with patch("builtins.open", mock_open()):
            scan_secrets(self.test_domain, self.test_output_dir)

            # Verify error was logged
            mock_logger.error.assert_called()

    @patch("modules.secrets_scanner.run_command")
    @patch("modules.secrets_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_secrets_github_dorks_failure(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test handling of github-dorks failure."""
        # Mock github-dorks returning None (failure)
        mock_run_command.return_value = (None, "github-dorks failed")
        
        # Mock directory operations
        mock_exists.return_value = True

        with patch("builtins.open", mock_open()):
            scan_secrets(self.test_domain, self.test_output_dir)

            # Verify warning was logged for no repositories found
            mock_logger.warning.assert_called_with("⚠️  No se encontraron repositorios públicos para el dominio")

    @patch("modules.secrets_scanner.run_command")
    @patch("modules.secrets_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_secrets_trufflehog_failure(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test handling of trufflehog failure."""
        # Mock successful github-dorks but failed trufflehog
        mock_run_command.side_effect = [
            ("https://github.com/example/repo1\n", None),  # github-dorks success
            (None, "trufflehog failed")  # trufflehog failure
        ]
        
        # Mock directory operations
        mock_exists.return_value = True
        
        with patch("builtins.open", mock_open()), \
             patch("tempfile.NamedTemporaryFile") as mock_temp, \
             patch("pathlib.Path.unlink") as mock_unlink:
            
            # Mock temporary file
            mock_temp_instance = mock_temp.return_value.__enter__.return_value
            mock_temp_instance.name = "/tmp/temp_results.json"
            
            scan_secrets(self.test_domain, self.test_output_dir)

            # Verify trufflehog was called and failed
            self.assertEqual(mock_run_command.call_count, 2)
            # Verify warning was logged for scanning failure
            mock_logger.warning.assert_called()

    @patch("modules.secrets_scanner.run_command")
    @patch("modules.secrets_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_secrets_no_repositories_found(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test handling when no repositories are found."""
        # Mock github-dorks returning empty result
        mock_run_command.side_effect = [
            None,  # github-dorks call (empty result)
        ]
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock empty repositories result
        def mock_find_repositories(*args: object, **kwargs: object) -> list[str]:
            return []
        
        with patch("builtins.open", mock_open()), \
             patch("modules.secrets_scanner._find_repositories_with_github_dorks", side_effect=mock_find_repositories):
            
            scan_secrets(self.test_domain, self.test_output_dir)

            # Verify no trufflehog calls were made (no repositories found)
            trufflehog_called = any("trufflehog" in str(call) for call in mock_run_command.call_args_list)
            self.assertFalse(trufflehog_called)


if __name__ == "__main__":
    unittest.main()