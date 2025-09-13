#!/usr/bin/env python3
"""Tests for parameter_fuzzer module."""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, Mock, mock_open, patch
import tempfile

from modules.parameter_fuzzer import fuzz_parameters


class TestParameterFuzzer(unittest.TestCase):
    """Test cases for parameter_fuzzer module."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_domain = "example.com"
        self.test_output_dir = Path(tempfile.gettempdir()) / "test_output"
        self.parameters_dir = self.test_output_dir / self.test_domain / "parameters"
        self.httpx_urls_file = self.test_output_dir / self.test_domain / "web" / "httpx_urls.txt"

    @patch("modules.parameter_fuzzer.run_command")
    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_success(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test successful parameter fuzzing."""
        # Mock successful arjun execution
        mock_results = [
            {
                "url": "https://example.com/page1",
                "method": "GET",
                "parameters": ["param1", "param2"]
            }
        ]
        mock_run_command.return_value = (json.dumps(mock_results), None)
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock file operations
        mock_urls_content = "https://example.com/page1\nhttps://example.com/page2\n"
        
        with patch("builtins.open", mock_open(read_data=mock_urls_content)) as mock_file:
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify arjun was called correctly
            mock_run_command.assert_called_once()
            args = mock_run_command.call_args[0][0]
            self.assertIn("arjun", args)
            self.assertIn("-i", args)
            
            # Verify results were written
            mock_file.assert_called()

    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_missing_tool(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock) -> None:
        """Test behavior when arjun is missing."""
        # Mock directory operations
        mock_exists.return_value = True
        
        # Mock missing tool
        with patch("modules.parameter_fuzzer.run_command", side_effect=FileNotFoundError("arjun not found")):
            with patch("builtins.open", mock_open(read_data="https://example.com\n")):
                fuzz_parameters(self.test_domain, self.test_output_dir)

                # Verify error was logged
                mock_logger.error.assert_called()

    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_missing_urls_file(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock) -> None:
        """Test behavior when httpx_urls.txt doesn't exist."""
        # Mock directory operations
        mock_exists.side_effect = lambda: False if "httpx_urls.txt" in str(self) else True
        
        with patch("builtins.open", mock_open()):
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify warning was logged
            mock_logger.warning.assert_called()

    @patch("modules.parameter_fuzzer.run_command")
    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_arjun_failure(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test behavior when arjun fails for a URL."""
        # Mock arjun failure
        mock_run_command.return_value = (None, "arjun failed")
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock file operations
        mock_urls_content = "https://example.com/page1\n"
        
        with patch("builtins.open", mock_open(read_data=mock_urls_content)):
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify error was logged
            mock_logger.error.assert_called()

    @patch("modules.parameter_fuzzer.run_command")
    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_empty_urls_file(self, mock_exists: Mock, _mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test behavior with empty URLs file."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock empty URLs file
        with patch("builtins.open", mock_open(read_data="")):
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify warning was logged
            mock_logger.warning.assert_called()

            # Verify arjun was not called
            mock_run_command.assert_not_called()

    @patch("modules.parameter_fuzzer.run_command")
    @patch("modules.parameter_fuzzer.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_invalid_json_output(self, mock_exists: Mock, _mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test behavior when arjun returns invalid JSON."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock URLs file content
        urls_content = "https://example.com/login"

        # Mock arjun with invalid JSON output
        mock_run_command.return_value = ("Invalid JSON output", "")

        with patch("builtins.open", mock_open(read_data=urls_content)):
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify error was logged for JSON parsing
            mock_logger.error.assert_called()

    @patch("modules.parameter_fuzzer.run_command")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_results_processing(self, mock_exists: Mock, _mock_mkdir: Mock, mock_run_command: Mock) -> None:
        """Test processing and saving of arjun results."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock URLs file content
        urls_content = "https://example.com/login\nhttps://api.example.com/users"

        # Mock successful arjun execution
        mock_run_command.return_value = ("success", "")

        with patch("builtins.open", mock_open(read_data=urls_content)) as mock_file:
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify arjun was called once
            mock_run_command.assert_called_once()
            
            # Verify results file was accessed
            self.assertTrue(any("arjun_results.json" in str(call) for call in mock_file.call_args_list))

    @patch("modules.parameter_fuzzer.run_command")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_fuzz_parameters_url_filtering(self, mock_exists: Mock, _mock_mkdir: Mock, mock_run_command: Mock) -> None:
        """Test that invalid URLs are filtered out."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock URLs file with valid and invalid URLs
        urls_content = (
            "https://example.com/login\n"
            "invalid-url\n"
            "ftp://example.com/file\n"
            "https://api.example.com/users\n"
            "\n"
            "   \n"
        )

        # Mock arjun output
        mock_run_command.return_value = (json.dumps([]), "")

        with patch("builtins.open", mock_open(read_data=urls_content)):
            fuzz_parameters(self.test_domain, self.test_output_dir)

            # Verify arjun was called once with temp file containing valid URLs
            self.assertEqual(mock_run_command.call_count, 1)

            # Verify arjun command was executed
            call_args = mock_run_command.call_args[0][0]
            self.assertIn("arjun", call_args)


if __name__ == "__main__":
    unittest.main()