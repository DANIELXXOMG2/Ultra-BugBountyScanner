#!/usr/bin/env python3
"""Tests for bucket_scanner module."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

from modules.bucket_scanner import scan_buckets


class TestBucketScanner(unittest.TestCase):
    """Test cases for bucket_scanner module."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_domain = "example.com"
        self.test_output_dir = Path("/tmp/test_output")
        self.buckets_dir = self.test_output_dir / self.test_domain / "buckets"
        self.subdomains_file = self.test_output_dir / self.test_domain / "subdomains" / "all_subdomains.txt"

    @patch("modules.bucket_scanner.run_command")
    @patch("modules.bucket_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_success(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test successful bucket scanning."""
        # Mock successful s3scanner execution
        mock_run_command.return_value = ("Found bucket: example-bucket\nFound bucket: test-bucket\n", None)
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock subdomains file content
        subdomains_content = "www.example.com\napi.example.com\ncdn.example.com\n"
        
        with patch("builtins.open", mock_open(read_data=subdomains_content)) as mock_file:
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify s3scanner was called
            mock_run_command.assert_called_once()
            args = mock_run_command.call_args[0][0]
            self.assertIn("s3scanner", args)
            
            # Verify results were written
            mock_file.assert_called()

    @patch("modules.bucket_scanner.run_command")
    @patch("modules.bucket_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_missing_tool(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test behavior when s3scanner is missing."""
        # Mock directory operations
        mock_exists.return_value = True
        
        # Mock missing tool
        with patch("modules.bucket_scanner.run_command", side_effect=FileNotFoundError("s3scanner not found")):
            with patch("builtins.open", mock_open(read_data="www.example.com\n")):
                scan_buckets(self.test_domain, self.test_output_dir)

                # Verify error was logged
                mock_logger.error.assert_called()

    @patch("modules.bucket_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_missing_subdomains_file(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock) -> None:
        """Test behavior when all_subdomains.txt doesn't exist."""
        # Mock directory operations
        mock_exists.side_effect = lambda: False if "all_subdomains.txt" in str(self) else True
        
        with patch("builtins.open", mock_open()):
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify warning was logged
            mock_logger.warning.assert_called()

    @patch("modules.bucket_scanner.run_command")
    @patch("modules.bucket_scanner.logger")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_s3scanner_failure(self, mock_exists: Mock, mock_mkdir: Mock, mock_logger: Mock, mock_run_command: Mock) -> None:
        """Test behavior when s3scanner fails."""
        # Mock s3scanner failure
        mock_run_command.return_value = (None, "s3scanner failed")
        
        # Mock directory operations
        mock_exists.return_value = True

        # Mock subdomains file content
        subdomains_content = "www.example.com\n"
        
        with patch("builtins.open", mock_open(read_data=subdomains_content)):
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify error was logged
            mock_logger.error.assert_called()

    @patch("modules.bucket_scanner.run_command")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_empty_subdomains_file(self, mock_exists: Mock, _mock_mkdir: Mock, mock_run_command: Mock) -> None:
        """Test behavior when subdomains file is empty."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock empty subdomains file
        with patch("builtins.open", mock_open(read_data="")):
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify s3scanner was not called (no bucket names to scan)
            mock_run_command.assert_not_called()

    @patch("modules.bucket_scanner.run_command")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_bucket_name_generation(self, mock_exists: Mock, mock_mkdir: Mock, mock_run_command: Mock) -> None:
        """Test bucket name generation logic."""
        # Mock subdomain file exists and has content
        mock_exists.return_value = True
        subdomains_content = "api.example.com\nwww.example.com\ntest.example.com"

        # Mock successful s3scanner execution
        mock_run_command.return_value = ("success", "")

        with patch("builtins.open", mock_open(read_data=subdomains_content)):
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify s3scanner was called
            mock_run_command.assert_called_once()
            
            # Verify the command contains s3scanner
            call_args = mock_run_command.call_args[0][0]
            self.assertIn("s3scanner", call_args)

    @patch("modules.bucket_scanner.run_command")
    @patch("pathlib.Path.mkdir")
    @patch("pathlib.Path.exists")
    def test_scan_buckets_results_processing(self, mock_exists: Mock, _mock_mkdir: Mock, mock_run_command: Mock) -> None:
        """Test processing and saving of s3scanner results."""
        # Mock directory and file operations
        mock_exists.return_value = True

        # Mock subdomains file content
        subdomains_content = "api.example.com"

        # Mock s3scanner output with various bucket states
        s3scanner_output = (
            "example-assets - bucket_exists:True - bucket_empty:False - acl_read:True - acl_write:False\n"
            "api-example - bucket_exists:True - bucket_empty:True - acl_read:False - acl_write:False\n"
            "nonexistent-bucket - bucket_exists:False - bucket_empty:False - acl_read:False - acl_write:False"
        )

        mock_run_command.return_value = (s3scanner_output, "")

        with patch("builtins.open", mock_open(read_data=subdomains_content)) as mock_file:
            scan_buckets(self.test_domain, self.test_output_dir)

            # Verify results were processed and saved
            write_calls = [call for call in mock_file().write.call_args_list]

            # Check that both text and JSON results were written
            self.assertTrue(any("s3scanner_results.txt" in str(call) for call in mock_file.call_args_list))
            self.assertTrue(any("bucket_scan_summary.json" in str(call) for call in mock_file.call_args_list))


if __name__ == "__main__":
    unittest.main()