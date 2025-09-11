#!/usr/bin/env python3
"""Test Logic Module.

Pruebas basadas en propiedades usando Hypothesis para las funciones principales.
Author: danielxxomg2
"""

from pathlib import Path
import shutil

# Importar la función a testear
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner_main import discover_web_assets, scan_vulnerabilities, setup_directories
from utils.notifications import send_discord_notification


class TestSetupDirectories(unittest.TestCase):
    """Pruebas para la función setup_directories usando Hypothesis."""

    def setUp(self) -> None:
        """Configurar el entorno de prueba."""
        self.test_base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_base_dir)

    @given(
        domains=st.lists(
            st.from_regex(r"[a-z0-9]+\.[a-z]{2,4}", fullmatch=True),
            min_size=1,
            max_size=2,
        )
    )
    @settings(suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_setup_directories_creates_structure(self, domains: list[str]) -> None:
        """Prueba que setup_directories crea la estructura correcta de directorios.

        Esta prueba verifica que:
        1. La función no lanza excepciones con dominios válidos
        2. Se crean todos los directorios esperados
        3. Los directorios tienen los permisos correctos
        """
        output_dir = Path(self.test_base_dir) / "test_output"

        # Ejecutar la función
        try:
            result = setup_directories(output_dir, domains)

            # Verificar que retorna True (éxito)
            self.assertTrue(result, "setup_directories debe retornar True en caso de éxito")

            # Verificar que el directorio base existe
            self.assertTrue(output_dir.exists(), "El directorio de salida debe existir")
            self.assertTrue(output_dir.is_dir(), "La salida debe ser un directorio")

            # Verificar que se crearon los subdirectorios para cada dominio
            for domain in domains:
                domain_dir = output_dir / domain
                self.assertTrue(domain_dir.exists(), f"El directorio para el dominio '{domain}' debe existir")
                self.assertTrue(domain_dir.is_dir(), f"'{domain}' debe ser un directorio")

                # Verificar subdirectorios esperados
                expected_subdirs = ["subdomains", "ports", "vulnerabilities"]
                for subdir in expected_subdirs:
                    subdir_path = domain_dir / subdir
                    self.assertTrue(subdir_path.exists(), f"El subdirectorio '{subdir}' debe existir para '{domain}'")
                    self.assertTrue(subdir_path.is_dir(), f"'{subdir}' debe ser un directorio para '{domain}'")

        except Exception as e:
            self.fail(f"setup_directories no debe lanzar excepciones con dominios válidos: {e}")

    def test_setup_directories_empty_list(self) -> None:
        """Prueba que setup_directories maneja correctamente una lista vacía de dominios."""
        output_dir = Path(self.test_base_dir) / "empty_test"

        result = setup_directories(output_dir, [])

        # Debe retornar True incluso con lista vacía
        self.assertTrue(result, "setup_directories debe manejar listas vacías")

        # El directorio base debe existir
        self.assertTrue(output_dir.exists(), "El directorio base debe crearse")

    def test_setup_directories_existing_directory(self) -> None:
        """Prueba que setup_directories maneja directorios existentes correctamente."""
        output_dir = Path(self.test_base_dir) / "existing_test"
        domains = ["example.com", "test.org"]

        # Crear el directorio previamente
        output_dir.mkdir(parents=True, exist_ok=True)

        # Ejecutar dos veces para verificar idempotencia
        result1 = setup_directories(output_dir, domains)
        result2 = setup_directories(output_dir, domains)

        self.assertTrue(result1, "Primera ejecución debe ser exitosa")
        self.assertTrue(result2, "Segunda ejecución debe ser exitosa (idempotente)")

        # Verificar que la estructura sigue siendo correcta
        for domain in domains:
            domain_dir = output_dir / domain
            self.assertTrue(domain_dir.exists(), f"Directorio '{domain}' debe existir")


class TestDiscoverWebAssets(unittest.TestCase):
    """Pruebas para la función discover_web_assets."""

    def setUp(self) -> None:
        """Configurar el entorno de prueba."""
        self.test_base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_base_dir)
        self.output_dir = Path(self.test_base_dir)
        self.domain = "example.com"

    @patch("scanner_main.run_command")
    def test_discover_web_assets_success(self, mock_run_command: Mock) -> None:
        """Prueba que discover_web_assets funciona correctamente y genera httpx_urls.txt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            domain = "example.com"
            output_dir = Path(temp_dir)
            subdomains_dir = output_dir / domain / "subdomains"
            subdomains_file = subdomains_dir / "all_subdomains.txt"
            web_dir = output_dir / domain / "web"
            httpx_output = web_dir / "httpx_live.txt"

            # Crear estructura de directorios y archivo de subdominios
            subdomains_dir.mkdir(parents=True)
            web_dir.mkdir(parents=True)
            subdomains_file.write_text("sub1.example.com\nsub2.example.com\n")

            # Simular salida de httpx
            httpx_output.write_text("https://sub1.example.com [200]\nhttps://sub2.example.com [200]\n")

            # Configurar mock
            mock_run_command.return_value = (0, "Output", "")

            # Ejecutar función
            discover_web_assets(domain, output_dir)

            # Verificar que se llamó a run_command
            self.assertTrue(mock_run_command.called)
            # Verificar que el comando contiene httpx
            call_args = mock_run_command.call_args[0][0]
            self.assertIn("httpx", call_args)

            # Verificar que se creó el archivo httpx_urls.txt
            urls_file = web_dir / "httpx_urls.txt"
            self.assertTrue(urls_file.exists(), "El archivo httpx_urls.txt debe ser creado")

            # Verificar el contenido del archivo de URLs
            urls_content = urls_file.read_text().strip().split("\n")
            expected_urls = ["https://sub1.example.com", "https://sub2.example.com"]
            self.assertEqual(urls_content, expected_urls, "Las URLs extraídas deben coincidir")

    def test_discover_web_assets_missing_subdomains(self) -> None:
        """Prueba que discover_web_assets maneja correctamente archivos faltantes."""
        with patch("scanner_main.logger") as mock_logger:
            discover_web_assets(self.domain, self.output_dir)
            mock_logger.warning.assert_called_once()


class TestScanVulnerabilities(unittest.TestCase):
    """Pruebas para la función scan_vulnerabilities."""

    def setUp(self) -> None:
        """Configurar el entorno de prueba."""
        self.test_base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_base_dir)
        self.output_dir = Path(self.test_base_dir)
        self.domain = "example.com"

    def test_scan_vulnerabilities_quick_mode(self) -> None:
        """Prueba que scan_vulnerabilities se salta en modo rápido."""
        with patch("scanner_main.logger") as mock_logger:
            scan_vulnerabilities(self.domain, self.output_dir, quick_mode=True)
            mock_logger.info.assert_called_with("Quick mode enabled, skipping vulnerability scanning")

    @patch("scanner_main.run_command")
    def test_scan_vulnerabilities_success(self, mock_run_command: Mock) -> None:
        """Prueba que scan_vulnerabilities funciona correctamente usando httpx_urls.txt."""
        with tempfile.TemporaryDirectory() as temp_dir:
            domain = "example.com"
            output_dir = Path(temp_dir)
            web_dir = output_dir / domain / "web"
            urls_file = web_dir / "httpx_urls.txt"

            # Crear estructura de directorios y archivo de URLs
            web_dir.mkdir(parents=True)
            urls_file.write_text("https://sub1.example.com\nhttps://sub2.example.com\n")

            # Configurar mock
            mock_run_command.return_value = (0, "Output", "")

            # Ejecutar función
            scan_vulnerabilities(domain, output_dir, quick_mode=False)

            # Verificar que se llamó a run_command
            self.assertTrue(mock_run_command.called)
            # Verificar que el comando contiene nuclei
            call_args = mock_run_command.call_args[0][0]
            self.assertIn("nuclei", call_args)
            # Verificar que usa el archivo httpx_urls.txt
            self.assertIn("httpx_urls.txt", str(call_args))

    def test_scan_vulnerabilities_missing_urls_file(self) -> None:
        """Prueba que scan_vulnerabilities maneja archivos httpx_urls.txt faltantes."""
        with patch("scanner_main.logger") as mock_logger:
            scan_vulnerabilities(self.domain, self.output_dir, quick_mode=False)
            # Verificar que se registra una advertencia sobre el archivo faltante
            mock_logger.warning.assert_called_once_with(
                f"URLs file not found: {self.output_dir / self.domain / 'web' / 'httpx_urls.txt'}"
            )


class TestDiscordNotifications(unittest.TestCase):
    """Pruebas para las notificaciones de Discord."""

    @patch("utils.notifications.requests.post")
    def test_send_discord_notification_success(self, mock_post: MagicMock) -> None:
        """Prueba que send_discord_notification funciona correctamente."""
        # Configurar mock para respuesta exitosa
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook_url = "https://discord.com/api/webhooks/test"
        message = "Test message"

        result = send_discord_notification(webhook_url, message)

        self.assertTrue(result)
        expected_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Ultra-BugBountyScanner/1.0",
        }
        mock_post.assert_called_once_with(webhook_url, json={"content": message}, headers=expected_headers, timeout=10)

    @patch("utils.notifications.requests.post")
    def test_send_discord_notification_failure(self, mock_post: MagicMock) -> None:
        """Prueba que send_discord_notification maneja errores correctamente."""
        # Configurar mock para respuesta de error
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        webhook_url = "https://discord.com/api/webhooks/test"
        message = "Test message"

        result = send_discord_notification(webhook_url, message)

        self.assertFalse(result)

    @patch("utils.notifications.requests.post")
    def test_send_discord_notification_exception(self, mock_post: MagicMock) -> None:
        """Prueba que send_discord_notification maneja excepciones."""
        # Configurar mock para lanzar excepción
        mock_post.side_effect = Exception("Connection error")

        webhook_url = "https://discord.com/api/webhooks/test"
        message = "Test message"

        result = send_discord_notification(webhook_url, message)

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
