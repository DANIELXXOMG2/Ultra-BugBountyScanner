#!/usr/bin/env python3
"""Test Logic Module.

Pruebas basadas en propiedades usando Hypothesis para las funciones principales.
Author: danielxxomg2
"""

import os
from pathlib import Path
import shutil

# Importar la función a testear
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scanner_main import setup_directories
from utils.ai_analyzer import format_scan_data_for_ai, get_gemini_summary
from utils.notifications import format_scan_summary, send_discord_notification


class TestSetupDirectories(unittest.TestCase):
    """Pruebas para la función setup_directories usando Hypothesis."""

    def setUp(self) -> None:
        """Configurar el entorno de prueba."""
        self.test_base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_base_dir)

    @given(
        domains=st.lists(
            st.builds(
                lambda name, tld: f"{name}.{tld}",
                name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=10),
                tld=st.sampled_from(["com", "org", "net", "edu", "gov"]),
            ),
            min_size=1,
            max_size=3,
        )
    )
    @settings(deadline=1000, suppress_health_check=[HealthCheck.filter_too_much])
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


class TestDiscordNotifications(unittest.TestCase):
    """Pruebas para las funciones de notificaciones de Discord."""

    @patch("utils.notifications.requests.post")
    def test_send_discord_notification_success(self, mock_post: Mock) -> None:
        """Prueba el envío exitoso de notificaciones a Discord."""
        # Configurar mock para respuesta exitosa
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook_url = "https://discord.com/api/webhooks/test"
        message = "Test message"

        result = send_discord_notification(webhook_url, message)

        self.assertTrue(result, "La notificación debe enviarse exitosamente")
        mock_post.assert_called_once()

        # Verificar que se llamó con los parámetros correctos
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], webhook_url)
        self.assertEqual(call_args[1]["json"]["content"], message)

    @patch("utils.notifications.requests.post")
    def test_send_discord_notification_failure(self, mock_post: Mock) -> None:
        """Prueba el manejo de errores en notificaciones de Discord."""
        # Configurar mock para respuesta de error
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        webhook_url = "https://discord.com/api/webhooks/test"
        message = "Test message"

        result = send_discord_notification(webhook_url, message)

        self.assertFalse(result, "La notificación debe fallar con status 400")

    def test_send_discord_notification_invalid_input(self) -> None:
        """Prueba la validación de entrada para notificaciones de Discord."""
        with self.assertRaises(ValueError):
            send_discord_notification("", "message")

        with self.assertRaises(ValueError):
            send_discord_notification("webhook_url", "")

    def test_format_scan_summary(self) -> None:
        """Prueba el formateo de resúmenes de escaneo."""
        domains = ["example.com", "test.org"]
        duration = 45.67  # Usar duración menor a 60 segundos
        output_dir = "/path/to/output"

        summary = format_scan_summary(
            domains=domains, duration=duration, output_dir=output_dir, total_subdomains=50, total_vulnerabilities=3
        )

        self.assertIn("example.com, test.org", summary)
        self.assertIn("45.7 segundos", summary)  # Verificar formato correcto
        self.assertIn("/path/to/output", summary)
        self.assertIn("50", summary)
        self.assertIn("3", summary)


class TestAIAnalyzer(unittest.TestCase):
    """Pruebas para las funciones de análisis con IA."""

    @patch("utils.ai_analyzer.genai")
    def test_get_gemini_summary_success(self, mock_genai: Mock) -> None:
        """Prueba la generación exitosa de resúmenes con Gemini."""
        # Configurar mocks
        mock_model = Mock()
        mock_response = Mock()
        mock_response.text = "AI generated summary"
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        api_key = "test_api_key"
        scan_results = "Test scan results"

        result = get_gemini_summary(api_key, scan_results)

        self.assertEqual(result, "AI generated summary")
        mock_genai.configure.assert_called_once_with(api_key=api_key)
        mock_genai.GenerativeModel.assert_called_once_with("gemini-pro")
        mock_model.generate_content.assert_called_once()

    @patch("utils.ai_analyzer.genai")
    def test_get_gemini_summary_failure(self, mock_genai: Mock) -> None:
        """Prueba el manejo de errores en Gemini."""
        # Configurar mock para lanzar excepción
        mock_genai.configure.side_effect = Exception("API Error")

        api_key = "test_api_key"
        scan_results = "Test scan results"

        result = get_gemini_summary(api_key, scan_results)

        self.assertIsNone(result, "Debe retornar None en caso de error")

    def test_get_gemini_summary_invalid_input(self) -> None:
        """Prueba la validación de entrada para Gemini."""
        with self.assertRaises(ValueError):
            get_gemini_summary("", "scan_results")

        with self.assertRaises(ValueError):
            get_gemini_summary("api_key", "")

    @patch("utils.ai_analyzer.Path")
    def test_format_scan_data_for_ai(self, mock_path: Mock) -> None:
        """Prueba el formateo de datos para análisis de IA."""
        # Configurar mock para archivos
        mock_subdomains_file = Mock()
        mock_subdomains_context = Mock()
        mock_subdomains_context.read.return_value = "sub1.example.com\nsub2.example.com"
        mock_subdomains_file.open.return_value.__enter__ = Mock(return_value=mock_subdomains_context)
        mock_subdomains_file.open.return_value.__exit__ = Mock(return_value=None)

        mock_ports_file = Mock()
        mock_ports_context = Mock()
        mock_ports_context.read.return_value = "80/tcp open\n443/tcp open"
        mock_ports_file.open.return_value.__enter__ = Mock(return_value=mock_ports_context)
        mock_ports_file.open.return_value.__exit__ = Mock(return_value=None)

        def mock_path_func(filename: str) -> Mock:
            if "subdomains.txt" in str(filename):
                return mock_subdomains_file
            if "ports.txt" in str(filename):
                return mock_ports_file
            mock_empty = Mock()
            mock_empty_context = Mock()
            mock_empty_context.read.return_value = ""
            mock_empty.open.return_value.__enter__ = Mock(return_value=mock_empty_context)
            mock_empty.open.return_value.__exit__ = Mock(return_value=None)
            return mock_empty

        mock_path.side_effect = mock_path_func

        result = format_scan_data_for_ai(subdomains_file="subdomains.txt", ports_file="ports.txt")

        self.assertIn("SUBDOMINIOS ENCONTRADOS", result)
        self.assertIn("ESCANEO DE PUERTOS", result)
        self.assertIn("sub1.example.com", result)
        self.assertIn("80/tcp open", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
