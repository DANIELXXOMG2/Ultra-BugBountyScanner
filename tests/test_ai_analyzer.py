"""Pruebas unitarias para el módulo de análisis de IA."""

from typing import Any
import unittest
from unittest.mock import MagicMock, patch

from utils.ai_analyzer import GENAI_AVAILABLE, get_gemini_summary


class TestAIAnalyzer(unittest.TestCase):
    """Pruebas para el analizador de IA con Gemini."""

    def test_get_gemini_summary_without_genai(self) -> None:
        """Prueba que la función retorne None cuando genai no está disponible."""
        if not GENAI_AVAILABLE:
            result = get_gemini_summary("test-api-key", "test scan results")
            self.assertIsNone(result)

    def test_get_gemini_summary_empty_params(self) -> None:
        """Prueba que la función retorne None con parámetros vacíos."""
        result = get_gemini_summary("", "")
        self.assertIsNone(result)

        result = get_gemini_summary("api-key", "")
        self.assertIsNone(result)

        result = get_gemini_summary("", "scan-results")
        self.assertIsNone(result)

    @patch("utils.ai_analyzer.genai")
    @patch("utils.ai_analyzer.GENAI_AVAILABLE", True)
    def test_get_gemini_summary_success(self, mock_genai: Any) -> None:
        """Prueba el caso exitoso de generación de resumen."""
        # Configurar mock
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "## Resumen Ejecutivo\nTest summary"
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        # Ejecutar función
        result = get_gemini_summary("test-api-key", "test scan results")

        # Verificar resultado
        self.assertEqual(result, "## Resumen Ejecutivo\nTest summary")
        mock_genai.configure.assert_called_once_with(api_key="test-api-key")
        mock_genai.GenerativeModel.assert_called_once_with("gemini-1.5-flash-latest")
        mock_model.generate_content.assert_called_once()

    @patch("utils.ai_analyzer.genai")
    @patch("utils.ai_analyzer.GENAI_AVAILABLE", True)
    def test_get_gemini_summary_api_error(self, mock_genai: Any) -> None:
        """Prueba el manejo de errores de la API."""
        # Configurar mock para lanzar excepción
        mock_genai.configure.side_effect = Exception("API Error")

        # Ejecutar función
        result = get_gemini_summary("test-api-key", "test scan results")

        # Verificar que retorna None en caso de error
        self.assertIsNone(result)

    @patch("utils.ai_analyzer.genai")
    @patch("utils.ai_analyzer.GENAI_AVAILABLE", True)
    def test_get_gemini_summary_empty_response(self, mock_genai: Any) -> None:
        """Prueba el caso donde Gemini retorna respuesta vacía."""
        # Configurar mock
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = ""
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        # Ejecutar función
        result = get_gemini_summary("test-api-key", "test scan results")

        # Verificar que retorna None
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
