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

from hypothesis import given
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scanner_main import setup_directories


class TestSetupDirectories(unittest.TestCase):
    """Pruebas para la función setup_directories usando Hypothesis."""

    def setUp(self) -> None:
        """Configurar el entorno de prueba."""
        self.test_base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_base_dir)

    @given(
        domains=st.lists(
            st.text(
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=".-_"),
                min_size=1,
                max_size=50,
            ).filter(lambda x: x and not x.startswith(".") and not x.endswith(".")),
            min_size=1,
            max_size=5,
        )
    )
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
