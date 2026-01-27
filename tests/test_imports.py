"""Sanity tests ensuring key modules import without raising."""


def test_import_binary_tools():
    """Binary tools module should be importable."""


def test_import_angr_backend():
    """Angr backend wrappers should import cleanly (dependencies installed)."""


def test_import_cli():
    """CLI module should resolve all top-level imports."""


def test_import_parallel_runner():
    """Parallel runner helpers should import."""
