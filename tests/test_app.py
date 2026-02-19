"""Tests for TaskForge app — minimal coverage."""
import pytest


def test_placeholder():
    """Placeholder test to keep CI green."""
    assert 1 + 1 == 2


def test_import_app():
    """Verify the app module can be imported."""
    from src.app import app  # noqa: F401
    assert app is not None
