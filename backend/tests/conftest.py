import pytest


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    """Every test gets its own SQLite file, so running tests never touches a developer's real scan history."""
    path = tmp_path / "test.db"
    monkeypatch.setenv("CLOUDDOCTOR_DB_PATH", str(path))
    return path
