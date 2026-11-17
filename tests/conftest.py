import pytest


@pytest.fixture
def make_tree(tmp_path):
    """Create files from a {relative_path: content} mapping and return the root."""

    def _make(files):
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return tmp_path

    return _make
