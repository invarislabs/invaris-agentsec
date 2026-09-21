import re
import sys
from pathlib import Path

import pytest

import agentsec

ROOT = Path(__file__).resolve().parent.parent


def pyproject_text():
    return (ROOT / "pyproject.toml").read_text()


def test_version_matches_between_package_and_pyproject_and_changelog():
    m = re.search(r'^version = "([^"]+)"', pyproject_text(), re.M)
    assert m and m.group(1) == agentsec.__version__
    assert "## %s" % agentsec.__version__ in (ROOT / "CHANGELOG.md").read_text()


def test_required_project_files_exist():
    for name in ("LICENSE", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"):
        assert (ROOT / name).is_file(), name


def test_metadata_declares_license_and_urls():
    text = pyproject_text()
    assert 'license = "Apache-2.0"' in text and "[project.urls]" in text


def test_json_schemas_are_declared_as_package_data():
    text = pyproject_text()
    for pkg in ("agentsec.policies", "agentsec.traces"):
        assert '"%s" = ["*.json"]' % pkg in text
        assert list((ROOT / pkg.replace(".", "/")).glob("*.json"))


def test_release_workflow_is_valid_yaml_and_runs_tests_before_publishing():
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    assert wf["jobs"]["publish"]["needs"] == "build"
    assert any(s.get("run") == "pytest" for s in wf["jobs"]["build"]["steps"])
