from os.path import abspath, dirname, join

import pytest

import nettacker.api.engine as engine

project_root = dirname(dirname(dirname(__file__)))
nettacker_dir = abspath(join(project_root, "nettacker"))
tests_dir = abspath(join(project_root, "tests"))


@pytest.fixture(autouse=True)
def api_test_state(tmp_path):
    original_app_config = dict(engine.app.config)
    original_results_dir = engine.nettacker_path_config.results_dir
    original_application_config = dict(engine.nettacker_application_config)

    engine.app.config["TESTING"] = True
    engine.app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": "test-key",
        "api_access_log": "",
        "api_cert": None,
        "api_cert_key": None,
        "api_client_whitelisted_ips": [],
        "language": "en",
        "options": None,
    }
    engine.nettacker_path_config.results_dir = tmp_path

    yield

    engine.app.config.clear()
    engine.app.config.update(original_app_config)
    engine.nettacker_path_config.results_dir = original_results_dir
    engine.nettacker_application_config.clear()
    engine.nettacker_application_config.update(original_application_config)


@pytest.fixture
def api_client():
    return engine.app.test_client()


@pytest.fixture
def api_key():
    return "test-key"
