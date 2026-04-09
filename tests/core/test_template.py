from nettacker.core.template import TemplateLoader
from nettacker.core.template import Config


def test_template_loader_initialization():
    loader = TemplateLoader("port_scan_scan")
    assert loader is not None


def test_template_loader_open(tmp_path, monkeypatch):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(parents=True)
    module_file = scan_dir / "port_scan.yaml"
    module_file.write_text("name: test\n", encoding="utf-8")

    monkeypatch.setattr(Config.path, "modules_dir", tmp_path)

    loader = TemplateLoader("port_scan_scan")
    content = loader.open()
    assert content is not None
    assert isinstance(content, str)
