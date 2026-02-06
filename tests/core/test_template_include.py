import pytest

from nettacker.core.template import TemplateLoader


def test_template_loader_include_merges_payloads():
    content = TemplateLoader(
        "wappalyzer_scan",
        {
            "target": "owasp.org",
            "user_agent": "curl/8.4.0",
        },
    ).load()
    assert content["info"]["name"] == "wappalyzer_scan"
    assert content.get("payloads"), "Included module payloads should be present after merge"


def test_template_loader_include_detects_cycles(tmp_path, monkeypatch):
    # Create two temporary modules with circular includes.
    from nettacker.config import Config

    modules_dir = tmp_path / "modules"
    (modules_dir / "scan").mkdir(parents=True)

    (modules_dir / "scan" / "a.yaml").write_text(
        "include: b_scan\ninfo:\n  name: a_scan\n  profiles: [scan]\n"
    )
    (modules_dir / "scan" / "b.yaml").write_text(
        "include: a_scan\ninfo:\n  name: b_scan\n  profiles: [scan]\n"
    )

    monkeypatch.setattr(Config.path, "modules_dir", modules_dir)

    with pytest.raises(ValueError):
        TemplateLoader("a_scan").load()

