"""Behavioural tests for the gitea_version_scan module.

The module is loaded through ``TemplateLoader``, the same path the engine uses, so
the regexes are tested after ``str.format`` has turned the ``{{``/``}}`` escapes
into literal braces. Each regex is then applied with ``re.findall``, as
``http.response_conditions_matched`` does, so a single capture group logs just the
version string.

The response bodies come from official Gitea container images (1.10 to 1.25 and
28.4.0, default settings and with REQUIRE_SIGNIN_VIEW, LANDING_PAGE, LANGS and
SHOW_FOOTER_POWERED_BY or APP_NAME changed), from Forgejo images (1.20, 1.21, 7 and 11,
also with SHOW_FOOTER_POWERED_BY = false) and from Gogs (0.11 template, 0.12 and 0.14
images).
"""

import re

import pytest

from nettacker.core.template import TemplateLoader

API_STEP = 0
FOOTER_STEP = 1


@pytest.fixture(scope="module")
def module():
    return TemplateLoader(
        "gitea_version_scan", {"target": "127.0.0.1", "user_agent": "Nettacker"}
    ).load()


@pytest.fixture(scope="module")
def steps(module):
    return module["payloads"][0]["steps"]


def content_regex(steps, index):
    return re.compile(steps[index]["response"]["conditions"]["content"]["regex"])


def extract_version(regex, body):
    return " ".join(sorted(set(re.findall(regex, body))))


# ---------------------------------------------------------------------------
# Module metadata / structure
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "gitea_version_scan"
    assert "gitea" in info["profiles"]
    assert "scan" in info["profiles"]


@pytest.mark.parametrize("index", [API_STEP, FOOTER_STEP])
def test_steps_target_expected_schemas_and_ports(steps, index):
    data = steps[index]["url"]["nettacker_fuzzer"]["data"]
    assert data["schema"] == ["http", "https"]
    # Gitea's default HTTP_PORT (3000) plus the common web ports.
    assert set(data["ports"]) == {80, 443, 3000}


def test_api_step_targets_version_endpoint(steps):
    assert steps[API_STEP]["url"]["nettacker_fuzzer"]["input_format"].endswith("/api/v1/version")


def test_footer_step_targets_home_and_sign_in_pages(steps):
    fuzzer = steps[FOOTER_STEP]["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/{paths}")
    # "/" redirects when LANDING_PAGE is not "home"; the sign-in page always renders
    # the footer, also with REQUIRE_SIGNIN_VIEW = true.
    assert fuzzer["data"]["paths"] == ["", "user/login"]


@pytest.mark.parametrize("index", [API_STEP, FOOTER_STEP])
def test_steps_require_http_200_and_log_content(steps, index):
    response = steps[index]["response"]
    assert response["condition_type"] == "and"
    assert response["conditions"]["status_code"]["regex"] == "200"
    assert response["log"] == "response_dependent['content']"


@pytest.mark.parametrize("index", [API_STEP, FOOTER_STEP])
def test_steps_do_not_follow_redirects(steps, index):
    assert steps[index]["allow_redirects"] is False


# ---------------------------------------------------------------------------
# /api/v1/version step
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # gitea/gitea:latest (28.4.0)
        ('{"version":"28.4.0"}', "28.4.0"),
        # gitea/gitea:1.10 ... 1.21 append a trailing newline
        ('{"version":"1.10.6"}\n', "1.10.6"),
        ('{"version":"1.21.11"}\n', "1.21.11"),
        ('{"version":"1.24.7"}', "1.24.7"),
        # gitea/gitea:1.24-nightly (release branch build)
        ('{"version":"1.24.7+2-g5ffd1e04ef"}', "1.24.7+2-g5ffd1e04ef"),
        # gitea.com development build
        ('{"version":"29.0.0+dev-160-g55186ca39b"}', "29.0.0+dev-160-g55186ca39b"),
        # release candidate
        ('{"version":"1.22.0-rc1"}', "1.22.0-rc1"),
        # pretty-printed JSON
        ('{\n  "version": "1.22.0"\n}', "1.22.0"),
    ],
)
def test_api_logs_only_the_version(steps, body, expected):
    assert extract_version(content_regex(steps, API_STEP), body) == expected


@pytest.mark.parametrize(
    "body",
    [
        # Forgejo 7+ (and Codeberg) report their own version with a +gitea- suffix
        '{"version":"11.0.16+gitea-1.22.0"}',
        '{"version":"17.0.0-100-2254cb0+gitea-1.22.0"}',
        # Forgejo 1.20 / 1.21 report "X.Y.Z+N"
        '{"version":"1.20.6+1"}',
        '{"version":"1.21.11+2"}',
        # REQUIRE_SIGNIN_VIEW = true: the API returns 403 with this body
        '{"message":"Only signed in user is allowed to call APIs."}',
        # other applications with a version field but a different shape
        '{"version":"1.0.0","name":"other"}',
        '{"status":"ok"}',
        '{"version":""}',
        "",
    ],
)
def test_api_no_false_positive(steps, body):
    assert re.findall(content_regex(steps, API_STEP), body) == []


# ---------------------------------------------------------------------------
# Page footer step
# ---------------------------------------------------------------------------

PAGE_HEAD = (
    '<!DOCTYPE html>\n<html lang="en-US">\n<head>\n'
    "\t<title>Sign In - Gitea: Git with a cup of tea</title>\n</head>\n<body>\n"
)
FOOTER_RIGHT = '\t<div class="right-links" role="group" aria-label="Links"></div>\n</footer>'


def page(footer, head=PAGE_HEAD):
    return head + footer + "\n</body>\n</html>"


def gitea_head(app_name):
    """Head of a Gitea sign-in page with a custom APP_NAME (quotes are escaped)."""
    return (
        '<!DOCTYPE html>\n<html lang="en-US" data-theme="gitea-auto">\n<head>\n'
        f"\t<title>Sign In - {app_name}</title>\n"
        f'\t<meta property="og:title" content="{app_name}">\n'
        f'\t<meta property="og:site_name" content="{app_name}">\n'
        "</head>\n<body>\n"
    )


# 28.4.0: version wrapped in a <span>
FOOTER_28 = (
    '<footer class="page-footer" role="group" aria-label="Footer">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n'
    '\t\t\t<a target="_blank" href="https://about.gitea.com">Powered by Gitea</a>\n'
    "\t\t\n\t\t\n\t\t\t<span>\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t28.4.0\n\t\t\t\n\t\t\t</span>\n"
    "\t\t\n\t\t\n\t\t\t<span>\n\t\t\t\tPage: <strong>21ms</strong>\n"
    "\t\t\t\tTemplate: <strong>21ms</strong>\n\t\t\t</span>\n\t\t\n\t\t\n\t</div>\n" + FOOTER_RIGHT
)
# 1.20 - 1.25: rel attribute on the link and no <span> around the version
FOOTER_124 = (
    '<footer class="page-footer" role="group" aria-label="Footer">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n'
    '\t\t\t<a target="_blank" rel="noopener noreferrer" href="https://about.gitea.com">'
    "Powered by Gitea</a>\n\t\t\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.24.7\n\t\t\t\n\t\t\n"
    "\t\t\n\t\t\tPage: <strong>3ms</strong>\n\t\t\tTemplate: <strong>3ms</strong>\n\t\t\n"
    "\t</div>\n" + FOOTER_RIGHT
)
# 1.22+ with SHOW_FOOTER_POWERED_BY = false: the Gitea link is removed
FOOTER_NO_POWERED_BY = (
    '<footer class="page-footer" role="group" aria-label="Footer">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n\t\t\n'
    "\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.24.7\n\t\t\t\n\t\t\n\t\t\n"
    "\t\t\tPage: <strong>2ms</strong>\n\t\t\tTemplate: <strong>1ms</strong>\n\t\t\n"
    "\t</div>\n" + FOOTER_RIGHT
)
# 1.24 with LANGS = zh-CN,...: the label is localized
FOOTER_ZH = (
    '<footer class="page-footer" role="group" aria-label="页脚">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="关于软件">\n\t\t\n'
    '\t\t\t<a target="_blank" rel="noopener noreferrer" href="https://about.gitea.com">'
    "Powered by Gitea</a>\n\t\t\n\t\t\n\t\t\t当前版本:\n\t\t\t\n\t\t\t\t1.24.7\n\t\t\t\n"
    "\t\t\n\t\t\n\t\t\t页面: <strong>1ms</strong>\n\t\t\t模板: <strong>1ms</strong>\n"
    "\t\t\n\t</div>\n" + FOOTER_RIGHT
)
# 1.24-nightly: "+" is HTML-escaped; the footer reports the release the build is based on
FOOTER_NIGHTLY = FOOTER_124.replace("1.24.7\n", "1.24.7&#43;2-g5ffd1e04ef\n")
# 1.18 - 1.25 footer as rendered for a signed-in administrator
FOOTER_ADMIN = FOOTER_124.replace("1.24.7\n", '<a href="/-/admin/config">1.24.7</a>\n')
# 1.19: <div class="ui left"> directly inside the footer, gitea.io link
FOOTER_119 = (
    '<footer role="group" aria-label="Footer">\n'
    '\t<div class="ui left" role="contentinfo" aria-label="About Software">\n'
    '\t\t<a target="_blank" rel="noopener noreferrer" href="https://gitea.io">'
    "Powered by Gitea</a>\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.19.4\n\t\t\t\n\t\t\n"
    "\t\t\n\t\t\tPage: <strong>6ms</strong>\n\t\t\tTemplate: <strong>5ms</strong>\n\t\t\n"
    '\t</div>\n\t<div class="ui right links" role="group" aria-label="Links"></div>\n'
    "</footer>"
)
# 1.18: <div class="ui container"> wrapper; French default language
FOOTER_118_FR = (
    '<footer>\n\t<div class="ui container">\n\t\t<div class="ui left">\n'
    '\t\t\t<a target="_blank" rel="noopener noreferrer" href="https://gitea.io">'
    "Propulsé par Gitea</a>\n\t\t\t\t\n\t\t\t\tVersion:\n\t\t\t\t\t\n\t\t\t\t\t\t1.18.5\n"
    "\t\t\t\t\t\n\t\t\t\t\n\t\t\t\t\n\t\t\t\tPage: <strong>1ms</strong>\n"
    "\t\t\t\tModèle: <strong>0ms</strong>\n\t\t\t\n\t\t</div>\n"
    '\t\t<div class="ui right links"></div>\n\t</div>\n</footer>'
)
# 1.17: plain "Powered by Gitea" text, label and version on separate lines
FOOTER_117 = (
    '<footer>\n\t<div class="ui container">\n\t\t<div class="ui left">\n'
    "\t\t\tPowered by Gitea\n\t\t\t\n\t\t\t\tVersion:\n\t\t\t\t\n\t\t\t\t\t1.17.4\n"
    "\t\t\t\t\n\t\t\t\n\t\t\t\n\t\t\t\tPage: <strong>5ms</strong>\n"
    "\t\t\t\tTemplate\n\t\t\t\t: <strong>4ms</strong>\n\t\t\t\n\t\t</div>\n"
    '\t\t<div class="ui right links"></div>\n\t</div>\n</footer>'
)
# 1.11 - 1.16: "Powered by Gitea Version: x Page: ..." on one line
FOOTER_113 = (
    '<footer>\n\t<div class="ui container">\n\t\t<div class="ui left">\n'
    "\t\t\tPowered by Gitea Version: 1.13.7 Page: <strong>10ms</strong> "
    "Template: <strong>10ms</strong>\n\t\t</div>\n"
    '\t\t<div class="ui right links"></div>\n\t</div>\n</footer>'
)
# 1.10: copyright sign instead of "Powered by"
FOOTER_110 = (
    '<footer>\n\t<div class="ui container">\n\t\t<div class="ui left">\n'
    "\t\t\t© Gitea Version: 1.10.6 Page: <strong>63ms</strong> "
    "Template: <strong>62ms</strong>\n\t\t</div>\n"
    '\t\t<div class="ui right links"></div>\n\t</div>\n</footer>'
)
# SHOW_FOOTER_VERSION = false: the link stays, the version is removed
FOOTER_HIDDEN = (
    '<footer class="page-footer" role="group" aria-label="Footer">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n'
    '\t\t\t<a target="_blank" href="https://about.gitea.com">Powered by Gitea</a>\n'
    "\t\t\n\t\t\n\t\t\n\t\t\t<span>\n\t\t\t\tPage: <strong>23ms</strong>\n"
    "\t\t\t\tTemplate: <strong>22ms</strong>\n\t\t\t</span>\n\t\t\n\t\t\n\t</div>\n" + FOOTER_RIGHT
)
# Forgejo 11: same markup as Gitea 1.20+
FORGEJO_PAGE = (
    '<!DOCTYPE html>\n<html lang="en-US" data-theme="forgejo-auto">\n<head>\n'
    '\t<meta name="keywords" content="git,forge,forgejo">\n</head>\n<body>\n'
    '<footer class="page-footer" role="group" aria-label="Footer">\n'
    '\t<div class="left-links" role="contentinfo" aria-label="About this software">\n'
    '\t\t\t<a target="_blank" rel="noopener noreferrer" href="https://forgejo.org">'
    "Powered by Forgejo</a>\n\t\t\tVersion:\n\t\t\t\t11.0.16\n"
    "\t\t\tPage: <strong>3ms</strong>\n\t</div>\n" + FOOTER_RIGHT + "\n</body>\n</html>"
)
# Forgejo 11 with SHOW_FOOTER_POWERED_BY = false: the footer has no Forgejo link, so only
# Forgejo's own page markup identifies it (default theme, Help link, built-in emoji list)
FORGEJO_HEAD = (
    '<!DOCTYPE html>\n<html lang="en-US" data-theme="forgejo-auto">\n<head>\n'
    "\t<title>Sign in - Forgejo: Beyond coding. We forge.</title>\n"
    "\t<script>\n\twindow.config = {\n"
    '\t\tcustomEmojis: {"codeberg":":codeberg:","forgejo":":forgejo:","git":":git:"},\n'
    "\t};\n\t</script>\n</head>\n<body>\n"
    '<a class="item" target="_blank" rel="noopener noreferrer" '
    'href="https://forgejo.org/docs/latest/">Help</a>\n'
)
FOOTER_FORGEJO_NO_POWERED_BY = FOOTER_NO_POWERED_BY.replace("1.24.7", "11.0.16").replace(
    'aria-label="About Software"', 'aria-label="About this software"'
)
# Forgejo 1.20 / 1.21 set the theme as a class on <html>
FORGEJO_121_HEAD = (
    '<!DOCTYPE html>\n<html lang="en-US" class="theme-forgejo-auto">\n<head>\n'
    "\t<title>Sign In - Forgejo: Beyond coding. We forge.</title>\n</head>\n<body>\n"
)
# Gogs 0.11 template with SHOW_FOOTER_VERSION: same markup as Gitea 1.10 - 1.18
FOOTER_GOGS = (
    '<footer>\n\t<div class="ui container">\n\t\t<div class="ui left">\n'
    "\t\t\t© 2020 Gogs Version: 0.11.91.0811 Page: <strong>1ms</strong> "
    "Template: <strong>1ms</strong>\n\t\t</div>\n"
    '\t\t<div class="ui right links"></div>\n\t</div>\n</footer>'
)


@pytest.mark.parametrize(
    "footer, expected",
    [
        (FOOTER_28, "28.4.0"),
        (FOOTER_124, "1.24.7"),
        (FOOTER_NO_POWERED_BY, "1.24.7"),
        (FOOTER_ZH, "1.24.7"),
        (FOOTER_NIGHTLY, "1.24.7"),
        (FOOTER_ADMIN, "1.24.7"),
        (FOOTER_119, "1.19.4"),
        (FOOTER_118_FR, "1.18.5"),
        (FOOTER_117, "1.17.4"),
        (FOOTER_113, "1.13.7"),
        (FOOTER_110, "1.10.6"),
    ],
    ids=[
        "28.4.0",
        "1.24",
        "1.24-no-powered-by",
        "1.24-zh-CN",
        "1.24-nightly",
        "1.24-admin-link",
        "1.19",
        "1.18-fr-FR",
        "1.17",
        "1.13",
        "1.10",
    ],
)
def test_footer_logs_only_the_version(steps, footer, expected):
    assert extract_version(content_regex(steps, FOOTER_STEP), page(footer)) == expected


@pytest.mark.parametrize(
    "app_name, footer, expected",
    [
        ("Migrated from forgejo", FOOTER_124, "1.24.7"),
        ("Forgejo to Gitea", FOOTER_28, "28.4.0"),
        ("Migrated from forgejo", FOOTER_117, "1.17.4"),
        # Gitea escapes quotes in APP_NAME, so it cannot spell Forgejo's markup
        (
            "&#34;forgejo&#34;:&#34;:forgejo:&#34; data-theme=&#34;forgejo-auto&#34;",
            FOOTER_NO_POWERED_BY,
            "1.24.7",
        ),
    ],
    ids=["1.24", "28.4.0", "1.17", "escaped-markup"],
)
def test_footer_detects_gitea_whose_site_name_mentions_forgejo(steps, app_name, footer, expected):
    body = page(footer, head=gitea_head(app_name))
    assert extract_version(content_regex(steps, FOOTER_STEP), body) == expected


@pytest.mark.parametrize(
    "body",
    [
        page(FOOTER_HIDDEN),
        FORGEJO_PAGE,
        # Forgejo 1.20 / 1.21 footer
        page(
            FOOTER_124.replace("https://about.gitea.com", "https://forgejo.org")
            .replace("Powered by Gitea", "Powered by Forgejo")
            .replace("1.24.7", "1.21.11&#43;2")
        ),
        page(FOOTER_FORGEJO_NO_POWERED_BY, head=FORGEJO_HEAD),
        page(FOOTER_FORGEJO_NO_POWERED_BY, head=FORGEJO_121_HEAD),
        # each Forgejo marker on its own is enough
        page(FOOTER_NO_POWERED_BY, head=PAGE_HEAD + '<a href="https://forgejo.org/docs/">'),
        page(FOOTER_NO_POWERED_BY, head=PAGE_HEAD + '{"forgejo":":forgejo:"}'),
        page(
            FOOTER_NO_POWERED_BY,
            head=PAGE_HEAD.replace("<html", '<html data-theme="forgejo-dark"'),
        ),
        page(
            FOOTER_NO_POWERED_BY,
            head=PAGE_HEAD.replace("<html", '<html class="theme-forgejo-auto"'),
        ),
        page(FOOTER_GOGS),
        # a Version label without Gitea's footer markup
        page("<footer>Version: 2.4.1</footer>"),
        page('<footer><a href="https://example.org">Other app</a> Version: 2.4.1</footer>'),
        # an old-style footer block that does not name Gitea
        page('<footer><div class="ui container"><div class="ui left">Version: 2.4.1</div>'),
        # Gitea markup outside the footer
        page('<main><a href="https://about.gitea.com">Gitea</a>Dependency Version: 2.4.1</main>'),
        page('<div class="left-links"><a href="https://about.gitea.com">Gitea</a></div>'),
        page(
            '<p>Built with <a href="https://about.gitea.com">Gitea</a></p>'
            "<footer><div>Version: 9.9.9</div></footer>"
        ),
        # the version in a later element, after the footer block has closed
        page(
            '<footer class="page-footer"><div class="left-links">'
            '<a href="https://about.gitea.com">Powered by Gitea</a></div>'
            "<div>Version: 9.9.9</div></footer>"
        ),
        "",
    ],
    ids=[
        "version-hidden",
        "forgejo-11",
        "forgejo-1.21",
        "forgejo-11-no-powered-by",
        "forgejo-1.21-no-powered-by",
        "marker-forgejo-link",
        "marker-forgejo-emoji",
        "marker-forgejo-data-theme",
        "marker-forgejo-theme-class",
        "gogs-0.11",
        "plain-footer",
        "other-app-footer",
        "old-markup-without-gitea",
        "gitea-link-in-main",
        "left-links-outside-footer",
        "gitea-link-outside-footer",
        "version-after-footer-block",
        "empty",
    ],
)
def test_footer_no_false_positive(steps, body):
    assert re.findall(content_regex(steps, FOOTER_STEP), body) == []
