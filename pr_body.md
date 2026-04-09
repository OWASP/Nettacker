## Proposed change

Adds a new detection module for **CVE-2024-0012**, a critical authentication bypass vulnerability in Palo Alto Networks PAN-OS software.

The detection logic relies on an Nginx path confusion exploit primitive:
- Sends an HTTP GET request to `/php/ztp_gate.php/.js.map`
- Injects the `X-PAN-AUTHCHECK: off` header (which the vulnerable Nginx proxy fails to override due to the missing `proxy_default.conf` include on `.js.map` URIs)
- Matches on HTTP `200` AND `<title>Zero Touch Provisioning</title>` in the response body.

This logic is designed to **minimize false positives** because patched hosts correctly decline the bypass (returning an HTTP 302 redirect to `/php/login.php`), and non-target generic web servers are unlikely to contain the PAN-OS-specific ZTP page title.

## Type of change

- [ ] New core framework functionality
- [ ] Bugfix (non-breaking change which fixes an issue)
- [ ] Code refactoring without any functionality changes
- [x] New or existing module/payload change
- [ ] Documentation/localization improvement
- [x] Test coverage improvement
- [ ] Dependency upgrade
- [ ] Other improvement (best practice, cleanup, optimization, etc)

## Checklist

- [x] I've followed the [contributing guidelines][contributing-guidelines]
- [x] I have **digitally signed** all my commits in this PR
- [x] I've run `make pre-commit` and confirm it didn't generate any warnings/changes
- [x] I've run `make test`, I confirm all tests passed locally
- [x] I've added/updated any relevant documentation in the `docs/` folder 
- [ ] I've linked this PR with an open issue
- [x] I've tested and verified that my code works as intended and resolves the issue as described
- [ ] I have attached screenshots demonstrating my code works as intended
- [x] I've checked all other open PRs to avoid submitting duplicate work
- [x] I confirm that the code and comments in this PR are not direct unreviewed outputs of AI
- [x] I confirm that I am the Sole Responsible Author for every line of code, comment, and design decision

[contributing-guidelines]: https://nettacker.readthedocs.io/en/latest/Developers/
