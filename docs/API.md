# Nettacker Web UI and API

Nettacker includes a Web UI and an HTTP API for starting scans and reading stored results.
Both are served by the same process.

Only use Nettacker against systems you are authorized to test. API clients can start intrusive
modules, including vulnerability checks and credential brute-force attempts.

## Contents

- [Start the API](#start-the-api)
- [Authentication](#authentication)
- [Submit a scan](#submit-a-scan)
- [Upload target and wordlist files](#upload-target-and-wordlist-files)
- [Scan lifecycle and identifiers](#scan-lifecycle-and-identifiers)
- [Endpoint reference](#endpoint-reference)
- [Compare scans](#compare-scans)
- [Errors](#errors)
- [Production and security guidance](#production-and-security-guidance)

## Start the API

The shortest way to start the Web UI and API is:

```bash
nettacker --start-api
```

With no additional API arguments, Nettacker:

- listens on `0.0.0.0:5000`, making the service available through every network interface allowed
  by the host firewall;
- generates a random API key and prints it in the API console;
- serves HTTPS using an ad-hoc self-signed certificate;
- accepts connections from any client IP address because the client whitelist is empty;
- writes API requests to `.nettacker/data/nettacker.log`.

On the same machine, open `https://127.0.0.1:5000/` and enter the printed API key in the Web UI.
The browser will warn about the temporary self-signed certificate. Do not expose this default
configuration to an untrusted network. Use an explicit bind address, strong persistent key, trusted
certificate, and network restrictions for anything beyond local testing.

Start the server on the loopback interface while testing locally:

```bash
nettacker --start-api \
  --api-host 127.0.0.1 \
  --api-port 5000 \
  --api-access-key 'replace-with-a-long-random-secret'
```

The Web UI is then available at `https://127.0.0.1:5000/`.

When no certificate is supplied, Nettacker creates an ad-hoc self-signed TLS certificate. Browsers
and HTTP clients will not trust that certificate automatically. Supply a certificate and matching
private key for a trusted TLS configuration:

```bash
nettacker --start-api \
  --api-host 127.0.0.1 \
  --api-port 5000 \
  --api-access-key 'replace-with-a-long-random-secret' \
  --api-cert /path/to/server.crt \
  --api-cert-key /path/to/server.key
```

If `--api-access-key` is omitted, Nettacker generates a random key and prints it in the API console.
Supplying an explicit key is recommended for repeatable deployments.

### API startup options

| Option | Meaning |
| --- | --- |
| `--start-api` | Start the Web UI and API server. |
| `--api-host HOST` | Bind address. The configured default is `0.0.0.0`; use `127.0.0.1` unless remote access is required. |
| `--api-port PORT` | Listening port; default `5000`. |
| `--api-access-key KEY` | Shared API key. A random key is generated when this is omitted. |
| `--api-client-whitelisted-ips VALUE` | Comma-separated IP addresses, ranges, or CIDRs permitted to connect. |
| `--api-access-log FILE` | Access-log path. The default is `.nettacker/data/nettacker.log`. |
| `--api-cert FILE` | TLS certificate. Use with `--api-cert-key`. |
| `--api-cert-key FILE` | TLS private key. Use with `--api-cert`. |
| `--api-debug-mode` | Enable Flask debug mode. Never enable this on an exposed server. |

For Docker, publish the API port and bind Nettacker to all container interfaces:

```bash
docker run --rm -p 5000:5000 owasp/nettacker \
  --start-api \
  --api-host 0.0.0.0 \
  --api-access-key 'replace-with-a-long-random-secret'
```

## Authentication

Protected endpoints expect the shared key in a request parameter or a cookie named `key`. Nettacker
checks, in order:

1. the query string;
2. form data;
3. cookies.

JSON request bodies are not used for authentication or scan parameters. Send
`application/x-www-form-urlencoded` data, or `multipart/form-data` when uploading a file.

### Direct authentication

The shortest form is a query parameter:

```python
import os

import requests

base_url = "https://127.0.0.1:5000"
api_key = os.environ["NETTACKER_API_KEY"]

response = requests.get(
    f"{base_url}/results/get_list",
    params={"key": api_key, "page": 1},
    verify=False,  # Local ad-hoc certificate only; verify trusted certificates normally.
    timeout=30,
)
response.raise_for_status()
print(response.json())
```

Avoid putting keys in URLs in shared environments because URLs are commonly retained in logs and
browser history.

### Cookie session

For multiple calls, exchange the key for a secure, HTTP-only cookie:

```python
import os

import requests

base_url = "https://127.0.0.1:5000"
session = requests.Session()
session.verify = False  # Local ad-hoc certificate only.

login = session.post(
    f"{base_url}/session/set",
    data={"key": os.environ["NETTACKER_API_KEY"]},
    timeout=30,
)
login.raise_for_status()

check = session.get(f"{base_url}/session/check", timeout=30)
check.raise_for_status()
print(check.json())
```

End the cookie session with `GET /session/kill`.

## Submit a scan

Use `POST /new/scan`. A minimal port scan looks like this:

```python
response = session.post(
    f"{base_url}/new/scan",
    data={
        "targets": "192.0.2.10",
        "selected_modules": "port_scan",
        "ports": "22,80,443",
        "report_path_filename": "api-port-scan.json",
    },
    timeout=30,
)
response.raise_for_status()
print(response.json())
```

`192.0.2.0/24` is reserved for documentation. Replace it with an authorized target.

The request must include:

- `report_path_filename`;
- exactly one target source: `targets` or an uploaded `targets_list` token;
- at least one module source: `selected_modules` or `profiles`.

`report_path_filename` is reduced to its basename and stored under
`.nettacker/data/results/`. Client-supplied parent directories are discarded. API scan submissions
currently accept `.html`, `.htm`, `.txt`, `.json`, and `.csv`, or a filename without an extension.

Module names and profile names come from the installed version. Use `nettacker --show-all-modules`
and `nettacker --show-all-profiles` on the server to list them.

### Common scan parameters

| Parameter | Format and behavior |
| --- | --- |
| `targets` | Comma-separated hosts, IP addresses, ranges, CIDRs, or domain names. |
| `selected_modules` | Comma-separated module IDs, such as `port_scan,http_status_scan`; `all` selects every module. |
| `profiles` | Comma-separated profile names; `all` selects every module. |
| `report_path_filename` | Required report basename and output format. |
| `ports` | Comma-separated ports and inclusive ranges, for example `22,80,443,8000-8010`. |
| `excluded_ports` | Ports and ranges to exclude. |
| `excluded_modules` | Comma-separated module IDs to exclude. |
| `schema` | `http`, `https`, or both separated by a comma. |
| `usernames` | Comma-separated usernames for supported brute-force modules. |
| `passwords` | Comma-separated passwords for supported brute-force modules. |
| `timeout` | Per-request timeout in seconds. |
| `retries` | Number of connection attempts. |
| `time_sleep_between_requests` | Delay in seconds between requests. |
| `thread_per_host` | Maximum concurrent module requests per host. |
| `parallel_module_scan` | Maximum modules processed concurrently within a target group. |
| `set_hardware_usage` | `low`, `normal`, `high`, or `maximum`; controls target process grouping. |
| `scan_subdomains` | Enable subdomain enumeration before the selected modules run. |
| `scan_ip_range` | For a single IP, request its registered range from RIPE and scan that range. Explicit ranges and CIDRs are expanded without this parameter. |
| `ping_before_scan` | Require a successful ICMP check before continuing. ICMP requires appropriate operating-system privileges. |
| `skip_service_discovery` | Skip the preliminary port scan and run selected modules without service filtering. |
| `http_header` | One or more `Name: value` headers separated by newlines. Sensitive headers are removed from stored event data. |
| `user_agent` | Custom HTTP user agent, or `random_user_agent`. |
| `socks_proxy` | SOCKS proxy URL, for example `socks5://127.0.0.1:9050`. |
| `graph_name` | Graph renderer for HTML output, such as `d3_tree_v2_graph`; omit it for non-HTML output. |
| `language` | Installed locale identifier; default `en`. |
| `modules_extra_args` | Module-specific values encoded as `name=value&other=value`. |

For boolean options, send `true` only when enabling the option and omit the field when it is false.
In particular, `skip_service_discovery` is enabled only by the exact lowercase value `true`.

## Upload target and wordlist files

The API does not accept server filesystem paths for `targets_list`, `usernames_list`,
`passwords_list`, or `read_from_file`. Upload the file first, then submit the returned token under
the matching scan parameter.

### 1. Upload the file

Send `POST /upload/file` as `multipart/form-data` with:

- `file`: the file contents;
- `param_name`: one of `targets_list`, `usernames_list`, `passwords_list`, or `read_from_file`.

```python
with open("targets.txt", "rb") as target_file:
    upload = session.post(
        f"{base_url}/upload/file",
        data={"param_name": "targets_list"},
        files={"file": target_file},
        timeout=30,
    )

upload.raise_for_status()
target_token = upload.json()["msg"]
```

### 2. Submit the token

```python
response = session.post(
    f"{base_url}/new/scan",
    data={
        "targets_list": target_token,
        "selected_modules": "port_scan",
        "report_path_filename": "uploaded-targets.json",
    },
    timeout=30,
)
response.raise_for_status()
```

Upload constraints:

- maximum file size: 10 MiB;
- accepted extensions: `.txt`, `.csv`, `.lst`, and `.list`;
- tokens are tied to the `param_name` used during upload;
- tokens expire after 15 minutes;
- tokens do not survive an API restart;
- `targets_list`, `usernames_list`, and `passwords_list` files are consumed and removed when the
  scan is submitted;
- `read_from_file` is retained until API shutdown because modules may read it while the scan runs.

Treat the returned `msg` as an opaque token. Do not decode it or replace it with a path.

## Scan lifecycle and identifiers

`POST /new/scan` validates the request, starts the scan in a background thread, and immediately
returns the normalized scan options. HTTP `200` means the scan was accepted; it does not mean the
scan has completed.

There is currently no job-status or cancellation endpoint, and the submission response does not
return the scan ID. Poll `GET /results/get_list?page=1` for a completed report.

The API exposes two different identifiers:

- `id`: the numeric database report ID used by `/results/get`, `/results/get_json`, and
  `/results/get_csv`;
- `scan_id`: the scan's unique string identifier, used by `/compare/scans`.

Do not pass a `scan_id` where an endpoint expects `id`.

## Endpoint reference

Except where noted, endpoints require the shared API key or a valid cookie session.

| Method | Endpoint | Parameters | Result |
| --- | --- | --- | --- |
| `GET`, `POST` | `/` | None | Public Web UI. |
| `POST` | `/upload/file` | Multipart `file`, `param_name` | Upload token in `msg`. |
| `POST` | `/new/scan` | Form-encoded scan options | Normalized options; scan starts asynchronously. |
| `POST` | `/compare/scans` | `scan_id_first`, `scan_id_second`, optional `compare_report_path` | Writes a comparison report. |
| `GET`, `POST` | `/session/set` | `key` | Sets a secure API-key cookie. |
| `GET` | `/session/check` | None | Confirms that the current key or cookie is valid. |
| `GET` | `/session/kill` | None | Public endpoint that expires the key cookie. |
| `GET` | `/results/get_list` | Optional `page`, default `1` | Up to 10 completed scan reports, newest first. |
| `GET` | `/results/get` | Numeric report `id` | Downloads the stored report in its original format. |
| `GET` | `/results/get_json` | Numeric report `id` | Downloads that scan's events as JSON. |
| `GET` | `/results/get_csv` | Numeric report `id` | Downloads that scan's events as CSV. |
| `GET` | `/logs/get_list` | Optional `page`, default `1` | Up to 10 targets with aggregated event information. |
| `GET` | `/logs/get_html` | `target` | HTML report containing all stored events for the target. |
| `GET` | `/logs/get_json` | `target` | JSON download containing all stored events for the target. |
| `GET` | `/logs/get_csv` | `target` | CSV download containing all stored events for the target. |
| `GET` | `/logs/search` | Optional `q`, optional `page` | Search stored targets and event fields. |

### List and download completed reports

```python
reports = session.get(
    f"{base_url}/results/get_list",
    params={"page": 1},
    timeout=30,
)
reports.raise_for_status()

for report in reports.json():
    print(report["id"], report["scan_id"], report["report_path_filename"])
```

Download the original report using its numeric `id`:

```python
report_id = reports.json()[0]["id"]
download = session.get(
    f"{base_url}/results/get",
    params={"id": report_id},
    timeout=30,
)
download.raise_for_status()

with open("nettacker-report", "wb") as output_file:
    output_file.write(download.content)
```

Use `/results/get_json` or `/results/get_csv` with the same numeric ID to convert stored events to
those formats.

### Read events by target

The `/logs/*` endpoints aggregate events for a target across stored scans:

```python
events = session.get(
    f"{base_url}/logs/get_json",
    params={"target": "192.0.2.10"},
    timeout=30,
)
events.raise_for_status()
print(events.json())
```

Search matches target, date, module name, port, event content, and scan ID:

```python
matches = session.get(
    f"{base_url}/logs/search",
    params={"q": "port_scan", "page": 1},
    timeout=30,
)
matches.raise_for_status()
print(matches.json())
```

## Compare scans

Use the unique `scan_id` values returned by `/results/get_list`, not the numeric report IDs:

```python
comparison = session.post(
    f"{base_url}/compare/scans",
    data={
        "scan_id_first": "first-scan-id",
        "scan_id_second": "second-scan-id",
        "compare_report_path": "comparison.json",
    },
    timeout=30,
)
comparison.raise_for_status()
print(comparison.json())
```

The comparison report is written under `.nettacker/data/results/`. Supported suffixes are `.html`,
`.htm`, `.json`, and `.csv`; other suffixes produce a text report. When
`compare_report_path` is omitted, Nettacker creates a timestamped JSON filename.

A successful response is:

```json
{
  "status": "success",
  "msg": "scan_comparison_completed"
}
```

## Errors

Handled errors normally use this structure:

```json
{
  "status": "error",
  "msg": "error description"
}
```

Common status codes:

| Status | Meaning |
| --- | --- |
| `400` | Missing or invalid parameters, invalid output filename, or invalid upload token. |
| `401` | Missing or invalid API key. |
| `403` | Client address is not permitted by the configured whitelist. |
| `404` | Route, scan data, or comparison scan ID was not found. |
| `500` | Unexpected server or database failure. |

An empty page may return a JSON message with `status` set to `finished` rather than an HTTP error.

## Production and security guidance

The built-in server is Flask's development server. It is useful for local operation and testing but
is not a hardened multi-user service.

Before allowing remote access:

- bind to loopback unless remote access is necessary;
- place the service behind appropriate network controls and a production TLS/reverse-proxy setup;
- use `--api-client-whitelisted-ips` as an additional restriction when clients connect directly;
- set a strong explicit API key and rotate it if disclosed;
- protect and rotate the API access log: it records the full URL and submitted form fields, which may
  include API keys, target information, usernames, or passwords;
- do not enable `--api-debug-mode`;
- remember that the shared API key provides no per-user identity, role separation, or per-user audit
  trail;
- apply external request rate limits and resource controls where required;
- persist and back up `.nettacker/data/` if scan history must survive container replacement.

When Nettacker runs behind a reverse proxy, IP whitelisting evaluates the immediate connection's
source address. Configure network controls with that behavior in mind.
