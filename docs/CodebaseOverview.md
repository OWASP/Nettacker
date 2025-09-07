## OWASP Nettacker Codebase Overview
OWASP Nettacker is an open‑source, Python‑based framework for automated penetration testing and information gathering. It supports modular tasks such as port scanning, service detection, subdomain enumeration, vulnerability scans, and credential brute forcing, all driven by a unified CLI, REST API, and Web UI.


## Project layout

```
.
├── docs
├── nettacker
│   ├── api
│   ├── core
│   │   ├── lib
│   │   └── utils
│   ├── database
│   ├── lib
│   │   ├── compare_report
│   │   ├── graph
│   │   │   ├── d3_tree_v1
│   │   │   └── d3_tree_v2
│   │   ├── html_log
│   │   ├── icmp
│   │   └── payloads
│   │       ├── User-Agents
│   │       ├── passwords
│   │       └── wordlists
│   ├── locale
│   ├── modules
│   │   ├── brute
│   │   ├── scan
│   │   └── vuln
│   └── web
│       └── static
│           ├── css
│           ├── fonts
│           ├── img
│           │   └── flags
│           │       ├── 1x1
│           │       └── 4x3
│           ├── js
│           └── report
└── tests
    ├── api
    ├── core
    │   ├── lib
    │   └── utils
    ├── database
    └── lib
        └── payloads

```

- **Entry point** – `nettacker/main.py` creates a `Nettacker` application instance and runs it when invoked via the provided script or CLI
- **Core engine (`nettacker/core`)**
  - `app.py` orchestrates scans: parsing arguments, expanding targets (including IP ranges and subdomains), launching multiprocess/multithread modules, and generating reports
  - `module.py` loads YAML-defined modules, applies service discovery results, expands payload loops, and dispatches protocol-specific engines in threaded fashion
  - `arg_parser.py`, `ip.py`, `messages.py`, and `utils` provide CLI parsing, IP range handling, internationalized messages, and common helpers
  - Protocol engines reside in `core/lib` (e.g., HTTP, FTP, SSH, SMTP, socket) and are invoked by modules
- **Modules (`nettacker/modules`)** – Scanning logic is defined declaratively in YAML under three categories (`brute`, `scan`, `vuln`). Each module contains an `info` block and a list of `payloads` that specify library, request parameters, fuzzing rules, and response conditions. Example: `dir_scan` performs directory discovery over HTTP using wordlists and response conditions
- **Database layer (`nettacker/database`)** – Uses SQLAlchemy to interface with SQLite, MySQL, or PostgreSQL for persisting events and reports
- **API & Web UI (`nettacker/api`, `nettacker/web`)** – Flask-based REST API plus static assets enabling web‑based scan management
- **Supporting libraries (`nettacker/lib`)** – Reporting helpers, ICMP tools, graph generation, and payload wordlists
- **Configuration** – `config.py` defines default paths, database settings, and runtime options
- **Tests** – The `tests` directory includes unit tests and validation checks; for example, `test_yaml_regexes.py` ensures regex definitions in YAML modules compile correctly
- **Build & dependencies** – `pyproject.toml` defines the project as a Poetry package and lists dependencies such as `aiohttp`, `multiprocess`, `paramiko`, and `sqlalchemy`

## Important concepts
- **Modular architecture:** Modules are YAML files; the engine interprets them and runs protocol-specific steps.
- **Target expansion:** Before scanning, the engine normalizes URLs, enumerates IP ranges, resolves subdomains, and runs preliminary checks like ICMP and port scans
- **Service discovery:** Results from `port_scan` feed into subsequent modules, allowing conditional execution based on discovered services. Service discovery can be turned off during scans using `-d` or `--skip-service-discovery` run-time option.
- **Concurrency:** Scans are distributed across processes and threads for performance, with configurable limits per host and module using the `-t` and `-M` runtime options. The requests can be rate-limited using the `-w` option.

## Where to go next
- **Documentation:** Review `docs/Installation.md` and `docs/Usage.md` for setup and basic usage; `docs/Modules.md` explains module types and parameters; `docs/Developers.md` covers contribution guidelines and how to add languages or modules
- **Explore modules:** Study YAML files under `nettacker/modules/*` to see how scans, brute-force checks, and vulnerability tests are structured.
- **Understand protocol engines:** Read files in `nettacker/core/lib/` to learn how HTTP, socket, and other protocol interactions are implemented.
- **Run locally:** Use the CLI (`nettacker`) or Docker instructions in [Installation](Installation.md) and [Usage](Usage.md)
- **Contribute:** Follow the guidelines in `docs/Developers.md` and run `make pre-commit` and `make test` before submitting changes.
