# External Services Configuration

Nettacker uses several external OSINT services to perform scans (e.g., Subdomain Scan). While most services offer a free tier (often limited by rate), you can provide your own API keys to access higher limits and more results.

## Configuration

You can provide API keys directly via command-line arguments.

### Supported Services

| Service | Argument | Key Source |
| :--- | :--- | :--- |
| **Netlas.io** | `--netlas-api-key` | [Register](https://netlas.io/pricing/) -> Profile |
| **HackerTarget** | `--hackertarget-api-key` | [Membership](https://hackertarget.com/scan-membership/) |
| **CertSpotter** | `--certspotter-api-key` | [SSLMate Account](https://sslmate.com/) |
| **URLScan.io** | `--urlscan-api-key` | [Register](https://urlscan.io/pricing/) |
| **DNSDumpster** | `--dnsdumpster-api-key` | [Membership](https://dnsdumpster.com/membership/) |

### Usage Example

To run a subdomain scan using your Netlas and URLScan API keys:

For a single service API key
```bash
python nettacker.py -m subdomain_scan -t example.com --netlas-api-key "YOUR_NETLAS_KEY"
```

For multiple service API keys
```bash
python nettacker.py -m subdomain_scan -t example.com --netlas-api-key "YOUR_NETLAS_KEY" --urlscan-api-key "YOUR_URLSCAN_KEY"
```

### Notes
*   **Optional Keys**: If you do not provide a key, Nettacker will automatically attempt to use the free/anonymous tier of the service.
*   **Rate Limits**: Providing an API key significantly increases the number of requests you can make per day.
