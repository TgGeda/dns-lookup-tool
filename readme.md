<<<<<<< HEAD
dnspython
cachetools
beautifulsoup4
=======
# DNS Lookup Tool

## Description

The DNS Lookup Tool is a command-line utility that performs DNS lookups for given domain names. It uses multiple DNS servers with a weighted round-robin approach to distribute the queries. The tool can perform both simple and recursive DNS lookups and supports various output formats, including CSV, JSON, and HTML.

## Features

- Perform DNS lookups for multiple domain names.
- Use a weighted round-robin approach to distribute queries among multiple DNS servers.
- Cache results for 1 hour to improve performance.
- Output results in CSV, JSON, or HTML format.
- Log errors and debug information for troubleshooting.

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - `argparse`
  - `subprocess`
  - `random`
  - `csv`
  - `dns.resolver`
  - `re`
  - `logging`
  - `ipaddress`
  - `functools`
  - `time`
  - `concurrent.futures`
  - `cachetools`
  - `json`
  - `bs4`
  - `dns.exception`

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/TgGeda/dns-lookup-tool.git
    cd dns-lookup-tool
    ```

2. Install the required Python packages:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Command-Line Arguments

- `domains`: One or more domain names to lookup.
- `-d`, `--dns-server`: Custom DNS server address.
- `-r`, `--recursive`: Perform recursive DNS lookups.
- `-f`, `--format`: Output format (`csv`, `json`, `html`). Default is `csv`.

### Example Commands

1. Lookup a single domain and output results in CSV format:

    ```sh
    python dns_lookup_tool.py example.com
    ```

2. Lookup multiple domains with a custom DNS server and output results in JSON format:

    ```sh
    python dns_lookup_tool.py example.com example.org -d 8.8.8.8 -f json
    ```

3. Perform recursive DNS lookups and output results in HTML format:

    ```sh
    python dns_lookup_tool.py example.com -r -f html
    ```

## Output

### CSV

The results are saved in a file named `results.csv` with the following columns:

- Domain
- DNS Server
- NS Record
- IP Address

### JSON

The results are saved in a file named `results.json` with the following structure:

```json
[
    {
        "dns_server": "8.8.8.8",
        "domain": "example.com",
        "ip_address": "93.184.216.34",
        "ns_record": "ns1.example.com"
    },
    ...
]
```

### HTML

The results are saved in a file named `results.html` with a table containing the following columns:

- Domain
- DNS Server
- NS Record
- IP Address

## Logging

The tool logs information, warnings, and errors to the console. You can adjust the logging level by modifying the `logging.basicConfig` configuration in the script.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Contact

For any questions or suggestions, please open an issue on GitHub.
>>>>>>> e54c3a846f6dd604e548176931da655908a4c2a4
