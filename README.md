\# ReconX



\*\*Smart Web Content Discovery for Authorized Security Testing\*\*



ReconX is a Python-based web content discovery tool designed to identify accessible paths on web applications using a wordlist. It supports concurrent requests, response analysis, filtering, and multiple report formats.



> \*\*Version:\*\* 1.0.0



\## Features



\- \*\*Wordlist-based discovery:\*\* Test candidate paths against a target web application.

\- \*\*Concurrent scanning:\*\* Use multiple worker threads to improve scanning efficiency.

\- \*\*Rate limiting:\*\* Control the request rate.

\- \*\*Wildcard detection:\*\* Identify potentially misleading responses returned for nonexistent paths.

\- \*\*Response analysis:\*\* Record HTTP status codes, response sizes, content types, and body hashes.

\- \*\*Redirect handling:\*\* Record redirect destinations without automatically following redirects.

\- \*\*Filtering:\*\* Filter results by HTTP status code and exclude redirects.

\- \*\*Duplicate detection:\*\* Group responses with matching characteristics.

\- \*\*Request error handling:\*\* Record failed requests and handle unexpected worker errors.

\- \*\*Multiple report formats:\*\* Export results as CSV, JSON, and HTML.

\- \*\*Configuration profiles:\*\* Reuse supported scan settings.

\- \*\*Maximum request limits:\*\* Limit the number of wordlist candidates processed.



\## Requirements



\- Python 3.10 or newer recommended

\- pip

\- Dependencies listed in `requirements.txt`



\## Installation



Clone the repository:



```bash

git clone https://github.com/RishiRz/ReconX

cd ReconX

```



Create a virtual environment:



\*\*Windows PowerShell\*\*



```powershell

python -m venv venv

.\\venv\\Scripts\\Activate.ps1

```



Install dependencies:



```powershell

python -m pip install -r requirements.txt

```



If PowerShell blocks virtual-environment activation, you can run the environment's Python directly:



```powershell

.\\venv\\Scripts\\python.exe -m pip install -r requirements.txt

```



\## Usage



Display the available commands:



```powershell

python reconx.py --help

```



Display scan options:



```powershell

python reconx.py scan --help

```



Example scan against an authorized target:



```powershell

python reconx.py scan -u http://127.0.0.1:8000 -w wordlists/test.txt

```



Set a request timeout:



```powershell

python reconx.py scan -u http://127.0.0.1:8000 -w wordlists/test.txt --timeout 2

```



Show request errors:



```powershell

python reconx.py scan -u http://127.0.0.1:8000 -w wordlists/test.txt --show-errors

```



Export results to CSV, JSON, and HTML:



```powershell

python reconx.py scan -u http://127.0.0.1:8000 -w wordlists/test.txt --csv reports/results.csv --output reports/results.json --html reports/results.html

```



\*\*Note:\*\* Available options may depend on your current CLI implementation. Run `python reconx.py scan --help` for the authoritative list.



\## Local Testing



You can test ReconX against a local HTTP server.



Start the server in one terminal:



```powershell

python -m http.server 8000 --directory testsite

```



Run ReconX from a second terminal:



```powershell

python reconx.py scan -u http://127.0.0.1:8000 -w wordlists/test.txt

```



Keep the target limited to systems you own or are explicitly authorized to assess.



\## Running Tests



Install pytest if it is not already available:



```powershell

python -m pip install pytest

```



Run the test suite:



```powershell

python -m pytest -q

```



The v1.0.0 development verification completed with \*\*34 passing tests and zero failures\*\*.



\## Output Formats



| Format | Option | Purpose |

|---|---|---|

| CSV | `--csv` | Tabular results |

| JSON | `--output` | Structured results and summary |

| HTML | `--html` | Browser-readable report |



Report fields and included error details depend on the selected format and configuration.



\## Limitations



\- Discovery results depend on the supplied wordlist and scan configuration.

\- Wildcard detection is heuristic and may produce false positives or false negatives.

\- A discovered path is not necessarily a vulnerability.

\- Connection failures can result from timeouts, network restrictions, or unavailable services.

\- ReconX is a content discovery tool, not a complete vulnerability scanner.



\## Responsible Use



Use ReconX only against systems you own or have explicit permission to test. Follow applicable laws, engagement rules, and rate limits. Avoid disrupting services or accessing data without authorization.



\## Roadmap



Potential future improvements include:



\- More robust connection and DNS error classification

\- Additional automated tests

\- Improved report customization

\- Better scan configuration and documentation

\- Continuous integration with automated tests



\## License



No license has been specified yet. Add a license file before publishing the project for reuse by others.



\---



\*\*ReconX v1.0.0\*\* — built for authorized web security testing and learning.

