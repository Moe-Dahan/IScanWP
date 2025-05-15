# IScanWP

**WordPress Vulnerability Scanner**

IScanWP is a command-line utility for enumerating and testing WordPress sites. It leverages the WordPress REST API along with Selenium browser automation to detect core versions, plugins, users, routes, exposed settings, and potential CVEs. Optional brute‑force against `wp-login.php` is supported, as well as an on‑demand search for known plugin exploits.

## Features

* Detect WordPress core version via HTML meta generator
* Enumerate plugin namespaces using the REST API
* List available REST routes and identify sensitive endpoints
* Enumerate registered users and check for exposed application passwords
* Test `wp/v2/settings` for public GET and writeable POST
* **Optional** automated CVE/Exploit search for detected plugins (`-s`/`--search`)
* Optional brute-force attack against `wp-login.php` with a password list
* Output results to console and save to a text file

## Prerequisites

* Python 3.8+
* Firefox browser
* GeckoDriver in your PATH

### Python packages

```bash
pip install -r requirements.txt
```

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Moe-Dahan/IScanWP.git
   cd IScanWP
   ```
2. Ensure `geckodriver` is installed and accessible:

   * Download from [Mozilla GeckoDriver releases](https://github.com/mozilla/geckodriver/releases)
   * Move to `/usr/local/bin` or add to your PATH

## Usage

```bash
python iscanwp.py -t <target_url> [-s] [-f <password_file>] [-o <output_file>]
```

### Arguments

* `-t`, `--target` **(required)**

  * Target site URL (e.g., `https://example.com`)
* `-s`, `--search` **(optional)**

  * Enable plugin CVE/exploit search
* `-f`, `--file` **(optional)**

  * Path to a newline-separated password file for brute‑force
* `-o`, `--output` **(optional)**

  * Path to save scan results (text file)

### Examples

* Basic scan:

  ```bash
  python iscanwp.py -t https://victim.com
  ```

* Scan with plugin exploit search:

  ```bash
  python iscanwp.py -t https://victim.com -s
  ```

* Scan with brute-force and search:

  ```bash
  python iscanwp.py -t https://victim.com -s -f passwords.txt
  ```

* Scan and save output:

  ```bash
  python iscanwp.py -t https://victim.com -o results.txt
  ```

## Output Structure

Results saved to the output file include sections for:

1. WordPress version
2. Detected plugin namespaces
3. Enumerated usernames and IDs
4. Discovered REST routes
5. Useful links (CVE/exploit search results)
6. Valid credentials (from brute‑force)

## Notes

* Ensure you have permission to scan the target site.
* Running automated scans or brute‑force attacks without authorization may be illegal.

## License

MIT License

---

*Use at your own risk.*

