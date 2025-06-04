Im still learning, and what better way to learn and code, this is how this script came to light, the aim is for me to be able to automate the whole wordpress recon process or most of it at least. This script is still a work
in progress, I will be updating it as I go along and have time to do so.

# IScanWP: WordPress Vulnerability Scanner

IScanWP is a comprehensive command-line utility designed to scan and identify vulnerabilities in WordPress sites. It uses the WordPress REST API, Selenium, and various other techniques to detect

   - WordPress core versions

   - Installed plugins and potential CVEs

   - Registered users and possible exposed passwords

   - Sensitive endpoints like /wp/v2/settings and /wp/v2/users

   - SQL injection, XSS vulnerabilities, and missing security headers

The tool also supports brute-force attacks against wp-login.php using a password list, and it can perform a custom scan for known plugin exploits.
Features

   - WordPress Version Detection: Identifies the WordPress version via the HTML meta tag.

   - Plugin Enumeration: Enumerates installed plugin namespaces through the REST API.

   - Exploit Search: Search for known CVEs and exploits for identified plugins.

   - User Enumeration: Scans the /wp/v2/users endpoint for registered users.

   - Settings Exposure: Tests if sensitive settings are exposed via the /wp/v2/settings endpoint.

   - Writable Settings Test: Checks for writeable settings via POST requests.

   - Directory Bruteforce: Force test for common WordPress subdirectories and custom paths.

   - SQL Injection Testing: Scan for SQL injection vulnerabilities.

   - XSS Testing: Checks for common Cross-Site Scripting (XSS) vulnerabilities.

   - Brute-Force Login: Attempts to brute-force wp-login.php with a custom password list.

   - Security Headers: Identifies missing security headers like X-Content-Type-Options, X-Frame-Options, etc.

   - Result Export: Optionally saves results to a text file for further analysis.

# Prerequisites

   Python 3.8+

   Firefox browser (for Selenium-based automation)

- GeckoDriver (required for Selenium)

## Installation

   Clone the repository:

      git clone https://github.com/Moe-Dahan/IScanWP.git
      cd IScanWP
      
   Install required Python packages by running:
    
    pip install -r requirements.txt
    
   - Ensure GeckoDriver is installed and accessible.

# Usage

To run a scan, use the following command:

python iscanwp.py -t <target_url> [-sD <sub_list>] [-sI <sql_list>] [-p <password_file>] [-o <output_file>]

Arguments

    -t, --target (required):

        The target WordPress site URL (e.g., https://example.com).

    -sD, --sub_list (optional):

        Path to a list of subdirectories to brute-force.

    -sI, --sql_list (optional):

        Path to a list of SQL payloads for SQL injection testing.

    -p, --file (optional):

        Path to a password file (newline-separated) for brute-forcing wp-login.php.

    -o, --output (optional):

        Path to save scan results to a text file.

# Examples

    Basic Scan (detect WordPress version, plugins, users, routes):

python iscanwp.py -t https://victim.com
 - Scan with Plugin Exploit Search (automatically search for CVEs)

python iscanwp.py -t https://victim.com -sD /path/to/subdirs.txt
 - Scan with Directory Bruteforce (using custom subdirectory list)
 - if left blank will do a common scan of subdirectories
   
python iscanwp.py -t https://victim.com -sI /path/to/sql_payloads.txt
 - SQL Injection Test (scan using custom SQL injection payloads)
 - if left blank will do a common sqli test

python iscanwp.py -t https://victim.com -p /path/to/passwords.txt
 - Brute-Force Login (using a password file for brute-force testing)

python iscanwp.py -t https://victim.com -o path/to/output/results.txt
 - Output Structure

The output saved to a text file includes the following sections:

    WordPress Version: Detected WordPress version.

    Detected Plugins: List of plugin namespaces.

    Useful Links: URLs for plugin CVEs or exploits found.

    Enumerated Users: List of user IDs and slugs.

    Found Routes: REST API routes discovered (e.g., /wp/v2/users, /wp/v2/settings).

    Writable Settings: Endpoints with writeable settings via POST requests.

    Subdirectories: Found subdirectories through brute-forcing.

    SQL Injection: SQL injection payloads tested and their results.

    Security Headers: Missing security headers.

    XSS Vulnerabilities: Possible Cross-Site Scripting vulnerabilities.

    Valid Credentials: Successfully cracked credentials from brute-force attempts.

Important Notes

    Permissions: Always ensure you have permission to scan the target site. Unauthorized scanning or brute-force attacks may be illegal.

    Brute-Force Caution: Excessive requests may trigger rate-limiting or block the target site. Use brute-force with care.

    False Positives: While the tool is designed to identify vulnerabilities, always manually verify any findings.

License

This project is licensed under the MIT License.

Use at your own risk. IScanWP is intended for ethical use only with explicit permission from the site owner.
