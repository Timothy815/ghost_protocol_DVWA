# GHOST PROTOCOL - FLAG KEY GUIDE

**Purpose**: This guide explains what constitutes the "flag" for each mission in Ghost Protocol. Each flag represents a successful exploitation or key finding from the vulnerability.

---

## OP-001: The Gatekeeper (Brute Force)

**Vulnerability**: Weak password authentication
**Exploitation**: Use Hydra to brute force login credentials
**Flag Format**: `password`
**How to Get It**:
1. Launch Hydra from terminal: `hydra -l admin -P /path/to/wordlist http://localhost/login.php`
2. Or manually try common passwords: `admin:password` is the default
3. Submit: `password`

**Why This Flag?**: The "key finding" from brute forcing is discovering the weak password itself.

---

## OP-002: The Pipeline (Command Injection)

**Vulnerability**: Unsanitized command execution
**Exploitation**: Inject shell commands into the parameter field
**Flag Format**: `flag{<your_proof_of_execution>}` — e.g., `flag{127.0.0.1; whoami}` or `flag{www-data}`
**How to Get It**:
1. Access the command injection page
2. In the input field, inject a command: `127.0.0.1; whoami`
3. Execute the injection to prove RCE (check the output)
4. Wrap your payload or output in `flag{...}` and submit

**Why This Flag?**: Proving you can execute arbitrary commands on the server makes you a "pipeline master."

---

## OP-003: The Imposter (CSRF - Cross-Site Request Forgery)

**Vulnerability**: Missing CSRF token validation
**Exploitation**: Craft a forged request that the authenticated user unknowingly submits
**Flag Format**: `flag{csrf_<token>}` shown in the response after a successful CSRF password change
**How to Get It**:
1. Analyze the CSRF page to understand what requests it makes
2. While authenticated as admin, trigger a forged GET: `?password_new=...&password_conf=...&Change=Change`
3. The page now returns a line like `FLAG: flag{csrf_deadbeef}` — copy that and submit it

**Why This Flag?**: Successfully exploiting CSRF proves you've made an unauthorized request on behalf of the user.

---

## OP-004: The Archive (Local File Inclusion - LFI)

**Vulnerability**: Unrestricted file inclusion allows reading arbitrary files
**Exploitation**: Use path traversal to read sensitive files like `/etc/passwd`
**Flag Format**: `root:x:0:0`
**How to Get It**:
1. Access the file inclusion page
2. Try path traversal: `../../../../../../etc/passwd`
3. Extract the root user entry from the file
4. Submit: `root:x:0:0`

**Why This Flag?**: The flag is literally the first line of `/etc/passwd` - proof you read a sensitive system file.

---

## OP-005: The Heist (SQL Injection)

**Vulnerability**: Unsanitized SQL query construction
**Exploitation**: Inject SQL code to extract database contents
**Flag Format**: `flag{db_dumped}`
**How to Get It**:
1. Access the SQL injection page
2. Inject SQL: `admin'#` or `' OR '1'='1`
3. Extract user credentials or data from the database
4. Submit: `flag{db_dumped}`

**Why This Flag?**: Successfully dumping database contents is the ultimate SQL injection goal.

---

## OP-006: Viral Signal (Stored XSS)

**Vulnerability**: Unsanitized input stored in database and reflected to other users
**Exploitation**: Inject JavaScript that persists and executes for all users
**Flag Format**: `flag{xss_persistence}`
**How to Get It**:
1. Access the XSS (Stored) page
2. Inject payload: `<script>alert('XSS')</script>` or similar
3. Submit the form to store it
4. Refresh or visit as another user - the script executes
5. Submit: `flag{xss_persistence}`

**Why This Flag?**: Stored XSS that persists across users is the most dangerous XSS variant.

---

## OP-007: The Trojan (File Upload)

**Vulnerability**: Unrestricted file upload allows executing malicious code
**Exploitation**: Upload a PHP shell or reverse shell script
**Flag Format**: `flag{shell_uploaded}`
**How to Get It**:
1. Access the file upload page
2. Create a simple PHP file: `<?php system($_GET['cmd']); ?>`
3. Upload the file
4. Access the uploaded file and execute commands
5. Submit: `flag{shell_uploaded}`

**Why This Flag?**: Successfully uploading and executing a shell means you have code execution on the server.

---

## OP-008: Ghost in the Machine (Full System Compromise)

**Vulnerability**: Combination of all previous vulnerabilities leading to root access
**Exploitation**: Chain exploits to gain root-level command execution
**Flag Format**: `flag{root_access_granted}`
**How to Get It**:
1. Use previous exploits to establish initial access
2. Escalate privileges (find SUID binaries, weak sudo config, kernel exploits)
3. Achieve root access
4. Submit: `flag{root_access_granted}`

**Why This Flag?**: Obtaining root access represents complete system compromise.

---

## Mission Submission Workflow

1. **Exploit the vulnerability** using the tools in your Kali terminal
2. **Discover the flag** - the key finding or proof of exploitation
3. **Submit the flag** in the Ghost Protocol dashboard
4. **Unlock next mission** - progression unlocks the next challenge

---

## Quick Reference Table

| Op Code | Mission | Vulnerability | Flag |
|---------|---------|---|---|
| OP-001 | The Gatekeeper | Brute Force | `password` |
| OP-002 | The Pipeline | Command Injection | `flag{<your_proof_of_execution>}` |
| OP-003 | The Imposter | CSRF | `flag{csrf_<token>}` |
| OP-004 | The Archive | LFI | `root:x:0:0` |
| OP-005 | The Heist | SQL Injection | `flag{db_dumped}` |
| OP-006 | Viral Signal | XSS (Stored) | `flag{xss_persistence}` |
| OP-007 | The Trojan | File Upload | `flag{shell_uploaded}` |
| OP-008 | Ghost in the Machine | Full Compromise | `flag{root_access_granted}` |

---

## For Students

The **flag** is not just a random string - it's the **proof of your exploitation**. It represents:
- A credential you discovered
- Data you extracted
- Output from a command you executed
- Evidence that you compromised the system

Each mission trains a specific offensive security skill used in real penetration testing.
