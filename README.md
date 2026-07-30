# 🛡️ VibeShield AI

**VibeShield AI** is an AI-powered multi-agent application-security platform that scans Python projects, detects vulnerabilities, generates secure code fixes, applies those fixes to a copied project, verifies the patched code, performs independent quality checks, and provides a downloadable corrected project.

> **Detect • Fix • Verify • Protect**

---

## 📌 Problem Statement

AI-assisted and rapid application development helps students, developers, startups, and small businesses create software quickly.

However, applications may accidentally contain security vulnerabilities such as:

- Hard-coded passwords
- Exposed API keys
- SQL injection
- Dangerous `eval()` usage
- Flask debug mode enabled in production
- Unsafe shell-command execution

Most traditional security scanners only display warnings. Beginner developers may not understand the vulnerability or know how to correct it.

VibeShield AI solves this problem by providing a complete security workflow:

```text
Detect → Explain → Fix → Verify → Download
```

---

## 💡 Proposed Solution

VibeShield AI uses four specialised security agents.

### 🔴 Red Agent

The Red Agent scans every Python file inside the uploaded project and detects security issues.

It currently detects:

- Hard-coded passwords
- Hard-coded API keys
- Hard-coded tokens and secrets
- Possible SQL injection
- Dangerous `eval()` usage
- Flask debug mode
- Unsafe `shell=True` usage

For every issue, the Red Agent displays:

- Vulnerability name
- Severity level
- File name
- Line number
- Vulnerable code
- Description
- Recommended solution

---

### 🔵 Blue Agent

The Blue Agent generates secure replacements for vulnerabilities detected by the Red Agent.

Example 1 — Hard-coded password:

```python
# Before
password = "admin123"

# After
password = os.getenv("PASSWORD")
```

Example 2 — SQL injection:

```python
# Before
query = "SELECT * FROM users WHERE id = " + user_id

# After
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

Example 3 — Dangerous `eval()`:

```python
# Before
result = eval(input("Enter calculation: "))

# After
result = ast.literal_eval(input("Enter calculation: "))
```

Example 4 — Debug mode:

```python
# Before
app.run(debug=True)

# After
app.run(debug=False)
```

The Blue Agent also identifies required imports such as:

```python
import os
import ast
```

---

### 🟢 Verifier Agent

The Verifier Agent applies the generated fixes to a copied version of the uploaded project.

It does not modify the original project.

The Verifier Agent:

- Copies the uploaded project
- Applies generated fixes
- Adds required imports only once
- Creates a `.env.example` file
- Checks Python syntax
- Rescans the patched project
- Calculates the new security score
- Compares the before-and-after results
- Creates a downloadable patched ZIP file

---

### 🟣 Quality Agent

The Quality Agent performs independent static checks without executing uploaded code.

It uses:

- Python compilation checking
- Pyflakes
- Bandit

The Quality Agent can identify:

- Syntax errors
- Undefined variables
- Unused imports
- Code-quality warnings
- Additional security issues

---

## ✨ Key Features

- Secure ZIP project upload
- Maximum upload size of 20 MB
- Safe ZIP extraction
- ZIP path-traversal protection
- Python file detection
- Vulnerability scanning
- Severity classification
- Security score calculation
- Secure code-fix generation
- Before-and-after code comparison
- Automatic patch application
- Required import generation
- Environment variable conversion
- Python syntax verification
- Patched-project rescanning
- Independent Bandit scan
- Pyflakes quality warnings
- Downloadable patched project
- Modern cybersecurity dashboard
- Responsive user interface
- Original project remains unchanged

---

## 🔄 Application Workflow

```text
Upload Python Project ZIP
            ↓
Safe ZIP Extraction
            ↓
Red Agent Vulnerability Scan
            ↓
Blue Agent Fix Generation
            ↓
Apply Fixes to a Safe Copy
            ↓
Verifier Agent Syntax Check
            ↓
Rescan Patched Project
            ↓
Quality Agent Analysis
            ↓
Download Patched Project
```

---

## 📊 Sample Result

A deliberately vulnerable test project produced the following result:

| Measurement | Before Fixing | After Fixing |
|---|---:|---:|
| Security Score | 10/100 | 100/100 |
| Total Issues | 5 | 0 |
| High-Severity Issues | 4 | 0 |
| Medium-Severity Issues | 1 | 0 |
| Applied Fixes | 0 | 5 |
| Failed Fixes | — | 0 |
| Python Syntax | — | Valid |
| Compile Check | — | Passed |
| Bandit Issues | — | 0 |
| Pyflakes Warnings | — | 2 |

The test project contained:

- Two hard-coded secrets
- One possible SQL injection
- One dangerous `eval()` call
- Flask debug mode enabled

The Pyflakes warnings occurred because the small test project did not define:

```python
cursor
app
```

This shows that VibeShield AI correctly distinguishes between security remediation and complete runtime readiness.

---

## 🖥️ Dashboard

The VibeShield AI dashboard displays:

- Original security score
- Total vulnerabilities
- High, medium, and low issue counts
- Issues fixed
- Recent scan summary
- Vulnerability distribution
- Red Agent findings
- Blue Agent secure fixes
- Before-and-after code
- Verifier Agent results
- Quality Agent warnings
- Downloadable patched project



## 🛠️ Technology Stack

| Category | Technology |
|---|---|
| Programming Language | Python |
| Backend Framework | Flask |
| Frontend | HTML, CSS and JavaScript |
| Security Detection | Custom Red Agent |
| Automatic Fixing | Blue Agent |
| Verification | Python AST and static rescanning |
| Security Scanner | Bandit |
| Code Quality | Pyflakes |
| File Handling | Python ZIP processing |
| Version Control | GitHub |
| Deployment | Render |
| Development Approach | Agentic coding workflow |

---

## 📁 Project Structure

```text
vibeshield-ai/
│
├── app.py
├── scanner.py
├── blue_agent.py
├── verifier_agent.py
├── quality_agent.py
├── requirements.txt
├── .gitignore
├── README.md
│
└── templates/
    └── index.html
```

The application automatically creates these folders while running:

```text
uploads/
scanned_projects/
patched_projects/
downloads/
```

These generated folders and files are excluded from GitHub using `.gitignore`.

---

## ⚙️ Installation

### 1. Clone the repository

sivani2025

```bash
git clone https://github.com/sivanis2025/vibeshield-ai
```

Move into the project folder:

```bash
cd vibeshield-ai
```

---

### 2. Create a virtual environment

#### Windows

```bash
py -m venv vibe
```

Activate it:

```bash
vibe\Scripts\activate
```

#### Linux or macOS

```bash
python3 -m venv vibe
```

Activate it:

```bash
source vibe/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Run the application

```bash
python app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

---

## 🚀 How to Use

1. Start the Flask application.
2. Open VibeShield AI in the browser.
3. Click **Choose ZIP**.
4. Select a Python project in ZIP format.
5. Click **Start Scan**.
6. Review the Red Agent vulnerability findings.
7. Examine the Blue Agent secure replacements.
8. View the Verifier Agent results.
9. Review Pyflakes and Bandit findings.
10. Download the patched project ZIP.

---

## 🔒 Security Design

VibeShield AI follows several security precautions:

- Accepts only ZIP files
- Limits uploads to 20 MB
- Uses secure file-name handling
- Prevents ZIP path-traversal attacks
- Deletes temporary uploaded ZIP files
- Does not modify the original project
- Applies fixes only to a copied project
- Does not execute uploaded Python code
- Uses static analysis
- Uses syntax validation
- Validates download project IDs
- Stores generated projects separately

---

## ⚠️ Current Limitations

- The current version supports Python projects only.
- Detection is based on predefined static-analysis rules.
- Automatic SQL fixes are mainly designed for SQLite-style queries.
- Generated fixes may require project-specific manual review.
- Valid Python syntax does not guarantee complete runtime functionality.
- Uploaded projects are not executed.
- Automated functional testing is not currently available.
- Large or complex projects may contain patterns not detected by the current scanner.
- Environment variables must be configured manually after downloading the patched project.

---

## 🔮 Future Enhancements

- GitHub repository scanning
- GitHub pull-request generation
- Support for JavaScript
- Support for Java
- Support for C and C++
- Docker-based isolated runtime testing
- Dependency vulnerability scanning
- OWASP Top 10 coverage
- Authentication and user accounts
- Scan history
- PDF security reports
- Email security reports
- Secure exploit demonstrations
- Custom security policies
- Machine-learning vulnerability prioritisation
- Cloud-based collaboration
- Real-time repository monitoring
- CI/CD pipeline integration
- Semgrep integration
- `pip-audit` integration

---

## 🏆 Hackathon Information

This project was developed for:

# ChatGPT Codex India Hackathon 2026

VibeShield AI demonstrates an agentic development workflow through:

- Project planning
- Modular agent creation
- Vulnerability detection
- Secure-code generation
- Automatic patching
- Independent verification
- Code-quality analysis
- Iterative debugging
- User-interface improvement
- Deployment preparation

---

## 🎯 Impact

VibeShield AI is designed to help:

- Students learning secure coding
- Beginner developers
- Developers using AI-assisted coding tools
- Startups
- Small businesses
- Organisations without dedicated security teams
- Hackathon participants
- Cybersecurity learners

Traditional scanners often follow this process:

```text
Find Problems → Display Warnings → Stop
```

VibeShield AI follows a complete remediation process:

```text
Detect → Explain → Fix → Verify → Download
```

---

## 👩‍💻 Developer

**Sivani Senthilkumar**

B.E. Computer Science and Engineering — Cyber Security  
Sri Eshwar College of Engineering  
Coimbatore, Tamil Nadu, India

---

## 📄 License

This project is currently provided for educational, research, cybersecurity-learning, and hackathon-demonstration purposes.

---

## ⭐ Support

If you find VibeShield AI useful, consider giving the GitHub repository a star.

> Build faster. Code safer. Verify everything.