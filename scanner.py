import re
from pathlib import Path


SECURITY_RULES = [
    {
        "name": "Hard-coded Secret",
        "severity": "High",
        "pattern": re.compile(
            r"""(?ix)
            \b(password|passwd|api_key|apikey|secret|token)\b
            \s*=\s*
            ["'][^"']{3,}["']
            """
        ),
        "description": "A password, API key, secret or token is stored directly in the code.",
        "recommendation": "Store sensitive values in environment variables.",
    },
    {
        "name": "Debug Mode Enabled",
        "severity": "Medium",
        "pattern": re.compile(r"\bdebug\s*=\s*True\b"),
        "description": "Debug mode may reveal sensitive application information.",
        "recommendation": "Disable debug mode before deploying the application.",
    },
    {
        "name": "Dangerous eval() Usage",
        "severity": "High",
        "pattern": re.compile(r"\beval\s*\("),
        "description": "eval() can execute dangerous input as Python code.",
        "recommendation": "Avoid eval() and use safe parsing methods.",
    },
    {
        "name": "Unsafe Shell Execution",
        "severity": "High",
        "pattern": re.compile(r"\bshell\s*=\s*True\b"),
        "description": "Using shell=True can allow command-injection attacks.",
        "recommendation": "Use shell=False and pass commands as a list.",
    },
]


def contains_possible_sql_injection(line):
    """
    Detect basic SQL queries built using string concatenation,
    f-strings or format().
    """

    sql_words = ("SELECT", "INSERT", "UPDATE", "DELETE")

    uppercase_line = line.upper()

    contains_sql = any(word in uppercase_line for word in sql_words)

    dangerous_construction = (
        "+" in line
        or ".format(" in line
        or line.strip().startswith('f"')
        or line.strip().startswith("f'")
        or '= f"' in line
        or "= f'" in line
    )

    return contains_sql and dangerous_construction


def scan_project(project_folder):
    """
    Scan every Python file and return detected vulnerabilities.
    """

    project_folder = Path(project_folder)
    vulnerabilities = []

    for python_file in project_folder.rglob("*.py"):
        try:
            content = python_file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            lines = content.splitlines()

            for line_number, line in enumerate(lines, start=1):
                for rule in SECURITY_RULES:
                    if rule["pattern"].search(line):
                        vulnerabilities.append(
                            {
                                "name": rule["name"],
                                "severity": rule["severity"],
                                "file": str(
                                    python_file.relative_to(project_folder)
                                ),
                                "line": line_number,
                                "code": line.strip(),
                                "description": rule["description"],
                                "recommendation": rule["recommendation"],
                            }
                        )

                if contains_possible_sql_injection(line):
                    vulnerabilities.append(
                        {
                            "name": "Possible SQL Injection",
                            "severity": "High",
                            "file": str(
                                python_file.relative_to(project_folder)
                            ),
                            "line": line_number,
                            "code": line.strip(),
                            "description": (
                                "The SQL query appears to contain user data "
                                "through string construction."
                            ),
                            "recommendation": (
                                "Use parameterized SQL queries instead of "
                                "joining values directly."
                            ),
                        }
                    )

        except OSError:
            continue

    return vulnerabilities