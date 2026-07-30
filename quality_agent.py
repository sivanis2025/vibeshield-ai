import json
import re
import subprocess
import sys
from pathlib import Path


def make_relative_path(path_text, project_folder):
    """
    Convert an absolute result path into a project-relative path.
    """

    try:
        path = Path(path_text)
        project_folder = Path(project_folder).resolve()

        if path.is_absolute():
            return str(path.resolve().relative_to(project_folder))

    except (OSError, ValueError):
        pass

    return path_text


def run_compile_check(project_folder):
    """
    Compile Python source code without executing it.
    """

    project_folder = Path(project_folder)
    errors = []

    for python_file in project_folder.rglob("*.py"):
        try:
            source_code = python_file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            compile(
                source_code,
                str(python_file),
                "exec"
            )

        except SyntaxError as error:
            errors.append(
                {
                    "file": str(
                        python_file.relative_to(project_folder)
                    ),
                    "line": error.lineno or 0,
                    "message": error.msg,
                }
            )

        except OSError as error:
            errors.append(
                {
                    "file": str(
                        python_file.relative_to(project_folder)
                    ),
                    "line": 0,
                    "message": str(error),
                }
            )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "error_count": len(errors),
    }


def parse_pyflakes_output(output, project_folder):
    """
    Convert Pyflakes text output into structured results.
    """

    issues = []

    pattern = re.compile(
        r"^(.*):(\d+):(\d+):\s*(.*)$"
    )

    for output_line in output.splitlines():
        output_line = output_line.strip()

        if not output_line:
            continue

        match = pattern.match(output_line)

        if match:
            issues.append(
                {
                    "file": make_relative_path(
                        match.group(1),
                        project_folder
                    ),
                    "line": int(match.group(2)),
                    "column": int(match.group(3)),
                    "message": match.group(4),
                }
            )

        else:
            issues.append(
                {
                    "file": "Project",
                    "line": 0,
                    "column": 0,
                    "message": output_line,
                }
            )

    return issues


def run_pyflakes_check(project_folder):
    """
    Run Pyflakes without executing the uploaded project.
    """

    project_folder = Path(project_folder)

    command = [
        sys.executable,
        "-m",
        "pyflakes",
        str(project_folder),
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False
        )

        combined_output = "\n".join(
            part
            for part in [
                process.stdout.strip(),
                process.stderr.strip(),
            ]
            if part
        )

        if (
            "No module named pyflakes"
            in combined_output
        ):
            return {
                "available": False,
                "issues": [],
                "issue_count": 0,
                "error": (
                    "Pyflakes is not installed. "
                    "Run: pip install pyflakes"
                ),
            }

        issues = parse_pyflakes_output(
            combined_output,
            project_folder
        )

        return {
            "available": True,
            "issues": issues,
            "issue_count": len(issues),
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "issues": [],
            "issue_count": 0,
            "error": "Pyflakes scan timed out.",
        }

    except OSError as error:
        return {
            "available": False,
            "issues": [],
            "issue_count": 0,
            "error": str(error),
        }


def parse_bandit_results(report, project_folder):
    """
    Convert the Bandit JSON report into structured results.
    """

    issues = []

    for result in report.get("results", []):
        issues.append(
            {
                "test_id": result.get(
                    "test_id",
                    "Unknown"
                ),
                "name": result.get(
                    "test_name",
                    "Security issue"
                ),
                "file": make_relative_path(
                    result.get("filename", "Unknown"),
                    project_folder
                ),
                "line": result.get(
                    "line_number",
                    0
                ),
                "severity": result.get(
                    "issue_severity",
                    "Unknown"
                ).title(),
                "confidence": result.get(
                    "issue_confidence",
                    "Unknown"
                ).title(),
                "message": result.get(
                    "issue_text",
                    "Security review required."
                ),
                "code": result.get(
                    "code",
                    ""
                ).strip(),
            }
        )

    return issues


def run_bandit_check(project_folder):
    """
    Run an independent Bandit security scan.
    """

    project_folder = Path(project_folder)

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(project_folder),
        "-f",
        "json",
        "-q",
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=45,
            shell=False
        )

        standard_output = process.stdout.strip()
        standard_error = process.stderr.strip()

        if (
            "No module named bandit"
            in standard_error
        ):
            return {
                "available": False,
                "issues": [],
                "issue_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "error": (
                    "Bandit is not installed. "
                    "Run: pip install bandit"
                ),
            }

        if not standard_output:
            return {
                "available": True,
                "issues": [],
                "issue_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "error": (
                    standard_error
                    or "Bandit returned no report."
                ),
            }

        try:
            report = json.loads(standard_output)

        except json.JSONDecodeError:
            return {
                "available": True,
                "issues": [],
                "issue_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "error": (
                    "Bandit returned an unreadable report."
                ),
            }

        issues = parse_bandit_results(
            report,
            project_folder
        )

        high_count = sum(
            1
            for issue in issues
            if issue["severity"] == "High"
        )

        medium_count = sum(
            1
            for issue in issues
            if issue["severity"] == "Medium"
        )

        low_count = sum(
            1
            for issue in issues
            if issue["severity"] == "Low"
        )

        return {
            "available": True,
            "issues": issues,
            "issue_count": len(issues),
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "issues": [],
            "issue_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "error": "Bandit scan timed out.",
        }

    except OSError as error:
        return {
            "available": False,
            "issues": [],
            "issue_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "error": str(error),
        }


def run_quality_checks(project_folder):
    """
    Run all safe code-quality checks.

    Uploaded code is analysed but never executed.
    """

    compile_result = run_compile_check(
        project_folder
    )

    pyflakes_result = run_pyflakes_check(
        project_folder
    )

    bandit_result = run_bandit_check(
        project_folder
    )

    tools_available = (
        pyflakes_result["available"]
        and bandit_result["available"]
    )

    checks_completed = (
        compile_result["valid"]
        and pyflakes_result["error"] is None
        and bandit_result["error"] is None
    )

    quality_passed = (
        tools_available
        and checks_completed
        and pyflakes_result["issue_count"] == 0
        and bandit_result["issue_count"] == 0
    )

    if quality_passed:
        status = "Static quality checks passed"

    elif not tools_available:
        status = "Quality tools are not installed"

    elif not compile_result["valid"]:
        status = "Python compilation failed"

    elif bandit_result["issue_count"] > 0:
        status = "Security review required"

    elif pyflakes_result["issue_count"] > 0:
        status = "Functional code review required"

    else:
        status = "Additional review required"

    return {
        "compile": compile_result,
        "pyflakes": pyflakes_result,
        "bandit": bandit_result,
        "tools_available": tools_available,
        "checks_completed": checks_completed,
        "quality_passed": quality_passed,
        "status": status,
    }