import re


def create_secret_fix(code):
    """
    Replace a hard-coded secret with an environment variable.
    """

    match = re.match(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=",
        code.strip()
    )

    variable_name = match.group(1) if match else "secret_value"
    environment_name = variable_name.upper()

    return {
        "after": (
            f'{variable_name} = '
            f'os.getenv("{environment_name}")'
        ),
        "required_import": "import os",
        "explanation": (
            "The sensitive value is removed from the source code "
            "and loaded from an environment variable."
        ),
    }


def create_sql_fix(code):
    """
    Generate a parameterized SQLite query.
    """

    variable_match = re.match(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=",
        code.strip()
    )

    parameter_match = re.search(
        r"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
        code.strip()
    )

    query_variable = (
        variable_match.group(1)
        if variable_match
        else "query"
    )

    parameter_name = (
        parameter_match.group(1)
        if parameter_match
        else "user_value"
    )

    sql_match = re.search(
        r'["\']([^"\']+)["\']',
        code
    )

    if sql_match:
        sql_query = sql_match.group(1).rstrip()

        if sql_query.endswith("="):
            sql_query = f"{sql_query} ?"
        else:
            sql_query = f"{sql_query} ?"
    else:
        sql_query = "SELECT * FROM users WHERE id = ?"

    return {
        "after": (
            f'{query_variable} = "{sql_query}"\n'
            f"cursor.execute({query_variable}, ({parameter_name},))"
        ),
        "required_import": None,
        "explanation": (
            "The user-controlled value is sent separately as a SQL "
            "parameter instead of being added directly to the query."
        ),
    }


def create_eval_fix(code):
    """
    Replace eval() with ast.literal_eval().
    """

    fixed_code = code.replace(
        "eval(",
        "ast.literal_eval(",
        1
    )

    return {
        "after": fixed_code,
        "required_import": "import ast",
        "explanation": (
            "ast.literal_eval() reads basic Python values without "
            "executing arbitrary Python commands."
        ),
    }


def create_debug_fix(code):
    """
    Disable Flask debug mode.
    """

    fixed_code = re.sub(
        r"debug\s*=\s*True",
        "debug=False",
        code
    )

    return {
        "after": fixed_code,
        "required_import": None,
        "explanation": (
            "Debug mode is disabled to prevent sensitive error and "
            "application information from being exposed."
        ),
    }


def create_shell_fix(code):
    """
    Replace shell=True with shell=False.
    """

    fixed_code = re.sub(
        r"shell\s*=\s*True",
        "shell=False",
        code
    )

    return {
        "after": fixed_code,
        "required_import": None,
        "explanation": (
            "The command no longer executes through the operating-system "
            "shell, reducing command-injection risk."
        ),
    }


def generate_fix(issue):
    """
    Generate one fix for a vulnerability.
    """

    issue_name = issue["name"]
    vulnerable_code = issue["code"]

    if issue_name == "Hard-coded Secret":
        generated_fix = create_secret_fix(vulnerable_code)

    elif issue_name == "Possible SQL Injection":
        generated_fix = create_sql_fix(vulnerable_code)

    elif issue_name == "Dangerous eval() Usage":
        generated_fix = create_eval_fix(vulnerable_code)

    elif issue_name == "Debug Mode Enabled":
        generated_fix = create_debug_fix(vulnerable_code)

    elif issue_name == "Unsafe Shell Execution":
        generated_fix = create_shell_fix(vulnerable_code)

    else:
        generated_fix = {
            "after": "Manual security review required.",
            "required_import": None,
            "explanation": (
                "The Blue Agent could not safely generate an automatic "
                "replacement for this issue."
            ),
        }

    return {
        "name": issue_name,
        "severity": issue["severity"],
        "file": issue["file"],
        "line": issue["line"],
        "before": vulnerable_code,
        "after": generated_fix["after"],
        "required_import": generated_fix["required_import"],
        "explanation": generated_fix["explanation"],
        "status": "Fix generated",
    }


def generate_all_fixes(vulnerabilities):
    """
    Generate fixes for all vulnerabilities.
    """

    return [
        generate_fix(issue)
        for issue in vulnerabilities
    ] 