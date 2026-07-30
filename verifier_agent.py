import ast
import re
import shutil
from pathlib import Path


def find_replacement_line(lines, expected_index, vulnerable_code):
    """
    Find the line that contains the vulnerable code.

    First, check the original line number. If it does not match,
    search the complete file for an exact stripped-line match.
    """

    expected_code = vulnerable_code.strip()

    if 0 <= expected_index < len(lines):
        if lines[expected_index].strip() == expected_code:
            return expected_index

    matching_indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip() == expected_code
    ]

    if len(matching_indexes) == 1:
        return matching_indexes[0]

    return None


def preserve_indentation(original_line, replacement_code):
    """
    Add the original line indentation to every generated replacement line.
    """

    indentation = original_line[
        :len(original_line) - len(original_line.lstrip())
    ]

    replacement_lines = replacement_code.splitlines()

    return [
        f"{indentation}{line}" if line.strip() else ""
        for line in replacement_lines
    ]


def find_import_position(lines):
    """
    Find a safe location for generated imports.

    Imports are placed after:
    - shebang
    - encoding declaration
    - module docstring
    - __future__ imports
    """

    content = "\n".join(lines)
    insertion_index = 0

    if lines and lines[0].startswith("#!"):
        insertion_index = 1

    if insertion_index < len(lines):
        possible_encoding = lines[insertion_index]

        if "coding" in possible_encoding:
            insertion_index += 1

    try:
        syntax_tree = ast.parse(content)

        if syntax_tree.body:
            first_node = syntax_tree.body[0]

            is_docstring = (
                isinstance(first_node, ast.Expr)
                and isinstance(first_node.value, ast.Constant)
                and isinstance(first_node.value.value, str)
            )

            if is_docstring and first_node.end_lineno:
                insertion_index = max(
                    insertion_index,
                    first_node.end_lineno
                )

        for node in syntax_tree.body:
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "__future__"
                and node.end_lineno
            ):
                insertion_index = max(
                    insertion_index,
                    node.end_lineno
                )

    except SyntaxError:
        pass

    return insertion_index


def add_required_imports(lines, required_imports):
    """
    Add generated imports only when they are not already present.
    """

    if not required_imports:
        return lines

    existing_content = "\n".join(lines)

    missing_imports = []

    for required_import in sorted(required_imports):
        import_pattern = (
            rf"^\s*{re.escape(required_import)}\s*$"
        )

        if not re.search(
            import_pattern,
            existing_content,
            flags=re.MULTILINE
        ):
            missing_imports.append(required_import)

    if not missing_imports:
        return lines

    insertion_index = find_import_position(lines)

    lines[insertion_index:insertion_index] = (
        missing_imports + [""]
    )

    return lines


def create_environment_example(project_folder, environment_variables):
    """
    Create a .env.example file for secrets moved to environment variables.
    """

    if not environment_variables:
        return

    env_example_path = project_folder / ".env.example"

    existing_lines = []

    if env_example_path.exists():
        existing_lines = env_example_path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()

    existing_names = {
        line.split("=", 1)[0].strip()
        for line in existing_lines
        if "=" in line
    }

    for variable_name in sorted(environment_variables):
        if variable_name not in existing_names:
            existing_lines.append(
                f"{variable_name}=replace_with_secure_value"
            )

    env_example_path.write_text(
        "\n".join(existing_lines) + "\n",
        encoding="utf-8"
    )


def validate_python_syntax(project_folder):
    """
    Check Python syntax without executing uploaded code.
    """

    project_folder = Path(project_folder)
    syntax_errors = []

    for python_file in project_folder.rglob("*.py"):
        try:
            content = python_file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            ast.parse(
                content,
                filename=str(python_file)
            )

        except SyntaxError as error:
            syntax_errors.append(
                {
                    "file": str(
                        python_file.relative_to(project_folder)
                    ),
                    "line": error.lineno or 0,
                    "message": error.msg,
                }
            )

        except OSError as error:
            syntax_errors.append(
                {
                    "file": str(
                        python_file.relative_to(project_folder)
                    ),
                    "line": 0,
                    "message": str(error),
                }
            )

    return {
        "syntax_valid": len(syntax_errors) == 0,
        "syntax_errors": syntax_errors,
    }


def apply_fixes_to_project(source_folder, destination_folder, fixes):
    """
    Copy a project and apply generated fixes to the copied files.
    """

    source_folder = Path(source_folder)
    destination_folder = Path(destination_folder)

    if destination_folder.exists():
        shutil.rmtree(destination_folder)

    shutil.copytree(source_folder, destination_folder)

    fixes_by_file = {}

    for fix in fixes:
        fixes_by_file.setdefault(
            fix["file"],
            []
        ).append(fix)

    applied_fixes = []
    failed_fixes = []
    environment_variables = set()

    for relative_file, file_fixes in fixes_by_file.items():
        target_file = destination_folder / Path(relative_file)

        if not target_file.exists():
            for fix in file_fixes:
                failed_fixes.append(
                    {
                        "name": fix["name"],
                        "file": fix["file"],
                        "line": fix["line"],
                        "reason": "The target file was not found.",
                    }
                )

            continue

        try:
            lines = target_file.read_text(
                encoding="utf-8",
                errors="ignore"
            ).splitlines()

        except OSError as error:
            for fix in file_fixes:
                failed_fixes.append(
                    {
                        "name": fix["name"],
                        "file": fix["file"],
                        "line": fix["line"],
                        "reason": str(error),
                    }
                )

            continue

        required_imports = set()

        sorted_fixes = sorted(
            file_fixes,
            key=lambda item: item["line"],
            reverse=True
        )

        for fix in sorted_fixes:
            expected_index = fix["line"] - 1

            replacement_index = find_replacement_line(
                lines,
                expected_index,
                fix["before"]
            )

            if replacement_index is None:
                failed_fixes.append(
                    {
                        "name": fix["name"],
                        "file": fix["file"],
                        "line": fix["line"],
                        "reason": (
                            "The vulnerable line could not be matched "
                            "safely."
                        ),
                    }
                )

                continue

            original_line = lines[replacement_index]

            replacement_lines = preserve_indentation(
                original_line,
                fix["after"]
            )

            lines[
                replacement_index:replacement_index + 1
            ] = replacement_lines

            if fix.get("required_import"):
                required_imports.add(
                    fix["required_import"]
                )

            environment_matches = re.findall(
                r'os\.getenv\(\s*["\']'
                r'([A-Za-z_][A-Za-z0-9_]*)'
                r'["\']\s*\)',
                fix["after"]
            )

            environment_variables.update(
                environment_matches
            )

            applied_fixes.append(
                {
                    "name": fix["name"],
                    "file": fix["file"],
                    "line": fix["line"],
                    "status": "Applied",
                }
            )

        lines = add_required_imports(
            lines,
            required_imports
        )

        target_file.write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8"
        )

    create_environment_example(
        destination_folder,
        environment_variables
    )

    syntax_result = validate_python_syntax(
        destination_folder
    )

    return {
        "applied_fixes": applied_fixes,
        "failed_fixes": failed_fixes,
        "applied_count": len(applied_fixes),
        "failed_count": len(failed_fixes),
        "syntax_valid": syntax_result["syntax_valid"],
        "syntax_errors": syntax_result["syntax_errors"],
    }