from pathlib import Path
import re
import shutil
import uuid
import zipfile

from flask import (
    Flask,
    abort,
    flash,
    render_template,
    request,
    send_from_directory,
)
from werkzeug.utils import secure_filename

from scanner import scan_project
from blue_agent import generate_all_fixes
from verifier_agent import apply_fixes_to_project
from quality_agent import run_quality_checks


app = Flask(__name__)
app.secret_key = "vibeshield-secret-key"

# Maximum uploaded ZIP size: 20 MB
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent

UPLOAD_FOLDER = BASE_DIR / "uploads"
SCANNED_FOLDER = BASE_DIR / "scanned_projects"
PATCHED_FOLDER = BASE_DIR / "patched_projects"
DOWNLOAD_FOLDER = BASE_DIR / "downloads"

UPLOAD_FOLDER.mkdir(exist_ok=True)
SCANNED_FOLDER.mkdir(exist_ok=True)
PATCHED_FOLDER.mkdir(exist_ok=True)
DOWNLOAD_FOLDER.mkdir(exist_ok=True)


def safely_extract_zip(zip_path, destination):
    """
    Extract a ZIP safely and prevent path-traversal attacks.
    """

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    safe_destination = destination.resolve()

    with zipfile.ZipFile(zip_path, "r") as zip_file:
        for member in zip_file.infolist():
            member_path = (
                destination / member.filename
            ).resolve()

            if (
                member_path != safe_destination
                and safe_destination
                not in member_path.parents
            ):
                raise ValueError(
                    "Unsafe ZIP file detected."
                )

        zip_file.extractall(destination)


def calculate_security_score(vulnerabilities):
    """
    Calculate a security score using issue severity.
    """

    score = 100

    for issue in vulnerabilities:
        if issue["severity"] == "High":
            score -= 20

        elif issue["severity"] == "Medium":
            score -= 10

        else:
            score -= 5

    return max(score, 0)


def count_severities(vulnerabilities):
    """
    Count High, Medium and Low issues.
    """

    return {
        "high": sum(
            1
            for issue in vulnerabilities
            if issue["severity"] == "High"
        ),
        "medium": sum(
            1
            for issue in vulnerabilities
            if issue["severity"] == "Medium"
        ),
        "low": sum(
            1
            for issue in vulnerabilities
            if issue["severity"] == "Low"
        ),
    }


def create_patched_zip(
    project_id,
    patched_project_folder
):
    """
    Create a downloadable patched ZIP.
    """

    archive_base = (
        DOWNLOAD_FOLDER
        / f"{project_id}_patched"
    )

    existing_archive = archive_base.with_suffix(
        ".zip"
    )

    if existing_archive.exists():
        existing_archive.unlink()

    archive_path = shutil.make_archive(
        str(archive_base),
        "zip",
        root_dir=patched_project_folder
    )

    return Path(archive_path)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        uploaded_file = request.files.get(
            "project"
        )

        if (
            not uploaded_file
            or uploaded_file.filename == ""
        ):
            flash("Please choose a ZIP file.")

            return render_template(
                "index.html",
                result=None
            )

        filename = secure_filename(
            uploaded_file.filename
        )

        if not filename.lower().endswith(".zip"):
            flash("Only ZIP files are allowed.")

            return render_template(
                "index.html",
                result=None
            )

        project_id = uuid.uuid4().hex[:8]

        zip_path = (
            UPLOAD_FOLDER
            / f"{project_id}_{filename}"
        )

        project_folder = (
            SCANNED_FOLDER
            / project_id
        )

        patched_project_folder = (
            PATCHED_FOLDER
            / project_id
        )

        uploaded_file.save(zip_path)

        try:
            safely_extract_zip(
                zip_path,
                project_folder
            )

            python_files = list(
                project_folder.rglob("*.py")
            )

            # Red Agent scans the original project.
            vulnerabilities = scan_project(
                project_folder
            )

            original_counts = count_severities(
                vulnerabilities
            )

            original_score = (
                calculate_security_score(
                    vulnerabilities
                )
            )

            # Blue Agent generates secure replacements.
            fixes = generate_all_fixes(
                vulnerabilities
            )

            # Verifier Agent applies fixes to a copy.
            verification = (
                apply_fixes_to_project(
                    project_folder,
                    patched_project_folder,
                    fixes
                )
            )

            # Red Agent scans the patched copy again.
            remaining_vulnerabilities = (
                scan_project(
                    patched_project_folder
                )
            )

            patched_counts = count_severities(
                remaining_vulnerabilities
            )

            patched_score = (
                calculate_security_score(
                    remaining_vulnerabilities
                )
            )

            # Independent compile, Pyflakes and Bandit checks.
            quality = run_quality_checks(
                patched_project_folder
            )

            patched_zip = create_patched_zip(
                project_id,
                patched_project_folder
            )

            score_improvement = (
                patched_score - original_score
            )

            fixed_issue_count = max(
                len(vulnerabilities)
                - len(remaining_vulnerabilities),
                0
            )

            security_verification_passed = (
                verification["syntax_valid"]
                and len(
                    remaining_vulnerabilities
                ) == 0
                and verification["failed_count"] == 0
            )

            final_review_passed = (
                security_verification_passed
                and quality["quality_passed"]
            )

            result = {
                "project_name": filename,
                "project_id": project_id,
                "python_file_count": len(
                    python_files
                ),
                "python_files": [
                    str(
                        file.relative_to(
                            project_folder
                        )
                    )
                    for file in python_files[:15]
                ],

                "vulnerabilities": vulnerabilities,
                "issue_count": len(
                    vulnerabilities
                ),
                "high_count": (
                    original_counts["high"]
                ),
                "medium_count": (
                    original_counts["medium"]
                ),
                "low_count": (
                    original_counts["low"]
                ),
                "security_score": original_score,

                "fixes": fixes,
                "fix_count": len(fixes),

                "verification": verification,
                "verification_passed": (
                    security_verification_passed
                ),
                "patched_security_score": (
                    patched_score
                ),
                "score_improvement": (
                    score_improvement
                ),
                "remaining_vulnerabilities": (
                    remaining_vulnerabilities
                ),
                "remaining_issue_count": len(
                    remaining_vulnerabilities
                ),
                "remaining_high_count": (
                    patched_counts["high"]
                ),
                "remaining_medium_count": (
                    patched_counts["medium"]
                ),
                "remaining_low_count": (
                    patched_counts["low"]
                ),
                "fixed_issue_count": (
                    fixed_issue_count
                ),

                "quality": quality,
                "final_review_passed": (
                    final_review_passed
                ),

                "patched_zip_created": (
                    patched_zip.exists()
                ),
            }

        except zipfile.BadZipFile:
            shutil.rmtree(
                project_folder,
                ignore_errors=True
            )

            shutil.rmtree(
                patched_project_folder,
                ignore_errors=True
            )

            flash(
                "The selected file is not a valid ZIP file."
            )

        except ValueError as error:
            shutil.rmtree(
                project_folder,
                ignore_errors=True
            )

            shutil.rmtree(
                patched_project_folder,
                ignore_errors=True
            )

            flash(str(error))

        except Exception as error:
            shutil.rmtree(
                project_folder,
                ignore_errors=True
            )

            shutil.rmtree(
                patched_project_folder,
                ignore_errors=True
            )

            flash(
                f"An error occurred: {error}"
            )

        finally:
            if zip_path.exists():
                zip_path.unlink()

    return render_template(
        "index.html",
        result=result
    )


@app.route("/download/<project_id>")
def download_patched_project(project_id):
    """
    Download the patched project ZIP.
    """

    if not re.fullmatch(
        r"[a-f0-9]{8}",
        project_id
    ):
        abort(404)

    filename = f"{project_id}_patched.zip"
    file_path = DOWNLOAD_FOLDER / filename

    if not file_path.exists():
        abort(404)

    return send_from_directory(
        str(DOWNLOAD_FOLDER),
        filename,
        as_attachment=True,
        download_name=(
            f"VibeShield_{project_id}_patched.zip"
        )
    )


if __name__ == "__main__":
    app.run(debug=True)