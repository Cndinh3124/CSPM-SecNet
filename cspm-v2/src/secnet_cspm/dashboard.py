import csv
import os
import shutil
from pathlib import Path


def sync_scan_csv(scan_output: Path) -> dict:
    """
    Validate and copy Prowler CSV files to the official dashboard
    output directory.

    This function does not restart or stop the dashboard process.
    """
    dashboard_dir = os.getenv("PROWLER_DASHBOARD_DIR")
    dashboard_output = os.getenv("PROWLER_DASHBOARD_OUTPUT_DIR")

    if not dashboard_dir or not dashboard_output:
        return {
            "status": "SKIPPED",
            "reason": "Dashboard paths are not configured.",
            "files_copied": 0,
        }

    source_dir = Path(scan_output).resolve()
    prowler_dir = Path(dashboard_dir).expanduser().resolve()
    target_dir = Path(dashboard_output).expanduser().resolve()

    if not source_dir.is_dir():
        return {
            "status": "ERROR",
            "reason": "Prowler scan output directory does not exist.",
            "files_copied": 0,
        }

    if not prowler_dir.is_dir():
        return {
            "status": "ERROR",
            "reason": "Prowler Dashboard checkout does not exist.",
            "files_copied": 0,
        }

    expected_output = (prowler_dir / "output").resolve()

    if target_dir != expected_output:
        return {
            "status": "ERROR",
            "reason": (
                "Dashboard output must be the output directory "
                "inside the configured Prowler checkout."
            ),
            "files_copied": 0,
        }

    csv_files = sorted(source_dir.glob("*.csv"))

    if not csv_files:
        return {
            "status": "SKIPPED",
            "reason": "No Prowler CSV files were generated.",
            "files_copied": 0,
        }

    validated = []

    for source in csv_files:
        try:
            with source.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                reader = csv.DictReader(handle, delimiter=";")
                headers = set(reader.fieldnames or [])

                if not {"CHECK_ID", "STATUS"}.issubset(headers):
                    continue

                if not (
                    {"TIMESTAMP", "ASSESSMENT_START_TIME"} & headers
                ):
                    continue

                if not any(reader):
                    continue

            validated.append(source)

        except (OSError, UnicodeError, csv.Error):
            continue

    if not validated:
        return {
            "status": "ERROR",
            "reason": "No valid Prowler CSV files were found.",
            "files_copied": 0,
        }

    # Preflight all destinations before copying anything.
    conflicts = []

    for source in validated:
        destination = target_dir / source.name

        if (
            destination.exists()
            and source.resolve() != destination.resolve()
        ):
            conflicts.append(destination.name)

    if conflicts:
        return {
            "status": "ERROR",
            "reason": (
                "Dashboard CSV filename collision(s): "
                + ", ".join(conflicts)
            ),
            "files_copied": 0,
        }

    target_dir.mkdir(parents=True, exist_ok=True)

    copied_paths = []

    try:
        for source in validated:
            destination = target_dir / source.name

            # Source is already in the dashboard output directory.
            if source.resolve() == destination.resolve():
                continue

            # Copy to a temporary file, then publish it atomically.
            temporary = destination.with_name(
                f".{destination.name}.tmp"
            )

            try:
                shutil.copy2(source, temporary)

                # Do not overwrite a file that appeared after preflight.
                # os.link fails if destination already exists.
                os.link(temporary, destination)
                copied_paths.append(destination)
            finally:
                temporary.unlink(missing_ok=True)

    except OSError as exc:
        # Remove only files successfully created by this invocation.
        for destination in copied_paths:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass

        return {
            "status": "ERROR",
            "reason": f"CSV copy failed: {type(exc).__name__}",
            "files_copied": 0,
        }

    return {
        "status": "SYNCED",
        "files_copied": len(copied_paths),
        "output_dir": str(target_dir),
        "refresh_required": bool(copied_paths),
    }