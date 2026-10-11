import os
import subprocess
from pathlib import Path


# Prowler exit code 3 means:
# The scan completed, but one or more findings failed.
PROWLER_FINDINGS_EXIT_CODE = 3


def run(
    region: str,
    out: Path,
    check: str | None = None,
) -> int:
    """
    Run Prowler and save stdout/stderr to the scan directory.

    Returns:
        0: scan completed with no failed findings
        3: scan completed with failed findings

    Raises:
        RuntimeError: Prowler execution failed
    """

    out.mkdir(
        parents=True,
        exist_ok=True,
    )

    prowler_command = os.getenv(
        "PROWLER_COMMAND",
        "prowler",
    )

    command = [
        prowler_command,
        "aws",
        "--region",
        region,
        "--output-directory",
        str(out),
    ]

    if check:
        command.extend(
            [
                "--check",
                check,
            ]
        )

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    stdout_path = out / "stdout.log"
    stderr_path = out / "stderr.log"

    stdout_path.write_text(
        result.stdout,
        encoding="utf-8",
    )

    stderr_path.write_text(
        result.stderr,
        encoding="utf-8",
    )

    # Exit code 0:
    # Prowler completed successfully and found no failed checks.
    #
    # Exit code 3:
    # Prowler completed successfully but found failed checks.
    #
    # Both are valid CSPM scan results.
    if result.returncode in (
        0,
        PROWLER_FINDINGS_EXIT_CODE,
    ):
        return result.returncode

    # Other non-zero exit codes indicate an actual Prowler
    # execution failure.
    raise RuntimeError(
        f"Prowler execution failed with exit code "
        f"{result.returncode}; "
        f"see {stderr_path}"
    )
