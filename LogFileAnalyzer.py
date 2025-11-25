def read_log_file(path: str) -> list[str]:
    """Load the log file and return all lines."""


def parse_log_line(line: str) -> dict:
    """
    Extract useful fields from a log line:
    - timestamp
    - service (sshd, sudo, etc.)
    - message
    - IP address (if any)
    - action (e.g., failed login, sudo command)
    """


# -----------------------------
# SSH ANALYSIS FUNCTIONS
# -----------------------------

def count_failed_ssh_attempts(lines: list[str]) -> int:
    """Return total number of failed SSH login attempts."""


def detect_strange_ip_logins(lines: list[str]) -> list[str]:
    """
    Identify unusual or repeated IPs attempting login.
    Return a list of suspicious IP addresses.
    """


def build_attack_intent_report(lines: list[str]) -> dict:
    """
    Analyze SSH failures to determine what attackers were trying to do.
    Example output:
    - attempted usernames
    - rejected passwords
    - login methods used
    """


# -----------------------------
# SUDOERS LOG ANALYSIS
# -----------------------------

def analyze_sudo_activity(lines: list[str]) -> dict:
    """
    Summarize sudo usage:
    - number of sudo commands run
    - users who ran sudo
    - commands executed
    - failed sudo attempts (if present)
    """


# -----------------------------
# OUTPUT / UTILITIES
# -----------------------------

def print_summary(report: dict) -> None:
    """Display final results in a clean, readable format."""


def write_output(report: dict, path: str) -> None:
    """Save the full report or suspicious IP list to a file."""


# -----------------------------
# ARGPARSE SETUP
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """
    Subcommands will include:
    - ssh       (failed attempts, strange IPs, attacker intent)
    - sudo      (sudoers log summary)
    - summary   (full system report)
    """
    

def main():
    """Main entrypoint: parse args, run correct analysis, format output."""

