#!/usr/bin/env python3

import re
import argparse

def read_log_file(path: str) -> list[str]:
    """Load the log file and return all lines."""
    lines = []
    try:
        # open the log file and read it line by line
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # remove the newline at the end
                lines.append(line.rstrip('\n'))
    except FileNotFoundError:
        # simple error message if file is missing
        print(f"Error: cannot open log file '{path}'")
    return lines


def parse_log_line(line: str) -> dict:
    """
    Extract useful fields from a log line:
    - timestamp
    - service (sshd, sudo, etc.)
    - message
    - IP address (if any)
    - action (e.g., failed login, sudo command)
    """
    info = {
        "timestamp": "",
        "service": "",
        "message": line.strip(),
        "ip": None,
        "action": "OTHER",
    }

    parts = line.split()
    # basic check so we don't crash on weird/short lines
    if len(parts) < 5:
        return info

    # typical syslog layout:
    # Month Day Time Host Service: message...
    # ex: "Jan 10 12:34:56 myhost sshd[1234]: Failed password ..."
    info["timestamp"] = " ".join(parts[0:3])

    # service part usually something like "sshd[1234]:"
    service_part = parts[4]
    service_name = service_part.split(':')[0]
    if '[' in service_name:
        service_name = service_name.split('[')[0]
    info["service"] = service_name

    # message is everything after the first ':' in the line
    if ':' in line:
        info["message"] = line.split(':', 1)[1].strip()

    # try to find an IPv4 address in the line
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if ip_match:
        info["ip"] = ip_match.group(0)

    # decide what kind of action this is
    msg_lower = info["message"].lower()
    if service_name == "sshd" and "failed password" in msg_lower:
        info["action"] = "FAILED_SSH"
    elif service_name == "sshd" and "accepted password" in msg_lower:
        info["action"] = "SUCCESS_SSH"
    elif service_name == "sudo":
        info["action"] = "SUDO"

    return info


# -----------------------------
# SSH ANALYSIS FUNCTIONS
# -----------------------------

def count_failed_ssh_attempts(lines: list[str]) -> int:
    """Return total number of failed SSH login attempts."""
    count = 0
    for line in lines:
        data = parse_log_line(line)
        if data.get("action") == "FAILED_SSH":
            count += 1
    return count


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

