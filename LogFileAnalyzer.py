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
    ip_counts = {}

    # Count every IP we see
    for line in lines:
        data = parse_log_line(line)

        ip = data.get("ip")
        if not ip:
            continue

        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    suspicious = []

    # Analyze frequency + private vs public ranges
    for ip, count in ip_counts.items():
        # Flag external/public IPs (all suspicious)
        if not (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.")
        ):
            suspicious.append(ip)
            continue

        # Flag internal IPs that hit too many times
        if count > 10:
            suspicious.append(ip)

    return suspicious



def build_attack_intent_report(lines: list[str]) -> dict:
    """
    Analyze SSH failures to determine what attackers were trying to do.
    Returns:
    - attempted usernames
    - attacker IPs
    - login methods (MVP: just password attempts)
    """
    attempted_users = {}
    attacker_ips = {}
    methods = {"password": 0}

    for line in lines:
        data = parse_log_line(line)

        # Only look at failed SSH logins
        if data.get("action") == "ssh_failed":
            user = data.get("user")
            ip = data.get("ip")

            # Count username attempts
            attempted_users[user] = attempted_users.get(user, 0) + 1

            # Count attacker IP attempts
            attacker_ips[ip] = attacker_ips.get(ip, 0) + 1

            # Count password login methods (MVP simplifies this)
            methods["password"] += 1

    return {
        "attempted_usernames": attempted_users,
        "attacker_ips": attacker_ips,
        "login_methods": methods
    }


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
    sudo_commands = {}
    failed_sudo = 0

    for line in lines:
        data = parse_log_line(line)
        action = data.get("action")

        # Successful sudo command
        if action == "sudo_command":
            user = data.get("user")
            cmd = data.get("command")

            if user not in sudo_commands:
                sudo_commands[user] = []

            sudo_commands[user].append(cmd)

        # Failed sudo authentication
        elif action == "sudo_fail":
            failed_sudo += 1

    return {
        "total_sudo_commands": sum(len(v) for v in sudo_commands.values()),
        "commands_per_user": sudo_commands,
        "failed_sudo_attempts": failed_sudo,
    }



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






