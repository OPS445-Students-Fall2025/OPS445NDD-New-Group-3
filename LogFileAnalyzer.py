#!/usr/bin/env python3

import re
import argparse
import json
from pprint import pformat

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
    """Display final results in a clean, readable format.

    This function is defensive: it inspects common keys that may be present
    in the report dict and prints them in a human-friendly way. For anything
    unexpected it falls back to a pretty-printed view of the whole dict.
    """
    if not report:
        print("No data to display.")
        return

    # Human-friendly printing for common sections
    # SSH summary
    if "failed_ssh_attempts" in report or "failed_ssh" in report:
        count = report.get("failed_ssh_attempts", report.get("failed_ssh", 0))
        print("=== SSH ===")
        print(f"Failed SSH attempts: {count}")

    if "suspicious_ips" in report:
        ips = report.get("suspicious_ips", [])
        print("Suspicious IPs:")
        if ips:
            for ip in ips:
                print(f" - {ip}")
        else:
            print(" - none found")

    if "attack_intent" in report:
        ai = report["attack_intent"]
        print("\n=== Attack Intent Report ===")
        # attempted_usernames is expected to be a dict username->count
        users = ai.get("attempted_usernames", {})
        if users:
            print("Attempted usernames:")
            for u, c in sorted(users.items(), key=lambda x: -x[1]):
                print(f" - {u}: {c}")
        ips = ai.get("attacker_ips", {})
        if ips:
            print("Attacker IPs:")
            for ip, c in sorted(ips.items(), key=lambda x: -x[1]):
                print(f" - {ip}: {c}")
        methods = ai.get("login_methods", {})
        if methods:
            print("Login methods:")
            for m, c in methods.items():
                print(f" - {m}: {c}")

    # Sudo summary
    if "sudo" in report or "sudo_summary" in report or "total_sudo_commands" in report:
        sudo_section = report.get("sudo", report.get("sudo_summary", {}))
        # If it's a dict produced by analyze_sudo_activity, print fields
        if isinstance(sudo_section, dict):
            print("\n=== SUDO ===")
            total = sudo_section.get("total_sudo_commands",
                                     report.get("total_sudo_commands", 0))
            print(f"Total sudo commands: {total}")
            per_user = sudo_section.get("commands_per_user",
                                        report.get("commands_per_user", {}))
            if per_user:
                print("Commands per user:")
                for user, cmds in per_user.items():
                    print(f" - {user}: {len(cmds)} commands")
            failed = sudo_section.get("failed_sudo_attempts",
                                      report.get("failed_sudo_attempts", 0))
            print(f"Failed sudo attempts: {failed}")

    # If nothing matched above, or there are extra keys, pretty-print the whole report
    known_keys = {"failed_ssh_attempts", "failed_ssh", "suspicious_ips", "attack_intent",
                  "sudo", "sudo_summary", "total_sudo_commands", "commands_per_user",
                  "failed_sudo_attempts"}
    extra_keys = [k for k in report.keys() if k not in known_keys]
    if extra_keys:
        print("\n=== Additional data ===")
        for k in extra_keys:
            print(f"{k}:")
            # pretty format nested structures for readability
            print(pformat(report[k], indent=4))
    # If none of the above applied at all, do a final pretty print of the whole dict
    # (useful for debugging and unexpected report formats)
    if not (set(report.keys()) & known_keys) and not extra_keys:
        print("Full report:")
        print(pformat(report, indent=4))


def write_output(report: dict, path: str) -> None:
    """Save the full report to a file.

    Behavior:
      - If path ends with '.json', write JSON (pretty printed).
      - Otherwise write a human-readable textual report (same style as print_summary).
    """
    if path.lower().endswith('.json'):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return
        except Exception as e:
            print(f"Error writing JSON to {path}: {e}")
            return

    # For text output, reuse the string produced by print_summary but capture it
    try:
        # Create a textual representation similar to what print_summary prints
        # We'll build it into a string and write it out.
        lines = []
        # Simple helper to append lines
        def L(s=""):
            lines.append(str(s))

        if not report:
            L("No data to write.")
        else:
            if "failed_ssh_attempts" in report or "failed_ssh" in report:
                count = report.get("failed_ssh_attempts", report.get("failed_ssh", 0))
                L("=== SSH ===")
                L(f"Failed SSH attempts: {count}")

            if "suspicious_ips" in report:
                ips = report.get("suspicious_ips", [])
                L("Suspicious IPs:")
                if ips:
                    for ip in ips:
                        L(f" - {ip}")
                else:
                    L(" - none found")

            if "attack_intent" in report:
                ai = report["attack_intent"]
                L("")
                L("=== Attack Intent Report ===")
                users = ai.get("attempted_usernames", {})
                if users:
                    L("Attempted usernames:")
                    for u, c in sorted(users.items(), key=lambda x: -x[1]):
                        L(f" - {u}: {c}")
                ips = ai.get("attacker_ips", {})
                if ips:
                    L("Attacker IPs:")
                    for ip, c in sorted(ips.items(), key=lambda x: -x[1]):
                        L(f" - {ip}: {c}")
                methods = ai.get("login_methods", {})
                if methods:
                    L("Login methods:")
                    for m, c in methods.items():
                        L(f" - {m}: {c}")

            if "sudo" in report or "sudo_summary" in report or "total_sudo_commands" in report:
                sudo_section = report.get("sudo", report.get("sudo_summary", {}))
                if isinstance(sudo_section, dict):
                    L("")
                    L("=== SUDO ===")
                    total = sudo_section.get("total_sudo_commands",
                                             report.get("total_sudo_commands", 0))
                    L(f"Total sudo commands: {total}")
                    per_user = sudo_section.get("commands_per_user",
                                                report.get("commands_per_user", {}))
                    if per_user:
                        L("Commands per user:")
                        for user, cmds in per_user.items():
                            L(f" - {user}: {len(cmds)} commands")
                    failed = sudo_section.get("failed_sudo_attempts",
                                              report.get("failed_sudo_attempts", 0))
                    L(f"Failed sudo attempts: {failed}")

            # Add extra keys if present
            known_keys = {"failed_ssh_attempts", "failed_ssh", "suspicious_ips", "attack_intent",
                          "sudo", "sudo_summary", "total_sudo_commands", "commands_per_user",
                          "failed_sudo_attempts"}
            extra_keys = [k for k in report.keys() if k not in known_keys]
            if extra_keys:
                L("")
                L("=== Additional data ===")
                for k in extra_keys:
                    L(f"{k}:")
                    L(pformat(report[k]))

        # Actually write the textual lines to the file
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"Error writing report to {path}: {e}")


# -----------------------------
# ARGPARSE SETUP
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """
    Build the argparse parser and subcommands.

    Subcommands:
      - ssh     : analyze ssh-related entries
      - sudo    : analyze sudo-related entries
      - summary : full system report (both)
    Common options:
      --logfile or -l  : path to the log file (default: /var/log/syslog)
      --out or -o      : output file (optional). If ends with .json, JSON will be written.
    """
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Simple syslog analyzer for SSH and sudo activity"
    )

    parser.add_argument(
        "-l", "--logfile",
        default="/var/log/syslog",
        help="Path to the log file to analyze (default: /var/log/syslog)"
    )
    parser.add_argument(
        "-o", "--out",
        default=None,
        help="Optional output file to save the report (if ends with .json will produce JSON)"
    )

    subparsers = parser.add_subparsers(dest="command", required=False,
                                       help="Sub-command to run. If omitted, 'summary' is assumed.")

    # ssh subcommand
    ssh_p = subparsers.add_parser("ssh", help="Analyze SSH failed attempts and suspicious IPs")
    ssh_p.add_argument("-t", "--top", type=int, default=10,
                       help="Show top N IPs/usernames (not yet used by core functions)")

    # sudo subcommand
    sudo_p = subparsers.add_parser("sudo", help="Analyze sudo activity")
    sudo_p.add_argument("-u", "--user", default=None, help="Filter sudo report to a single user")

    # summary subcommand
    subparsers.add_parser("summary", help="Produce a combined system summary")

    return parser


def main():
    """Main entrypoint: parse args, run correct analysis, format output."""





