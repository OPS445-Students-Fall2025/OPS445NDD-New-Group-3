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



# ---------------------------------------------------------------
# THIS SECTION DEFINES FUNCTION TO DISPLAY THE OUTPUT / UTILITIES
# ---------------------------------------------------------------


def print_summary(report: dict) -> None:
    #The above function prints a human-readable summary of the analysis report.
    #This function does not return anything. It simply looks through the keys stored in the 'report' 
    #dictionary and prints the information in a clean and well-organized format. Some of the expected keys inside 
    #report are: 'failed ssh attempts', 'suspicious_ips', 'attack_intent', 'sudo_summary', 'total_sudo_commands',
    #This function checks for each section one by one before printing. 

    print("\n===== SYSTEM LOG ANALYSIS SUMMARY =====\n")

    # 1). FAILED SSH ATTEMPTS

    failed_attempts = report.get("failed_ssh_attempts")
    if failed_attempts is not None:
        print(f"Failed SSH Attempts: {failed_attempts}\n")

    # 2). SUSPICIOUS IP ADDRESSES
   
    suspicious_ips = report.get("suspicious_ips")
    if suspicious_ips:
        print("Suspicious IP Addresses Detected:")
        for ip in suspicious_ips:
            print(f"  - {ip}")
        print() 

    
    # 3). ATTACK INTENT REPORT (username guesses, IPs, methods)
    
    attack_intent = report.get("attack_intent")
    if attack_intent:
        print("Attacker Intent Breakdown:")

        # attempted usernames
        usernames = attack_intent.get("attempted_usernames", {})
        if usernames:
            print("  Attempted Usernames:")
            for user, count in usernames.items():
                print(f"    {user}: {count} times")

        # attacker IPs
        ips = attack_intent.get("attacker_ips", {})
        if ips:
            print("\n  Attacker IP Addresses:")
            for ip, count in ips.items():
                print(f"    {ip}: {count} attempts")

        # login methods
        methods = attack_intent.get("login_methods", {})
        if methods:
            print("\n  Login Methods Used:")
            for method, count in methods.items():
                print(f"    {method}: {count}")

        print()  

    
    # 4). SUDO SUMMARY (commands and failures)
    
    sudo_summary = report.get("sudo_summary")
    if sudo_summary:
        print("Sudo Activity Summary:")

        total_cmds = sudo_summary.get("total_sudo_commands", 0)
        print(f"  Total Sudo Commands: {total_cmds}")

        failed_sudo = sudo_summary.get("failed_sudo_attempts", 0)
        print(f"  Failed Sudo Attempts: {failed_sudo}")

        commands_per_user = sudo_summary.get("commands_per_user", {})
        if commands_per_user:
            print("\n  Commands Per User:")
            for user, commands in commands_per_user.items():
                print(f"    {user}:")
                for cmd in commands:
                    print(f"      - {cmd}")

        print() 

    
    # 5). ANY EXTRA KEYS THE SCRIPT MAY ADD LATER
    
    known_keys = {
        "failed_ssh_attempts",
        "suspicious_ips",
        "attack_intent",
        "sudo_summary",
        "total_sudo_commands",
    }

    # Print anything extra for future-proofing
    for key, value in report.items():
        if key not in known_keys:
            print(f"{key}: {value}")
            print()

    print("========== END OF SUMMARY ==========\n")

#KEYNOTE: In order for this function to be executed properly, print_summary(report) has to take 
#the report dictionary produced by the analysis functions(count_failed_ssh_attempts, detect_strange_ip_logins, 
#build_attack_intent_report, analyze_sudo_activity)and displays the results in a clean, readable format 
#for SSH and sudo activity.




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
    
    parser = build_arg_parser()
    args = parser.parse_args()

    lines = read_log_file(args.logfile)

    if args.command == "ssh":
        report = {
            "failed_ssh_attempts": count_failed_ssh_attempts(lines),
            "suspicious_ips": detect_strange_ip_logins(lines),
            "attack_intent": build_attack_intent_report(lines),
        }
        print_summary(report)

    elif args.command == "sudo":
        report = analyze_sudo_activity(lines)
        print_summary(report)

    elif args.command == "summary":
        report = {
            "failed_ssh_attempts": count_failed_ssh_attempts(lines),
            "suspicious_ips": detect_strange_ip_logins(lines),
            "attack_intent": build_attack_intent_report(lines),
            "sudo_activity": analyze_sudo_activity(lines),
        }
        print_summary(report)


if __name__ == "__main__":
    main()






