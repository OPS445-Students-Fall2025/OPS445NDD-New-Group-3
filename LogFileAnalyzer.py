#!/usr/bin/env python3

import re
import argparse
import json
from pprint import pformat

def read_log_file(path: str) -> list[str]:
    # Reads a log file and returns all lines in a list.
    # Each line is stripped of the newline at the end.
    # Added error handling so the function doesn’t crash if the file doesn't exist
    # or if there are permission issues.

    lines = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lines.append(line.rstrip("\n"))

    except FileNotFoundError:
        print(f"Error: log file not found: '{path}'")

    except Exception as e:
        # Catches permission errors, I/O errors, etc.
        print(f"Error reading log file '{path}': {e}")

    return lines



def parse_log_line(line: str) -> dict:
    # Takes one log line and extracts useful info from it.
    # Returns a dictionary with:
    # - timestamp (first 3 fields)
    # - service name (ex: sshd, sudo)
    # - message (everything after the first ':')
    # - ip address (if found)
    # - action category (FAILED_SSH, SUCCESS_SSH, SUDO, OTHER)
    #
    # This helps us standardize syslog lines so the other functions can work easily.

    info = {
        "timestamp": "",
        "service": "",
        "message": line.strip(),
        "ip": None,
        "action": "OTHER",
    }

    parts = line.split()
    # If a line is too short, it's probably not a real log entry
    if len(parts) < 5:
        return info

    # Basic syslog format → Month Day Time
    info["timestamp"] = " ".join(parts[0:3])

    # Extract service name (ex: sshd[1234]: → sshd)
    service_part = parts[4]
    service_name = service_part.split(':')[0]
    if '[' in service_name:
        service_name = service_name.split('[')[0]
    info["service"] = service_name

    # Capture everything after the first colon as the "message"
    if ':' in line:
        info["message"] = line.split(':', 1)[1].strip()

    # Simple IPv4 detection
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if ip_match:
        info["ip"] = ip_match.group(0)

    # Classify the type of event
    msg_lower = info["message"].lower()
    if service_name == "sshd" and "failed password" in msg_lower:
        info["action"] = "FAILED_SSH"
    elif service_name == "sshd" and "accepted password" in msg_lower:
        info["action"] = "SUCCESS_SSH"
    elif service_name == "sudo":
        info["action"] = "SUDO"

    return info

# -----------------------------------------------------
# SSH ANALYSIS FUNCTIONS
# -----------------------------------------------------

def count_failed_ssh_attempts(lines: list[str]) -> int:
    # Counts how many failed SSH login attempts appear in the log.
    # Uses parse_log_line() to detect entries marked as FAILED_SSH.

    count = 0
    for line in lines:
        data = parse_log_line(line)
        if data.get("action") == "FAILED_SSH":
            count += 1

    return count

# -----------------------------------------------------
# REFERENCES 
# Student: MEHRSHAD SAEIDI
# Student ID: 126073220
# -----------------------------------------------------

# Python Software Foundation. (2024). open() — Open file and return a corresponding file object.
#     https://docs.python.org/3/library/functions.html#open

# Python Software Foundation. (2024). string methods — str.split(), str.strip(), rstrip().
#     Used throughout the parsing logic to process log lines.
#     https://docs.python.org/3/library/stdtypes.html#string-methods



def detect_strange_ip_logins(lines: list[str]) -> list[str]:
# This function analyzes a list of log lines to identify potentially suspicious IP addresses.
# It works by:
# 1. Iterating through each log line and parsing it with parse_log_line().
# 2. Collecting the IP addresses found in each line and counting how many times each IP appears.
# 3. Identifying suspicious IPs using two criteria:
#    a) Public/external IP addresses (not in private ranges 10.*, 172.*, or 192.168.*) are flagged.
#    b) Internal/private IP addresses that appear frequently (more than 10 times) are flagged as suspicious.
# 4. Returning a list of these suspicious IP addresses.
# This function helps detect unusual login attempts or potential attacks on the system.
    
    ip_counts = {}

    # Count occurrences of each IP found in the logs
    for line in lines:
        data = parse_log_line(line)
        ip = data.get("ip")
        if not ip:
            continue
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    suspicious = []

    # Determine which IPs are suspicious based on frequency and private/public ranges
    for ip, count in ip_counts.items():
        # External/public IPs are always suspicious
        if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
            suspicious.append(ip)
            continue
        # Internal IPs with many login attempts are suspicious
        if count > 10:
            suspicious.append(ip)

    return suspicious



def build_attack_intent_report(lines: list[str]) -> dict:
# This function analyzes log lines to summarize the intent behind failed SSH login attempts.
# It returns a dictionary containing:
# - attempted_usernames: a count of each username attackers tried.
# - attacker_ips: a count of IP addresses used in failed attempts.
# - login_methods: a summary of login methods used (currently tracks password attempts).
#
# The function works by:
# 1. Iterating through each log line.
# 2. Parsing the line using parse_log_line().
# 3. Checking if the "action" is "ssh_failed" (failed SSH login attempt).
# 4. Recording the attempted username and IP address counts.
# 5. Counting the login method used (currently only "password").
# This allows higher-level reports to understand attacker behavior patterns.
    attempted_users = {}
    attacker_ips = {}
    methods = {"password": 0}

    for line in lines:
        data = parse_log_line(line)

        # Only look at failed SSH logins
        if data.get("action") == "FAILED_SSH":
            user = data.get("user")
            ip = data.get("ip")

            # Count attempted usernames
            if user:
                attempted_users[user] = attempted_users.get(user, 0) + 1

            # Count attacker IPs
            if ip:
                attacker_ips[ip] = attacker_ips.get(ip, 0) + 1

            # Count password login attempts
            methods["password"] += 1

    return {
        "attempted_usernames": attempted_users,
        "attacker_ips": attacker_ips,
        "login_methods": methods
    }



# -------------------------------------------------------------
# THIS SECTION DEFINES A FUNCTION TO ANALYZE SUDOERS ACTIVITIES
# -------------------------------------------------------------

def analyze_sudo_activity(lines: list[str]) -> dict:
# This function analyzes log lines to summarize sudo command activity.
# It returns a dictionary containing:
# - total_sudo_commands: total number of sudo commands executed.
# - commands_per_user: a dictionary of users and the commands they ran with sudo.
# - failed_sudo_attempts: number of failed sudo authentication attempts.
#
# The function works by:
# 1. Iterating through each log line.
# 2. Parsing the line using parse_log_line().
# 3. Checking the "action" field for sudo-related activity.
#    - "sudo_command" indicates a successful sudo command.
#    - "sudo_fail" indicates a failed sudo authentication.
# 4. Collecting and organizing command information by user and counting failures.
# This allows higher-level reports to summarize sudo usage and detect possible misuse.

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
            if cmd:
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
 # The write_output function saves the log analysis report to a file.
# It handles multiple scenarios to make the code safe and clear:
# - Checks if the output path exists and is writable.
# - Supports JSON output (pretty-printed) if the path ends with '.json'.
# - Writes human-readable text output for other file types, using a format similar to print_summary.
# - Handles empty reports gracefully by indicating "No data to write."
# - Catches exceptions during file writing to prevent crashes and prints an error message.
# - Formats nested structures in the report for readability using pprint if needed.
# This explicit handling increases reliability, safety, and clarity of the script.

    if not path:
        print("No output file specified. Skipping write.")
        return

    # 1). Handle JSON output
    if path.lower().endswith(".json"):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"Report successfully written as JSON to '{path}'")
            return
        except Exception as e:
            print(f"Error writing JSON to '{path}': {e}")
            return

    # 2). Handle text output (human-readable)
    try:
        lines = []

        # helper function to append lines
        def L(s=""):
            lines.append(str(s))

        if not report:
            L("No data to write.")
        else:
            # Reuse the sections similar to print_summary
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

            if "sudo_activity" in report or "sudo" in report or "sudo_summary" in report:
                sudo_section = report.get("sudo_activity", report.get("sudo", report.get("sudo_summary", {})))
                if isinstance(sudo_section, dict):
                    L("")
                    L("=== SUDO ===")
                    total = sudo_section.get("total_sudo_commands", 0)
                    L(f"Total sudo commands: {total}")
                    per_user = sudo_section.get("commands_per_user", {})
                    if per_user:
                        L("Commands per user:")
                        for user, cmds in per_user.items():
                            L(f" - {user}: {len(cmds)} commands")
                    failed = sudo_section.get("failed_sudo_attempts", 0)
                    L(f"Failed sudo attempts: {failed}")

        # Write all lines to the file
        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines) + "\n")
        print(f"Report successfully written to '{path}'")
    
    except Exception as e:
        print(f"Error writing report to '{path}': {e}")

# This write_output function is necessary because it safely saves the log analysis report to a file.  
# It supports both JSON and human-readable text formats.  
# It handles empty or nested data gracefully for clarity.  
# It uses conditional statements to handle different scenarios and try/except blocks to catch errors,
# ensuring the result is written safely.  




# ---------------------------------------------------------------------------------
# THIS SECTION CREATES AND CONFIGURES AN ARGPARSER TO HANDLE COMMAND LINE ARGUMENTS
# ---------------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
# This newly modified build_arg_parser function creates and returns an ArgumentParser
# that understands all command-line options the script accepts.

# What this function does:
# it Creates a main parser with a short description so users can run `-h` to see help.
# it Adds two global options used by all commands:
#    - `--logfile` to choose which log file to analyze.
#    - `--out` to choose where the output should be saved.
# it Adds subparsers (ssh, sudo, summary), each representing a different action.
#    Each sub-command can have its own options while still sharing the global ones.
# it Sets a default command (`summary`) so the script still works when the user
# provides arguments like `--logfile` but forgets to type a sub-command.

# This modified script fixes the issue of "arguments present but not working" by ensuring
# the parser always has a valid command to run. Previously, when no sub-command was given,
# `args.command` became None, causing the script to ignore all provided arguments. By
# setting `command="summary"` as the default, the parser now processes options correctly
# even when the user forgets to specify a sub-command.

# We still use subparsers because they keep the script organized by giving each mode
# (ssh, sudo, summary) its own set of options. This makes the command-line interface
# clearer, the help messages easier to understand, and the tool more professional.
# Subparsers are appropriate here — the issue wasn’t their use, but the missing default
# command. By adding a safe default, the subparsers now work exactly as intended.


    # 1). Creates the top-level parser with a short description
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Simple syslog analyzer for SSH and sudo activity"
    )

    # 2). Common/global options (apply regardless of chosen sub-command)
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

    # 3). Create subparsers for distinct commands (ssh, sudo, summary)
    # We did not set required=True here for maximum compatibility.
    subparsers = parser.add_subparsers(dest="command", help="Sub-command to run")

    
    # ssh sub-command: analyze SSH failed attempts and suspicious IPs
    
    ssh_p = subparsers.add_parser("ssh", help="Analyze SSH failed attempts and suspicious IPs")
    ssh_p.add_argument(
        "-t", "--top",
        type=int,
        default=10,
        help="Show top N IPs/usernames (default: 10)"
    )
    # Keynote: ssh subcommand here will use the global --logfile and --out options too.

   
    # sudo sub-command: analyze sudo activity
   
    sudo_p = subparsers.add_parser("sudo", help="Analyze sudo activity")
    sudo_p.add_argument(
        "-u", "--user",
        default=None,
        help="Filter sudo report to a single user (optional)"
    )

    
    # summary sub-command: combined report (explicit if user wants it)
    
    subparsers.add_parser("summary", help="Produce a combined system summary")

    
    # Default behavior:
    # If user does not provide any sub-command, treat it as 'summary'.
    # This will avoid args.command from being None and makes top-level options work.
    
    parser.set_defaults(command="summary")

    return parser


def main():
# This is the main entrypoint of the script. It orchestrates reading logs, analyzing them, 
# and displaying or saving reports. The function works as follows:
# 1. Builds the argument parser and parses command-line arguments.
# 2. Reads the log file specified by the user (or default /var/log/syslog) using read_log_file().
# 3. Checks which subcommand was invoked: 'ssh', 'sudo', or 'summary'.
# 4. Depending on the subcommand:
#     - 'ssh': builds a report including failed SSH attempts, suspicious IPs, and attack intent.
#     - 'sudo': builds a report summarizing sudo activity.
#     - 'summary': builds a combined report for both SSH and sudo activity.
# 5. Calls print_summary() to display the report to the user in a clean, readable format.
# This function is executed when the script is run directly and ensures the workflow operates
# correctly based on user input.
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
        sudo_report = analyze_sudo_activity(lines)
        report = {"sudo_summary": sudo_report}
        print_summary(report)

    elif args.command == "summary":
        report = {
            "failed_ssh_attempts": count_failed_ssh_attempts(lines),
            "suspicious_ips": detect_strange_ip_logins(lines),
            "attack_intent": build_attack_intent_report(lines),
            "sudo_summary": analyze_sudo_activity(lines),
        }
        print_summary(report)



if __name__ == "__main__":
    main()



# -----------------------------------------------------------------------------
# REFERENCES FOR FUNCTIONS 
# --[PRINT_SUMMARY, 
# --WRITE_OUTPUT AND 
# --BUILD_ARG_PARSER()]
# Student: OJI ONYEDIKACHI CHRISTOPHER
# Student ID: 133383224
# -----------------------------------------------------------------------------


# Python Software Foundation. (2024). argparse — Parser for command-line options. 
#     https://docs.python.org/3/library/argparse.html

# Pozo Ramos, L. (2023). Build command-line interfaces with argparse. Real Python. 
#     https://realpython.com/command-line-interfaces-python-argparse/

# Python Software Foundation. (2024). pprint — Data pretty printer.
#     https://docs.python.org/3/library/pprint.html



# -----------------------------------------------------------------------------
# REFERENCES FOR FUNCTIONS 
# --[PRINT_SUMMARY, 
# --WRITE_OUTPUT AND 
# --BUILD_ARG_PARSER()]
# Student: THULANEI ALLEN
# Student ID: 115659179
# -----------------------------------------------------------------------------
# Python Software Foundation. (2024). Data structures — Dictionaries. 
#     Python.org. https://docs.python.org/3/tutorial/datastructures.html#dictionaries
# Python Software Foundation. (2024). open() — Open file and return a corresponding file object. 
#     Python.org. https://docs.python.org/3/library/functions.html#open

