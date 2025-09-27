
import os
import sys
import subprocess

# Define the demo options
DEMO_OPTIONS = [
    "Plain chat (no TLS)",
    "TLS chat (certificate validation)",
    "TLS chat + Wireshark key log",
    "MITM with self-signed cert (insecure client)",
    "MITM blocked by certificate pinning (insecure client)"
]

# Define the role options
ROLE_OPTIONS = [
    "Server",
    "Client",
    "MITM Proxy"
]

# Define the mapping of demo options to arguments
DEMO_ARGS = [
    {"mode": "plain", "keylog": None, "mitm": False, "pin": False, "extras": ()},
    {"mode": "tls", "keylog": None, "mitm": False, "pin": False, "extras": ()},
    {"mode": "tls", "keylog": "tls_keys.log", "mitm": False, "pin": False, "extras": ()},
    {"mode": "tls", "keylog": None, "mitm": True, "pin": False, "extras": ("--insecure",)},
    {"mode": "tls", "keylog": None, "mitm": True, "pin": True, "extras": ("--insecure",)}
]

# Check for optional UI dependencies
def check_ui_dependencies():
    try:
        import colorama
        import pyfiglet
        import emoji
        return True
    except ImportError:
        return False

# Display the main menu
def display_main_menu():
    print("\nSelect a TLS Chat Demo:")
    for i, option in enumerate(DEMO_OPTIONS, 1):
        print(f"{i}. {option}")
    print("0. Exit")

# Display the role menu
def display_role_menu():
    print("\nSelect the role to run on this node:")
    for i, role in enumerate(ROLE_OPTIONS, 1):
        print(f"{i}. {role}")
    print("0. Exit")

# Launch the appropriate script
def launch_script(role, args):
    script = ""
    if role == 1:
        script = "server.py"
    elif role == 2:
        script = "client.py"
    elif role == 3:
        script = "mitm.py"
    else:
        print("Invalid role selected.")
        return

    cmd = [sys.executable, script]

    if script == "server.py" or script == "client.py":
        cmd += ["--mode", args["mode"], "--port", "12345"]
        if args["keylog"]:
            cmd += ["--keylog", args["keylog"]]
        if script == "client.py":
            if args["pin"]:
                cmd += ["--pin", "dummyfingerprint"]
            cmd += list(args["extras"])
    elif script == "mitm.py":
        cmd += ["--port", "23456"]

    print(f"\nLaunching: {' '.join(cmd)}\n")
    subprocess.run(cmd)

# Main launcher logic
def main():
    ui_enabled = check_ui_dependencies()
    if not ui_enabled:
        print("⚠️  Fancy UI features are disabled (missing dependencies).")

    while True:
        display_main_menu()
        try:
            demo_choice = int(input("Enter demo number: "))
        except ValueError:
            continue
        if demo_choice == 0:
            print("Exiting.")
            break
        if not (1 <= demo_choice <= len(DEMO_OPTIONS)):
            print("Invalid choice.")
            continue

        args = DEMO_ARGS[demo_choice - 1]

        while True:
            display_role_menu()
            try:
                role_choice = int(input("Enter role number: "))
            except ValueError:
                continue
            if role_choice == 0:
                break
            if not (1 <= role_choice <= len(ROLE_OPTIONS)):
                print("Invalid role.")
                continue

            launch_script(role_choice, args)
            break

if __name__ == "__main__":
    main()
