#!/usr/bin/python3
# Dependencies:
#   pip install pyyaml cryptography

import base64
import ipaddress
import os
import random
import re
import sys
import subprocess
import yaml

CONFIG_YAML = "wg-conf-config-awg1.yaml"

# ---------------------------------------------------------------------------
# Key / jitter generation
# ---------------------------------------------------------------------------
def generate_wireguard_keypair():
    """Generate an X25519 keypair and return (private_key_b64, public_key_b64)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        sys.exit("Please install: pip install cryptography")

    private_bytes = os.urandom(32)
    private_obj = X25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )


def generate_jitter_variables():
    """Return (Jc, Jmin, Jmax) for AWG jitter obfuscation."""
    jc = random.randint(4, 12)
    jmin = random.randint(64, 768)
    jmax = random.randint(jmin + random.randint(32, 64), 1024)
    return jc, jmin, jmax


def unique_random(lo, hi, *exclude):
    """Return a random int in [lo, hi] that is not in *exclude."""
    while True:
        value = random.randint(lo, hi)
        if value not in exclude:
            return value

# ---------------------------------------------------------------------------
# IP allocation
# ---------------------------------------------------------------------------

def get_free_ip(data):
    """Return the first unused host address in the server's subnet as x.x.x.x/32."""
    server_iface = ipaddress.ip_interface(data["server"]["Address"])
    used = {str(server_iface.ip)}

    for client_data in data.get("clients", {}).values():
        if "Address" in client_data:
            used.add(client_data["Address"].split("/")[0])

    for host in server_iface.network.hosts():
        if str(host) not in used:
            return f"{host}/32"

    sys.exit("No free IPs in the subnet")

# ---------------------------------------------------------------------------
# Config file I/O
# ---------------------------------------------------------------------------

def read_config(file):
    """Load YAML config, generate any missing server keys/params, and return data dict."""
    try:
        with open(file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        sys.exit(e)

    if not isinstance(data, dict):
        sys.exit(f"Config file '{file}' is empty or not valid YAML")

    server = data.get("server")
    if server is None:
        sys.exit(f"'server' block missing or empty in {file}")

    required_keys = ("Config", "Address", "ListenPort", "ClientEndpoint", "AWGInterface")
    for key in required_keys:
        if server.get(key) is None:
            sys.exit(f"'{key}' missing or empty in server block of {file}")

    changed = False

    # Keypair
    if server.get("PrivateKey") is None or server.get("PublicKey") is None:
        print("Private/public key missing — generating new keypair")
        server["PrivateKey"], server["PublicKey"] = generate_wireguard_keypair()
        changed = True

    # S1/S2 — must differ from each other
    if server.get("S1") is None:
        server["S1"] = random.randint(15, 150)
        changed = True
    if server.get("S2") is None:
        server["S2"] = unique_random(15, 150, server["S1"])
        changed = True

    # S3 / S4 — independent
    for key, lo, hi in (("S3", 0, 64), ("S4", 0, 32)):
        if server.get(key) is None:
            server[key] = random.randint(lo, hi)
            changed = True

    # H1–H4 — all must be distinct
    for h_key in ("H1", "H2", "H3", "H4"):
        if server.get(h_key) is None:
            existing = {server[k] for k in ("H1", "H2", "H3", "H4") if server.get(k) is not None}
            server[h_key] = unique_random(5, 2_147_483_647, *existing)
            changed = True

    if changed:
        write_config(file, data)

    return data


def write_config(file, data):
    """Persist data dict to YAML file."""
    try:
        with open(file, "w", encoding="utf-8") as f:
            yaml.dump(data, f)
    except Exception as e:
        sys.exit(e)

# ---------------------------------------------------------------------------
# AWG config generation
# ---------------------------------------------------------------------------

# Params written to [Interface] on the server side that clients don't need
_SERVER_ONLY_PARAMS = {"Config", "PublicKey", "ClientEndpoint", "AWGInterface"}

# Obfuscation params shared between server and client configs
_OBFS_PARAMS = {"S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"}

_BOOL_TO_STR = {True: "on", False: "off"}

def format_value(value):
    if isinstance(value, bool):
        return _BOOL_TO_STR[value]
    return value

def generate_awg_config(data):
    """Write server wg config and one client .conf per peer."""
    server = data["server"]
    clients = data.get("clients") or {}

    # --- server config ---
    config_path = server["Config"]
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write("[Interface]\n")
            for param, value in server.items():
                if param not in _SERVER_ONLY_PARAMS:
                    f.write(f"{param} = {format_value(value)}\n")

            for peer_name, peer_data in clients.items():
                f.write(f"\n[Peer] #{peer_name}\n")
                f.write(f"PublicKey = {peer_data['PublicKey']}\n")
                f.write(f"AllowedIPs = {peer_data['Address']}\n")
                f.write("PersistentKeepalive = 30\n")

        print(f"Server config written: {config_path}")
    except Exception as e:
        sys.exit(e)

    # --- client configs ---
    for client_name, client_data in clients.items():
        file_path = f"{client_name}-client.conf"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("[Interface]\n")
                for param, value in client_data.items():
                    if param != "PublicKey":
                        f.write(f"{param} = {format_value(value)}\n")
                for param in _OBFS_PARAMS:
                    if param in server:
                        f.write(f"{param} = {server[param]}\n")

                f.write("\n[Peer]\n")
                f.write(f"PublicKey = {server['PublicKey']}\n")
                f.write(f"Endpoint = {server['ClientEndpoint']}\n")
                f.write("AllowedIPs = 0.0.0.0/0\n")
                f.write("PersistentKeepalive = 30\n")

            print(f"Client config written: {file_path}")
        except Exception as e:
            sys.exit(e)

def sync_awg_config(data):
    """Apply the current config to the live AWG interface without restart."""
    iface = data["server"]["AWGInterface"]
    config_path = data["server"]["Config"]

    # setconf reads a stripped config (kernel-relevant fields only)
    try:
        stripped = subprocess.run(
            ["awg-quick", "strip", iface],
            check=True, capture_output=True, text=True,
        ).stdout
    except FileNotFoundError:
        print("Warning: 'awg-quick' not found — is AmneziaWG installed?")
        return
    except subprocess.CalledProcessError as e:
        print(f"Could not strip config: {e.stderr.strip()}")
        return

    try:
        subprocess.run(
            ["awg", "setconf", iface, "/dev/stdin"],
            input=stripped, check=True, capture_output=True, text=True,
        )
        print(f"Interface {iface} synced")
    except FileNotFoundError:
        print("Warning: 'awg' not found — is AmneziaWG installed?")
    except subprocess.CalledProcessError as e:
        print(f"Could not sync (interface down?): {e.stderr.strip()}")



# ---------------------------------------------------------------------------
# Client management
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _prompt_client_name(data, *, allow_existing=False):
    """
    Prompt for a valid client name.
    Returns the name string, or None if the user typed 'q'.
    """
    clients = data.get("clients", {})
    while True:
        name = input("Name (or q to return to menu): ").strip()
        if not name:
            print("Error: name cannot be empty")
        elif name == "q":
            return None
        elif not _NAME_RE.match(name):
            print("Error: only letters, digits, _ and - are allowed")
        elif not allow_existing and name in clients:
            answer = input(f"Client '{name}' already exists. Overwrite? (y/N): ")
            if answer.lower() == "y":
                return name
        elif allow_existing and name not in clients:
            print(f"Error: client '{name}' not found")
        else:
            return name


def add_client(data):
    if data.get("clients") is None:
        data["clients"] = {}

    name = _prompt_client_name(data)
    if name is None:
        return data

    private, public = generate_wireguard_keypair()
    jc, jmin, jmax = generate_jitter_variables()
    address = get_free_ip(data)

    data["clients"][name] = {
        "PrivateKey": private,
        "PublicKey": public,
        "Address": address,
        "Jc": jc,
        "Jmin": jmin,
        "Jmax": jmax,
    }
    print(f"Client '{name}' added ({address})")
    return data


def list_clients(data):
    clients = data.get("clients", {})
    if not clients:
        print("No clients configured")
        return
    for name, info in clients.items():
        print(f"{name:20s}  {info['Address']:18s}  {info['PublicKey']}")


def delete_client(data):
    if not data.get("clients"):
        print("No clients configured")
        return data

    name = _prompt_client_name(data, allow_existing=True)
    if name is None:
        return data

    answer = input(f"Delete client '{name}'? (y/N): ")
    if answer.lower() != "y":
        print("Cancelled")
        return data

    del data["clients"][name]
    print(f"Client '{name}' deleted")
    return data

# ---------------------------------------------------------------------------
# Main menu / REPL
# ---------------------------------------------------------------------------

def main_menu():
    print("─" * 20 + " Main Menu " + "─" * 20)
    print("  m) Print this menu")
    print("  l) List clients")
    print("  n) Add new client")
    print("  d) Delete client")
    print("  w) Write AWG configs")
    print("  s) Sync changes with AWG")
    print("  q) Exit")
    print("─" * 51)


def main():
    config = read_config(CONFIG_YAML)
    choice = "m"

    while True:
        if choice == "m":
            main_menu()
        elif choice == "n":
            config = add_client(config)
            write_config(CONFIG_YAML, config)
        elif choice == "l":
            list_clients(config)
        elif choice == "d":
            config = delete_client(config)
            write_config(CONFIG_YAML, config)
        elif choice == "w":
            generate_awg_config(config)
            write_config(CONFIG_YAML, config)
        elif choice == "s":
            sync_awg_config(config)
        elif choice == "q":
            break
        else:
            print("Unknown command — type 'm' for the menu")

        choice = input("Select: ").strip().lower()


if __name__ == "__main__":
    main()
