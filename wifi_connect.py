#!/usr/bin/env python3
"""
wifi_connect.py — Scan for WiFi networks, pick one, connect, and print
every step of the process in detail (Windows only).

Windows' native WiFi UI just shows a spinner and gives you almost no
feedback when a connection fails. This script talks to `netsh wlan`
directly and prints state transitions, auth/association progress,
error codes, and the final result so you can actually see what's
happening.

Usage:
    python wifi_connect.py

Requires: Windows, Python 3.8+, no third-party packages.
Run from an elevated (Administrator) terminal if profile creation fails.
"""

import subprocess
import sys
import time
import re
import locale
import xml.sax.saxutils as sax

ENCODING = locale.getpreferredencoding(False)


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=15):
    """Run a command, return (returncode, stdout, stderr) as decoded text."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print("ERROR: 'netsh' not found. This script only works on Windows.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return 1, "", "TIMEOUT"

    out = proc.stdout.decode(ENCODING, errors="replace")
    err = proc.stderr.decode(ENCODING, errors="replace")
    return proc.returncode, out, err


def log(msg, level="INFO"):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def check_wifi_adapter():
    log("Checking for a WiFi interface...")
    rc, out, err = run(["netsh", "wlan", "show", "interfaces"])
    if "There is no wireless interface" in out or rc != 0 and not out.strip():
        log("No WiFi adapter found, or WiFi is disabled/driver missing.", "ERROR")
        sys.exit(1)
    log("WiFi interface detected.")
    return out


def scan_networks():
    log("Triggering a network scan (netsh wlan show networks mode=bssid)...")
    rc, out, err = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if rc != 0:
        log(f"Scan command failed: {err.strip()}", "ERROR")
        sys.exit(1)

    networks = []
    current = None

    for line in out.splitlines():
        line = line.rstrip()

        m = re.match(r"^SSID\s+\d+\s+:\s?(.*)$", line)
        if m:
            if current:
                networks.append(current)
            current = {
                "ssid": m.group(1).strip(),
                "auth": "",
                "cipher": "",
                "signal": "",
                "bssids": [],
            }
            continue

        if current is None:
            continue

        m = re.match(r"^\s*Authentication\s+:\s?(.*)$", line)
        if m:
            current["auth"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Encryption\s+:\s?(.*)$", line)
        if m:
            current["cipher"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Signal\s+:\s?(.*)$", line)
        if m:
            current["signal"] = m.group(1).strip()
            continue
        
        m = re.match(r"^\s*BSSID\s+\d+\s+:\s?(.*)$", line)
        if m:
            current["bssids"].append(m.group(1).strip())
            continue

    if current:
        networks.append(current)

    log(f"Scan complete. Found {len(networks)} network(s).")
    return networks


def print_networks(networks):
    print()
    print(f"{'#':<4}{'SSID':<30}{'Signal':<10}{'MAC':<20}{'Auth':<15}{'Cipher':<10}")
    print("-" * 90)
    for i, n in enumerate(networks, start=1):
        ssid = n["ssid"] or "<hidden>"
        mac = n["bssids"][0] if n["bssids"] else "-"
        print(f"{i:<4}{ssid:<30}{n['signal']:<10}{mac:<20}{n['auth']:<15}{n['cipher']:<10}")
    print()


# --------------------------------------------------------------------------
# Profiles / connecting
# --------------------------------------------------------------------------

def list_existing_profiles():
    rc, out, err = run(["netsh", "wlan", "show", "profiles"])
    profiles = re.findall(r"^\s*(?:[A-Za-z]+\s+)*Profile\s*:\s?(.*)$", out, re.MULTILINE)
    return [p.strip() for p in profiles]


def build_profile_xml(ssid, auth, cipher, password):
    """Build a minimal WLAN profile XML for the given auth/cipher combo."""
    ssid_esc = sax.escape(ssid)
    pass_esc = sax.escape(password) if password else ""

    open_network = auth.lower() in ("open",) and not password

    if open_network:
        security_block = """
      <authEncryption>
        <authentication>open</authentication>
        <encryption>none</encryption>
        <useOneX>false</useOneX>
      </authEncryption>"""
        shared_key_block = ""
    else:
        # Map common auth strings to netsh profile values
        auth_map = {
            "wpa2-personal": "WPA2PSK",
            "wpa2-psk": "WPA2PSK",
            "wpa3-personal": "WPA3SAE",
            "wpa2/wpa3": "WPA2PSK",
            "wpa-personal": "WPAPSK",
        }
        auth_key = auth_map.get(auth.lower(), "WPA2PSK")
        cipher_val = "AES" if "AES" in cipher.upper() or not cipher else cipher.upper()
        if cipher_val not in ("AES", "TKIP"):
            cipher_val = "AES"

        security_block = f"""
      <authEncryption>
        <authentication>{auth_key}</authentication>
        <encryption>{cipher_val}</encryption>
        <useOneX>false</useOneX>
      </authEncryption>"""
        shared_key_block = f"""
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{pass_esc}</keyMaterial>
      </sharedKey>"""

    xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{ssid_esc}</name>
  <SSIDConfig>
    <SSID>
      <name>{ssid_esc}</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM>
    <security>{security_block}{shared_key_block}
    </security>
  </MSM>
</WLANProfile>
"""
    return xml


def add_profile(ssid, xml_content):
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(xml_content)

    log(f"Writing temporary profile XML to {path}")
    # user=current avoids the admin-rights requirement of an "All User" profile.
    rc, out, err = run(["netsh", "wlan", "add", "profile", f"filename={path}", "user=current"])
    os.remove(path)

    if rc != 0:
        log(f"Failed to add profile: {out.strip() or err.strip()}", "ERROR")
        log("If this persists, try running the terminal as Administrator.", "WARN")
        return False

    log("Profile added successfully (current user).")
    return True


def connect(ssid):
    log(f"Issuing connect command for SSID '{ssid}'...")
    rc, out, err = run(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"])
    if rc != 0:
        log(f"Connect command failed immediately: {out.strip() or err.strip()}", "ERROR")
        return False
    log("Connect command accepted by Windows. Monitoring interface state...")
    return True


def get_wlan_event_diagnostics(lookback_seconds=60, max_events=40):
    """Pull recent WLAN-AutoConfig operational events for a detailed reason
    behind a failed/aborted connection (Windows hides this from netsh)."""
    ps_cmd = (
        f"Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' "
        f"-MaxEvents {max_events} -ErrorAction Stop | "
        f"Where-Object {{ $_.TimeCreated -ge (Get-Date).AddSeconds(-{lookback_seconds}) }} | "
        f"Sort-Object TimeCreated | "
        f"ForEach-Object {{ \"---[{{0}}] Id:{{1}}---`n{{2}}\" -f "
        f"$_.TimeCreated.ToString('HH:mm:ss'), $_.Id, $_.Message }}"
    )
    rc, out, err = run(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=20)
    if rc != 0 or not out.strip():
        return None
    return out.strip()


def print_failure_diagnostics():
    log("Pulling detailed diagnostics from Windows event log...")
    details = get_wlan_event_diagnostics()
    if not details:
        log("Could not read WLAN-AutoConfig event log (may need admin rights, "
            "or no events were logged for this attempt).", "WARN")
        log("You can also run 'netsh wlan show wlanreport' manually, then open "
            "C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.html "
            "for a full visual report of the last connection attempts.")
        return
    print()
    print("=" * 70)
    print(" DETAILED WINDOWS WLAN EVENT LOG (most likely real cause below)")
    print("=" * 70)
    print(details)
    print("=" * 70)
    print()

def get_wifi_interface_name():
    rc, out, err = run(["netsh", "wlan", "show", "interfaces"])
    fields = parse_interface_state(out)
    return fields.get("Name", "Wi-Fi")


def restart_wifi_adapter():
    iface = get_wifi_interface_name()
    log(f"Restarting WiFi adapter '{iface}'...")

    log(f"Disabling '{iface}'...")
    rc, out, err = run(["netsh", "interface", "set", "interface", iface, "admin=disable"])
    if rc != 0:
        log(f"Failed to disable adapter: {out.strip() or err.strip()}", "ERROR")
        log("This usually requires Administrator rights — try running the "
            "terminal as Administrator.", "WARN")
        return False

    time.sleep(3)

    log(f"Enabling '{iface}'...")
    rc, out, err = run(["netsh", "interface", "set", "interface", iface, "admin=enable"])
    if rc != 0:
        log(f"Failed to re-enable adapter: {out.strip() or err.strip()}", "ERROR")
        log(f"You may need to manually re-enable '{iface}' in Network Connections.", "WARN")
        return False

    log("Waiting for adapter to come back up...")
    time.sleep(4)
    log("WiFi adapter restarted.")
    return True

def parse_interface_state(out):
    fields = {}
    for line in out.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9 .]+?)\s*:\s?(.*)$", line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            fields[key] = val
    return fields


def monitor_connection(ssid, timeout=25, poll_interval=1.0):
    log(f"Watching connection progress for up to {timeout}s...")
    last_state = None
    last_signal = None
    start = time.time()

    while time.time() - start < timeout:
        rc, out, err = run(["netsh", "wlan", "show", "interfaces"])
        fields = parse_interface_state(out)

        state = fields.get("State", "unknown")
        current_ssid = fields.get("SSID", "")
        signal = fields.get("Signal", "")
        radio = fields.get("Radio type", "")
        auth = fields.get("Authentication", "")
        channel = fields.get("Channel", "")

        if state != last_state:
            log(f"Interface state changed -> '{state}'"
                + (f" (SSID: {current_ssid})" if current_ssid else ""))
            last_state = state

        if signal and signal != last_signal:
            log(f"Signal quality: {signal}")
            last_signal = signal

        if state == "connected" and current_ssid == ssid:
            log("CONNECTED.", "SUCCESS")
            log(f"  SSID      : {current_ssid}")
            log(f"  Signal    : {signal}")
            log(f"  Radio type: {radio}")
            log(f"  Auth      : {auth}")
            log(f"  Channel   : {channel}")
            return True

        if state == "disconnected" and (time.time() - start) > 8:
            # give it a few seconds grace before flagging as stuck
            log("Still disconnected — authentication or association may be failing.", "WARN")

        time.sleep(poll_interval)

    log(f"Timed out after {timeout}s without reaching 'connected' state.", "ERROR")
    log("Common causes: wrong password, weak signal, MAC filtering, "
        "captive portal, or router rejecting the auth/cipher combo.")
    print_failure_diagnostics()
    return False


# --------------------------------------------------------------------------
# Main flow
# --------------------------------------------------------------------------

def main():
    if not sys.platform.startswith("win"):
        print("This script relies on 'netsh wlan' and only works on Windows.")
        sys.exit(1)

    check_wifi_adapter()

    while True:
        networks = scan_networks()

        if not networks:
            log("No networks found. Try moving closer to a router or check "
                "that WiFi is turned on.", "WARN")

        print_networks(networks)

        choice = input(
            f"Pick a network [1-{len(networks)}], Type '0' to refresh, 'R' to restart WiFi: \n\n =======> "
        ).strip().lower()

        if choice == "0":
            log("Refreshing network list...")
            continue

        if choice == "r":
            restart_wifi_adapter()
            log("Refreshing network list...")
            continue

        try:
            idx = int(choice) - 1
            assert 0 <= idx < len(networks)
        except (ValueError, AssertionError):
            print("Invalid selection.")
            continue

        break

    target = networks[idx]
    ssid = target["ssid"]
    log(f"Selected network: '{ssid}' (auth={target['auth']}, cipher={target['cipher']})")

    existing_profiles = list_existing_profiles()
    is_open = target["auth"].lower() == "open"

    if ssid in existing_profiles:
        log(f"A saved profile for '{ssid}' already exists — reusing it.")
    else:
        log(f"No saved profile for '{ssid}' found. Creating one...")
        password = ""
        if not is_open:
            password = input(f"Password for '{ssid}' (visible): ").strip()

        xml_content = build_profile_xml(ssid, target["auth"], target["cipher"], password)
        if not add_profile(ssid, xml_content):
            log("Aborting: could not create profile.", "ERROR")
            sys.exit(1)

    if not connect(ssid):
        sys.exit(1)

    success = monitor_connection(ssid)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
