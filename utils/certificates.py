"""
Certificate generation and installation utilities.
Handles mitmproxy certificate management and Java keystore operations.
"""

import os
import time
import subprocess

from utils.platform_utils import get_platform, get_keytool_executable


def get_mitmproxy_cert_path():
    """Get the path to the mitmproxy CA certificate."""
    home = os.path.expanduser("~")
    mitmproxy_dir = os.path.join(home, ".mitmproxy")
    cert_files = [
        "mitmproxy-ca-cert.pem",
        "mitmproxy-ca-cert.cer",
        "mitmproxy-ca-cert.p12",
    ]

    for cert_file in cert_files:
        cert_path = os.path.join(mitmproxy_dir, cert_file)
        if os.path.exists(cert_path):
            return cert_path

    return os.path.join(mitmproxy_dir, "mitmproxy-ca-cert.pem")


def find_cacerts(java_home):
    """Find the cacerts file in a Java installation."""
    possible_paths = [
        os.path.join(java_home, "lib", "security", "cacerts"),
        os.path.join(java_home, "jre", "lib", "security", "cacerts"),
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None


def check_cert_installed(keytool, cacerts_path, alias="mitmproxy"):
    """Check if a certificate is already installed in the keystore."""
    cmd = [
        keytool,
        "-list",
        "-alias",
        alias,
        "-keystore",
        cacerts_path,
        "-storepass",
        "changeit",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0


def install_cert_to_java(java_home, cert_path):
    """Install the mitmproxy certificate to a Java installation's keystore."""
    current_os = get_platform()
    keytool = get_keytool_executable(java_home)

    cacerts_path = find_cacerts(java_home)
    if not cacerts_path:
        print(f"  [X] cacerts not found in {java_home}")
        return False

    if not os.path.exists(cert_path):
        print(f"  [X] Certificate not found: {cert_path}")
        return False

    if check_cert_installed(keytool, cacerts_path):
        print(f"  [OK] Certificate already installed in {java_home}")
        return True

    install_cmd = [
        keytool,
        "-import",
        "-trustcacerts",
        "-alias",
        "mitmproxy",
        "-file",
        cert_path,
        "-keystore",
        cacerts_path,
        "-storepass",
        "changeit",
        "-noprompt",
    ]

    try:
        if current_os != "windows":
            result = subprocess.run(install_cmd, capture_output=True, text=True)
            if result.returncode != 0 and "permission" in result.stderr.lower():
                install_cmd = ["sudo"] + install_cmd
                result = subprocess.run(install_cmd, capture_output=True, text=True)
        else:
            result = subprocess.run(install_cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"  [OK] Certificate installed in {java_home}")
            return True
        else:
            print(f"  [X] Installation error: {result.stderr}")
            return False
    except Exception as e:
        print(f"  [X] Error: {e}")
        return False


def generate_mitmproxy_cert():
    """Generate the mitmproxy CA certificate if it doesn't exist."""
    home = os.path.expanduser("~")
    mitmproxy_dir = os.path.join(home, ".mitmproxy")
    cert_path = os.path.join(mitmproxy_dir, "mitmproxy-ca-cert.pem")

    if os.path.exists(cert_path):
        print(f"[OK] mitmproxy certificate already exists: {cert_path}")
        return True

    print("[*] Generating mitmproxy certificate...")
    print("    (Running mitmdump briefly to create certificates)")

    try:
        process = subprocess.Popen(
            ["mitmdump", "--listen-port", "18080"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        process.terminate()
        process.wait()

        if os.path.exists(cert_path):
            print(f"[OK] Certificate created: {cert_path}")
            return True
        else:
            print("[X] Failed to create certificate")
            return False
    except FileNotFoundError:
        print("[X] mitmdump not found! Install: pip install mitmproxy")
        return False
    except Exception as e:
        print(f"[X] Error: {e}")
        return False
