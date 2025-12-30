"""
Utilities module - platform, certificates, and Minecraft helpers.
"""

__all__ = [
    # platform_utils
    "get_platform",
    "find_java_installations",
    "get_java_version",
    "get_java_executable",
    "get_keytool_executable",
    "is_valid_java_home",
    # certificates
    "get_mitmproxy_cert_path",
    "find_cacerts",
    "check_cert_installed",
    "install_cert_to_java",
    "generate_mitmproxy_cert",
    # minecraft
    "find_minecraft_directory",
    "get_minecraft_versions",
    "launch_minecraft",
]

from .platform_utils import (
    get_platform,
    find_java_installations,
    get_java_version,
    get_java_executable,
    get_keytool_executable,
    is_valid_java_home,
)
from .certificates import (
    get_mitmproxy_cert_path,
    find_cacerts,
    check_cert_installed,
    install_cert_to_java,
    generate_mitmproxy_cert,
)
from .minecraft import (
    find_minecraft_directory,
    get_minecraft_versions,
    launch_minecraft,
)
