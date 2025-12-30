"""
Command-line interface for Glance with Rich TUI.
Handles user interaction for Java/version selection and launching.
"""

import os
import sys
import time
import subprocess

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

from core.config import EXPORT_FOLDER
from utils.platform_utils import (
    get_platform,
    find_java_installations,
    get_java_version,
    get_keytool_executable,
)
from utils.minecraft import (
    find_minecraft_directory,
    get_minecraft_versions,
    launch_minecraft,
)
from utils.certificates import (
    get_mitmproxy_cert_path,
    find_cacerts,
    check_cert_installed,
    install_cert_to_java,
    generate_mitmproxy_cert,
)

console = Console()


def print_banner():
    """Display the Glance banner."""
    banner = Text()
    banner.append(
        "╔═══════════════════════════════════════════════════════════╗\n", style="cyan"
    )
    banner.append("║", style="cyan")
    banner.append(
        "              🛡️  GLANCE  🛡️                              ", style="bold white"
    )
    banner.append("║\n", style="cyan")
    banner.append("║", style="cyan")
    banner.append(
        "        Minecraft Security Interceptor                     ", style="dim white"
    )
    banner.append("║\n", style="cyan")
    banner.append(
        "╠═══════════════════════════════════════════════════════════╣\n", style="cyan"
    )
    banner.append("║", style="cyan")
    banner.append(f"  Platform: {get_platform().upper():<48}", style="green")
    banner.append("║\n", style="cyan")
    banner.append(
        "╚═══════════════════════════════════════════════════════════╝", style="cyan"
    )
    console.print(banner)
    console.print()
    console.print(
        Panel(
            "[bold]Protects against malicious mods stealing your tokens[/bold]\n"
            "[dim]Intercepts Discord/Telegram webhooks and API calls[/dim]",
            border_style="dim",
            box=box.ROUNDED,
        )
    )


def select_java():
    """Interactive Java installation selector with Rich UI."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Searching for Java installations...", total=None)
        java_installations = find_java_installations()

    if not java_installations:
        console.print("[bold red]✗[/] Java not found!")
        console.print("  [dim]Install Java (JDK 8+) and try again[/]")
        return None

    # Build Java table
    table = Table(
        title=f"[bold cyan]Found {len(java_installations)} Java Installation(s)[/]",
        box=box.ROUNDED,
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("#", style="cyan", justify="center", width=4)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Path", style="white")
    table.add_column("Version", style="green", width=15)

    for i, java_home in enumerate(java_installations, 1):
        version = get_java_version(java_home)
        cacerts = find_cacerts(java_home)
        keytool = get_keytool_executable(java_home)

        if cacerts:
            installed = check_cert_installed(keytool, cacerts)
            status = "[bold green]✓ CERT[/]" if installed else "[yellow]○ NO CERT[/]"
        else:
            status = "[dim]?[/]"

        table.add_row(str(i), status, java_home, version)

    console.print()
    console.print(table)
    console.print()

    while True:
        try:
            choice = Prompt.ask(
                "[cyan]Select Java[/]",
                default="1",
            )
            choice = int(choice)
            if 1 <= choice <= len(java_installations):
                selected = java_installations[choice - 1]
                console.print(f"[bold green]✓[/] Selected: [cyan]{selected}[/]")
                return selected
            else:
                console.print("[red]Invalid number, try again[/]")
        except ValueError:
            console.print("[red]Enter a number[/]")
        except KeyboardInterrupt:
            return None


def select_minecraft_version(minecraft_dir):
    """Interactive Minecraft version selector with Rich UI."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Searching for Minecraft versions...", total=None)
        versions = get_minecraft_versions(minecraft_dir)

    if not versions:
        console.print("[bold red]✗[/] No Minecraft versions found!")
        console.print(f"  [dim]Check folder: {minecraft_dir}/versions[/]")
        return None

    page_size = 15
    current_page = 0
    total_pages = (len(versions) + page_size - 1) // page_size

    while True:
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, len(versions))

        # Build version table
        table = Table(
            title=f"[bold cyan]Minecraft Versions[/] [dim](Page {current_page + 1}/{total_pages})[/]",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        table.add_column("#", style="cyan", justify="center", width=5)
        table.add_column("Version", style="white")

        for i in range(start_idx, end_idx):
            table.add_row(str(i + 1), versions[i])

        console.print()
        console.print(table)

        if total_pages > 1:
            console.print(
                "[dim]  [n] Next page  •  [p] Previous page  •  Or enter version number[/]"
            )
        console.print()

        try:
            choice = Prompt.ask("[cyan]Select version[/]")

            if choice.lower() == "n" and current_page < total_pages - 1:
                current_page += 1
                continue
            elif choice.lower() == "p" and current_page > 0:
                current_page -= 1
                continue

            choice = int(choice)
            if 1 <= choice <= len(versions):
                selected = versions[choice - 1]
                console.print(f"[bold green]✓[/] Selected: [cyan]{selected}[/]")
                return selected
            else:
                console.print("[red]Invalid number[/]")
        except ValueError:
            console.print("[red]Enter a number[/]")
        except KeyboardInterrupt:
            return None


def setup_certificates(java_home):
    """Handle certificate generation and installation with Rich UI."""
    console.print()
    console.rule("[bold cyan]Certificate Setup[/]", style="cyan")
    console.print()

    # Generate certificate
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking mitmproxy certificate...", total=None)
        success = generate_mitmproxy_cert()

    if not success:
        console.print("[bold red]✗[/] Failed to create certificate. Exiting.")
        return False, None

    cert_path = get_mitmproxy_cert_path()
    console.print(f"[bold green]✓[/] Certificate: [dim]{cert_path}[/]")

    # Install to Java
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Installing certificate to Java keystore...", total=None)
        installed = install_cert_to_java(java_home, cert_path)

    if not installed:
        console.print("[bold yellow]![/] Failed to install certificate automatically")
        console.print("  [dim]Minecraft may not trust the proxy[/]")
        if not Confirm.ask("Continue anyway?", default=False):
            return False, None

    return True, cert_path


def launch_session(java_home, minecraft_dir, version, username):
    """Launch the MITM proxy and Minecraft with Rich UI."""
    console.print()
    console.rule("[bold cyan]Launching[/]", style="cyan")
    console.print()

    console.print("[bold green]▶[/] Starting MITM proxy on port [cyan]8080[/]...")
    console.print(f"[dim]  Exports folder: {EXPORT_FOLDER.absolute()}[/]")
    console.print()

    # Start mitmproxy
    try:
        addon_path = os.path.join(os.path.dirname(__file__), "core", "addon.py")
        mitm_process = subprocess.Popen(
            [
                "mitmdump",
                "-s",
                addon_path,
                "--listen-port",
                "8080",
                "--set",
                "block_global=false",
                "--set",
                "ssl_insecure=true",
                "--ssl-insecure",
            ],
        )
        console.print(
            f"[bold green]✓[/] MITM proxy started [dim](PID: {mitm_process.pid})[/]"
        )
    except FileNotFoundError:
        console.print("[bold red]✗[/] mitmdump not found!")
        console.print("  [dim]Install: pip install mitmproxy[/]")
        return

    time.sleep(2)

    # Launch Minecraft
    mc_process = launch_minecraft(java_home, minecraft_dir, version, username)

    if mc_process:
        console.print()
        console.print(
            Panel(
                "[bold green]Minecraft is running![/]\n\n"
                "[cyan]All HTTPS traffic is being intercepted[/]\n"
                "[dim]Suspicious requests will be blocked and logged[/]\n\n"
                "[yellow]Press Ctrl+C to stop[/]",
                title="[bold]🎮 Active Session[/]",
                border_style="green",
                box=box.DOUBLE,
            )
        )

        try:
            mc_process.wait()
        except KeyboardInterrupt:
            pass
        finally:
            mitm_process.terminate()
            console.print("\n[bold green]✓[/] Session ended")
    else:
        console.print()
        console.print(
            Panel(
                "[yellow]Minecraft not launched automatically[/]\n\n"
                "Launch Minecraft manually with proxy:\n"
                "[cyan]  Host: 127.0.0.1[/]\n"
                "[cyan]  Port: 8080[/]\n\n"
                "[dim]Press Ctrl+C to stop MITM proxy[/]",
                title="[bold]Manual Launch Required[/]",
                border_style="yellow",
            )
        )

        try:
            mitm_process.wait()
        except KeyboardInterrupt:
            mitm_process.terminate()
            console.print("\n[bold green]✓[/] Proxy stopped")


def main():
    """Main entry point for the Glance CLI."""
    console.clear()
    print_banner()
    console.print()

    # Select Java
    java_home = select_java()
    if not java_home:
        console.print("\n[bold red]✗[/] Java not selected. Exiting.")
        sys.exit(1)

    # Find Minecraft
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Finding Minecraft installation...", total=None)
        minecraft_dir = find_minecraft_directory()

    if not minecraft_dir:
        console.print("[bold red]✗[/] .minecraft folder not found!")
        console.print("  [dim]Run Minecraft at least once first[/]")
        sys.exit(1)

    console.print(f"[bold green]✓[/] Found Minecraft: [dim]{minecraft_dir}[/]")

    # Certificate setup
    success, cert_path = setup_certificates(java_home)
    if not success:
        sys.exit(1)

    # Select Minecraft version
    console.print()
    console.rule("[bold cyan]Select Minecraft Version[/]", style="cyan")

    version = select_minecraft_version(minecraft_dir)
    if not version:
        console.print("\n[bold red]✗[/] Version not selected. Exiting.")
        sys.exit(1)

    # Get username
    console.print()
    username = Prompt.ask("[cyan]Enter username[/]", default="Player")

    # Launch session
    launch_session(java_home, minecraft_dir, version, username)


if __name__ == "__main__":
    main()
