"""
NetSpy — cli.py
Entry point registered by pyproject.toml as the `netspy` command.
"""

import argparse
import sys
import os
import webbrowser
import threading
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **k): print(*a)
    console = Console()
    Panel = None


def main():
    parser = argparse.ArgumentParser(
        prog="netspy",
        description="NetSpy — Network packet sniffer & live dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netspy                      Start dashboard on http://127.0.0.1:5000
  netspy --port 8080          Use a different port
  netspy --no-browser         Don't open browser automatically
  netspy --host 0.0.0.0       Expose on all interfaces (LAN access)

Then in the browser:
  1. Pick a network interface (or leave blank for auto)
  2. Optionally set a BPF filter (e.g.  tcp port 443)
  3. Press START — packets appear live in the table

Note: Packet capture requires root/admin privileges.
      Run with:  sudo netspy
        """,
    )
    parser.add_argument("--host",       default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", default=5000, type=int, help="Port to bind (default: 5000)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    parser.add_argument("--debug",      action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    url = f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}"

    console.print()
    if Panel:
        console.print(Panel.fit(
            f"[bold white]NetSpy[/]  [dim]v1.0[/]\n"
            f"[dim]Network Packet Sniffer & Visualizer\n\n[/]"
            f"[bold]Dashboard →[/] [cyan]{url}[/]\n\n"
            f"[dim]Ctrl+C to stop[/]",
            border_style="dim",
        ))
    else:
        print(f"NetSpy — dashboard at {url}")

    if not args.no_browser:
        def _open():
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    from .app import run
    try:
        run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        console.print("\n[dim]NetSpy stopped.[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()
