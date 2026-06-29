"""
NetSpy — app.py
Flask web server. Serves the dashboard and exposes a JSON API
that the frontend polls every second to show live packet data.
"""

import os
import sys
from pathlib import Path
from flask import Flask, jsonify, request, render_template, abort
from . import capture

# Always resolve templates relative to this file — works from any venv or install path
_TEMPLATES = Path(__file__).parent / "templates"
app = Flask(__name__, template_folder=str(_TEMPLATES))
app.config["SECRET_KEY"] = os.urandom(16)


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/packets")
def api_packets():
    since = request.args.get("since", 0, type=int)
    limit = request.args.get("limit", 100, type=int)
    pkts  = capture.get_packets(since_id=since, limit=limit)
    return jsonify(pkts)


@app.route("/api/stats")
def api_stats():
    return jsonify(capture.get_stats())


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(capture.list_interfaces())


@app.route("/api/start", methods=["POST"])
def api_start():
    data       = request.get_json(silent=True) or {}
    iface      = data.get("iface") or None
    bpf_filter = data.get("filter", "")
    started    = capture.start_capture(iface=iface, bpf_filter=bpf_filter)
    return jsonify({"ok": started, "running": capture.is_running()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    capture.stop_capture()
    return jsonify({"ok": True, "running": False})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    capture.clear()
    return jsonify({"ok": True})


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    interfaces = capture.list_interfaces()
    return render_template("dashboard.html", interfaces=interfaces)


def run(host="127.0.0.1", port=5000, debug=False):
    app.run(host=host, port=port, debug=debug, use_reloader=False)
