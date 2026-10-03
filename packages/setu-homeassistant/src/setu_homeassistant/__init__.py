"""Home Assistant for Setu: see your home, change it, and -- only at the
level that says so -- the things that guard it.

Two connectors live here, and a person picks one:

* ``homeassistant`` -- Setu's own tools on Home Assistant's REST API.
  Works with any version. Its tools are ours, so their classes are too:
  reading is read, turning things on and off is write, and locks,
  alarms, doors, scripts and admin actions are a separate tool classed
  spend, which a harness asks about every time (server.py).
* ``homeassistant-mcp`` -- a bridge to Home Assistant's built-in MCP
  server (the "Model Context Protocol Server" integration, 2025.2 and
  later). Its tools are Home Assistant's Assist tools, and which devices
  they reach is decided on Home Assistant's own "exposed entities" page
  (bridge.py).
"""

from pathlib import Path

#: The entry points ``setu.connectors:homeassistant`` and
#: ``setu.connectors:homeassistant-mcp`` resolve to these paths.
MANIFEST = str(Path(__file__).with_name("manifest.toml"))
MCP_MANIFEST = str(Path(__file__).with_name("manifest-mcp.toml"))
