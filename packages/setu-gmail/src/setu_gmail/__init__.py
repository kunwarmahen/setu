"""Gmail for Setu: read your mail, draft replies, and send when allowed.

The tool names and shapes follow Google's own Gmail MCP server
(``search_threads``, ``get_thread``, ``get_message``, ``list_labels``,
``list_drafts``, ``create_draft``), so a harness, a skill or a recipe
written against one works against the other -- and whoever can use
Google's server can switch without rewriting anything. ``send_message``
is the one addition Google's server does not have, offered only at the
level that asks Google for sending by name.
"""

from pathlib import Path

#: The entry point ``setu.connectors:gmail`` resolves to this path.
MANIFEST = str(Path(__file__).with_name("manifest.toml"))
