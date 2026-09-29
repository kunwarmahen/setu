"""Gmail for Setu: read your mail, draft replies, never send.

The tool names and shapes follow Google's own Gmail MCP server
(``search_threads``, ``get_thread``, ``get_message``, ``list_labels``,
``list_drafts``, ``create_draft``), so a harness, a skill or a recipe
written against one works against the other -- and whoever can use
Google's server can switch without rewriting anything.
"""

from pathlib import Path

#: The entry point ``setu.connectors:gmail`` resolves to this path.
MANIFEST = str(Path(__file__).with_name("manifest.toml"))
