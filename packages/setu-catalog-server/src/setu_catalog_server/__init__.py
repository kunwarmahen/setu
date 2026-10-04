"""Setu's catalog, served: the signed index, install counts, submissions.

THE SERVER NEVER HOLDS THE SIGNING KEY. It keeps and serves the bytes the
maintainer signed on their own machine (``setu catalog sign``). A server
taken over can withhold the index or serve an old one -- and clients
refuse an index older than the one they kept -- but it cannot list a
connector, change a hash or lift a withdrawal: every client checks the
signature against the keys it trusts. What the server knows that is not
signed (live install counts, the submission queue) is a hint or an
inbox, never authority.

FILES, NO DATABASE. Everything lives under one data directory, written
atomically: the index and its signature, the keys an upload must be
signed by, the counts, the queue. Back it up by copying it.
"""

__version__ = "0.1.0"
