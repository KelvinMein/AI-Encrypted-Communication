from fastapi import WebSocket

# email -> the live WebSocket of that user. Shared so an administrator's action can end a session.
active_connections: dict[str, WebSocket] = {}

# session id -> its live WebSocket, so signing out a session also closes its connection
session_sockets: dict[str, WebSocket] = {}