"""Constants shared by the server and the client.

Kept in its own module with no imports so the client executable does not drag
in tkinter, pystray and PIL just to learn a header name.
"""

API_VERSION = "1"
REQUIRED_HEADER = "X-Bwprx-Client"
MAX_BODY = 64 * 1024

ENDPOINT_STATUS = "/v1/status"
ENDPOINT_LIST = "/v1/list"
ENDPOINT_CREDENTIAL = "/v1/credential"
ENDPOINT_CREATE = "/v1/item/create"
ENDPOINT_EDIT = "/v1/item/edit"
ENDPOINT_DELETE = "/v1/item/delete"
ENDPOINT_MOVE = "/v1/item/move"
ENDPOINT_FOLDERS = "/v1/folders"
ENDPOINT_FOLDER_CREATE = "/v1/folder/create"
