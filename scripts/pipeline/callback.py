import socket


class Listener:
    """
    Listener is used to evaluate the success of evasive malware.
    """

    def __init__(self, host: str, port: int, timeout: int):
        self.host = host
        self.port = port
        self.timeout = timeout

    def test(self) -> int:
        """
        Tests the callback, returns True if the connection is successful, false
        if no connection is received.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.host, self.port))
                listener.settimeout(self.timeout)
                listener.listen(1)
                conn, addr = listener.accept()
                return 0
        except Exception:
            return 1
