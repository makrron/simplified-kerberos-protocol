"""
Example class for sending and receiving messages on a TCP channel.
Do not use in a production environment
"""

import socket
import struct


class SOCKET_SIMPLE_TCP:

    def __init__(self, host, puerto):
        """Initializes a TCP socket object, providing a host and a port."""
        self.host = host
        self.puerto = puerto
        self.server = None

    def connect(self):
        """Converts the socket object into a client, and connects to a server."""
        self.socket = socket.create_connection((self.host, self.puerto))

    def listen(self):
        """Converts the socket object into a server, and receives the request from a client."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (self.host, self.puerto)
        self.server.bind(server_address)
        self.server.listen(1)
        self.socket, dir_cliente = self.server.accept()
        return dir_cliente

    def __recvall(self, count):
        """PRIVATE: Receive "count" bytes from the input buffer"""
        buffer = b''
        while count:
            newbuf = self.socket.recv(count)
            if not newbuf:
                return None
            buffer += newbuf
            count -= len(newbuf)
        return buffer

    def send(self, datos):
        """Sends an array of "data" bytes from the source to the destination."""
        longitud = len(datos)
        self.socket.sendall(struct.pack('!I', longitud))
        self.socket.sendall(datos)

    def receive(self):
        """Receives an array of "data" bytes from the destination to the destination."""
        lenbuf = self.__recvall(4)
        longitud, = struct.unpack('!I', lenbuf)
        return self.__recvall(longitud)

    def close(self):
        """Closes the connection"""
        if self.socket != None:
            self.socket.close()
