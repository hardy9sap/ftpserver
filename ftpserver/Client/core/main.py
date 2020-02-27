"""
FTPClient
"""
from .ftpclient import MyFTPClient
from .parseini import HOST
from .parseini import PORT


def main():
    client = MyFTPClient((HOST, PORT))
    client.client_run()
