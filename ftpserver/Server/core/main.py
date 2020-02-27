"""
FTPServer
"""
from .ftpserver import MyFTPServer
from .parseini import HOST
from .parseini import PORT
from gevent import spawn


def run():
    server = MyFTPServer((HOST, PORT))
    server.server_run()


def main():
    """
    main()
    """
    spawn(run).join()
