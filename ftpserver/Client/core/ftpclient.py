"""
FTPClient
"""
from .parseini import DOWNLOADS_PATH
from .parseini import UPLOADS_PATH
from .parseini import FILESTATUS
import hashlib
import socket
import struct
import time
import hmac
import json
import sys
import os


class Open(object):
    """文件管理协议类"""

    def __init__(self, name, mode, encoding=None):
        """文件名、模式、编码初始化"""
        self.name = name
        self.mode = mode
        self.encoding = encoding

    def __enter__(self):
        """返回一个文件对象给as后面定义的变量"""
        self.fp = open(file=self.name, mode=self.mode, encoding=self.encoding)
        return self.fp

    def __exit__(self, exc_type, exc_val, exc_tb):
        """文件管理协议语句结束后，做系统资源回收"""
        self.fp.flush()
        self.fp.close()
        if os.path.basename(self.fp.name) == 'filestatus.json.bak':
            os.replace(self.fp.name, os.path.splitext(self.fp.name)[0])
        return True


class MyFTPClient(object):
    """FTPClient类

     Attributes:
        :param: __protocol_type: socket协议类型
        :param: __address_family: socket地址簇
        :param: __buffer_size: 默认读写字节数
        :param: __encoding: 默认编码/解码
        :param: func_dc: 功能映射字典
     """
    __encoding = sys.getdefaultencoding()

    __protocol_type = socket.SOCK_STREAM

    __address_famliy = socket.AF_INET

    __buffer_size = 1024

    func_dc = {
        'setcon': 'setconcurrency',
        'setquota': 'setquota',
        'cd': 'change_dir',
        'ls': 'list_dir',
        'exit': 'logout',
        'get': 'get',
        'put': 'put'
    }

    def __init__(self, connected_address, connect=True):
        """MyFTPClient实例对象初始化"""
        self.connected_address = connected_address
        self.socket = socket.socket(family=MyFTPClient.__address_famliy,
                                    type=MyFTPClient.__protocol_type)
        self.cmd = None
        self.filename = None
        self.file_path = None
        self.filesize = None
        self.filetype = None

        if connect:
            self.__client_connect()

    def __client_connect(self):
        """客户端连接服务端"""
        self.socket.connect(self.connected_address)

    def client_run(self):
        """验证客户端、验证身份、续传功能分发器"""
        if self.socket.recv(self.__buffer_size) == b'False':
            print('Request exceeded limit. Please try again later!')
            exit()
        # 验证客户端
        status = self.__check_client()
        if not status:
            self.__client_close()
            exit()

        # 验证身份
        while not self.__check_identity():
            pass

        # 检查get下载功能续传部分
        self.__check_get_bkpt_file()

        # 加载put上传续传文件()
        self.__load_put_bkpt_file()

        # 检查put上传功能续传部分
        self.__check_put_bkpt_file()

        # 交互开始
        while 1:  # 隐藏属性用不了反射
            cmds = input('>>> ').strip()
            if not cmds:
                continue
            cmds_ls = cmds.split()
            cmd = self.func_dc.get(cmds_ls[0])
            if cmd is None:
                continue
            if hasattr(self, cmd):
                func = getattr(self, cmd)
                func(cmds_ls)

    def __check_client(self):
        """验证客户端"""
        sk = self.socket
        secret_key = 'luffycity'
        encrypting_bytes = sk.recv(self.__buffer_size)
        client_crypt = hmac.digest(bytes(secret_key, self.__encoding), encrypting_bytes, 'md5')
        sk.send(client_crypt)
        status = sk.recv(self.__buffer_size)
        if status == b'True':
            print('Legal client, welcome to use!')
            return True
        else:
            print('Illegal client, connection aborted')
            return False

    def __check_identity(self):
        """验证身份"""
        while 1:
            account = input('(Account)>>> ').strip()
            password = input('(Password)>>> ').strip()
            h = hashlib.md5(account.encode(encoding=self.__encoding))
            h.update(password.encode(encoding=self.__encoding))
            identity_code = h.hexdigest()
            identity_dc = {'account': account, 'identity_code': identity_code}
            identity_json = json.dumps(identity_dc)
            identity_bytes = bytes(identity_json, encoding=self.__encoding)
            identity_struct = struct.pack('i', len(identity_bytes))
            self.socket.send(identity_struct)
            self.socket.send(identity_bytes)
            status = self.socket.recv(1024)
            if status == b'True':
                print('Identification confirmed!')
                self.filestatus_path = FILESTATUS
                self.cur_user = account
                return True
            else:
                print('Identification denied!')

    def __load_put_bkpt_file(self):
        """加载put断点续传"""
        with Open(self.filestatus_path, 'r', self.__encoding) as fp:
            self.filestatus = json.load(fp)

    def __check_put_bkpt_file(self):
        """进行put断点续传"""
        if not self.filestatus or self.cur_user not in self.filestatus:
            self.socket.send(b'False')
            return
        deleting_ls = []
        for elm in self.filestatus[self.cur_user]:
            print(f'File: <{elm}>')
            print('Press y to resume or Press n to remove')
            code = input('Continue to DOWNLOAD?[y / n] ').strip()
            self.socket.send(bytes(code, encoding=self.__encoding))
            if code == 'y':

                filesize = self.filestatus[self.cur_user][elm]['filesize']
                filepath = self.filestatus[self.cur_user][elm]['filepath']
                header = {
                    'filename': elm,
                    'filesize': filesize,
                    'response': code
                }
                header_bytes = json.dumps(header).encode(encoding=self.__encoding)
                struct_head = struct.pack('i', len(header_bytes))
                self.socket.send(struct_head)
                self.socket.send(header_bytes)

                struct_head = self.socket.recv(4)
                cur_pos = int(self.socket.recv(struct.unpack('i', struct_head)[0]).decode(encoding=self.__encoding))
                readed_size = cur_pos
                dot = '.'
                lt = '>'
                starting = time.perf_counter()
                print('Upload Starting'.center(100, '='))
                with Open(filepath, 'rb', None) as fp:
                    fp.seek(cur_pos)
                    while readed_size < filesize:
                        data = fp.read(self.__buffer_size)
                        self.socket.send(data)
                        readed_size += len(data)
                        scale = readed_size / filesize * 100
                        print('\r%%%.2f[%s%s]%.2fs' % (
                            scale,
                            int(scale) * lt,
                            (100 - int(scale)) * dot,
                            time.perf_counter() - starting
                        ), end='')
                if self.socket.recv(4) == b'True':
                    print(f"File: <{elm}> Complete!")
                else:
                    print(f"File: <{elm}> Damaged, please UPLOAD again!")
                self.socket.recv(2)
                deleting_ls.append(elm)
            else:
                self.socket.send(bytes(elm, encoding=self.__encoding))
                recvs = self.socket.recv(self.__buffer_size)
                if recvs == b'True':
                    print(f'File: <{elm}> has been removed!')

        with Open(self.filestatus_path, 'r+', self.__encoding) as fp:
            for elm in deleting_ls:
                self.filestatus[self.cur_user].pop(elm)
            if not self.filestatus[self.cur_user]:
                self.filestatus.pop(self.cur_user)
            json.dump(self.filestatus, fp)
            fp.truncate()
        self.socket.send(b'exit')
        return

    def __check_get_bkpt_file(self):
        """进行get断点续传"""
        while 1:
            recvs = self.socket.recv(self.__buffer_size).decode(encoding=self.__encoding)
            if recvs == 'False' or recvs == 'exit':
                return
            else:
                print(f'File: <{recvs}>')
                print('Press y to resume or Press n to remove')
                res = input('Continue to DOWNLOAD?[y / n] ').strip()
                if res is 'y':
                    self.socket.send(res.encode(encoding=self.__encoding))
                    struct_head = self.socket.recv(4)
                    header_len = struct.unpack('i', struct_head)[0]
                    header_dc = json.loads(self.socket.recv(header_len).decode(encoding=self.__encoding))
                    cur_file_size = os.path.getsize(os.path.abspath(os.path.join(DOWNLOADS_PATH, recvs)))
                    struct_head = struct.pack('i', str(cur_file_size).encode(encoding=self.__encoding).__len__())
                    self.socket.send(struct_head)
                    self.socket.send(str(cur_file_size).encode(encoding=self.__encoding))
                    # 传输开始
                    readed_size = cur_file_size
                    filesize = header_dc['filesize']
                    dot = '.'
                    lt = '>'
                    starting = time.perf_counter()
                    print('Transfer Starting'.center(100, '='))
                    with Open(DOWNLOADS_PATH + header_dc['filename'], 'ab', None) as fp:
                        while readed_size < filesize:
                            recvs = self.socket.recv(self.__buffer_size)
                            fp.write(recvs)
                            readed_size += len(recvs)
                            scale = readed_size / filesize * 100
                            print('\r%%%.2f[%s%s]%.2fs' % (
                                scale,
                                int(scale) * lt,
                                (100 - int(scale)) * dot,
                                time.perf_counter() - starting
                            ), end='')
                    self.socket.send(b'OK')
                    print()
                    print('Transfer Ending'.center(100, '='))
                    if os.path.getsize(fp.name) == filesize:
                        print(f"File: <{header_dc['filename']}> Complete!")
                        os.system(f'start explorer {os.path.abspath(DOWNLOADS_PATH)}')
                    else:
                        print(f"File: <{header_dc['filename']}> Damaged, please DOWNLOAD again!")
                else:
                    self.socket.send(res.encode(encoding=self.__encoding))
                    os.remove(DOWNLOADS_PATH + recvs)
                    print(f'File: <{recvs}> has been removed!')

    def setquota(self, args):
        """配额"""
        if args.__len__() != 2:
            return
        amount = args[-1][:-1]
        unit = args[-1][-1]
        if amount.isdigit() and unit in ('K', 'M', 'G'):
            self.socket.send(' '.join(args).encode(encoding=self.__encoding))
            status = self.socket.recv(self.__buffer_size)
            if status:
                print('Operation successful.')
            else:
                print('Operation unsuccessful.')
            return

    def setconcurrency(self, args):
        """设置并发数"""
        if args.__len__() != 2:
            return
        amount = args[-1]
        if amount.isdigit():
            self.socket.send(' '.join(args).encode(encoding=self.__encoding))
            status = self.socket.recv(self.__buffer_size)
            if status:
                print('Operation successful.')
            else:
                print('Operation unsuccessful.')
            return

    def change_dir(self, args):
        """切换目录"""
        self.socket.send(' '.join(args).encode(encoding=self.__encoding))
        path = self.socket.recv(self.__buffer_size).decode(encoding=self.__encoding)
        if path == 'False':
            print('Operation unsuccessful.')
            print(f"Unaccepted path: {' '.join(args)} or Permission denied!")
        else:
            print('Operation successful.')
            print(f'Your current path: {path}')
        return

    def list_dir(self, args):
        """查看目录下的文件"""
        self.socket.send(' '.join(args).encode(encoding=self.__encoding))
        struct_bytes = self.socket.recv(4)
        struct_len = struct.unpack('i', struct_bytes)[0]
        result = self.socket.recv(struct_len).decode(encoding=self.__encoding)
        print(result)

    def get(self, args):
        """下载功能"""
        if args.__len__() == 2:
            self.socket.send(' '.join(args).encode(encoding=self.__encoding))
            struct_head = self.socket.recv(4)
            header_len = struct.unpack('i', struct_head)[0]
            header_json = self.socket.recv(header_len).decode(encoding=self.__encoding)
            header_dc = json.loads(header_json)
            if header_dc['command'] == 'False':
                print('File does not exist!')
                return
            filesize = header_dc['filesize']
            filename = header_dc['filename']
            received_size = 0
            dot = '.'
            lt = '>'
            starting = time.perf_counter()
            md5 = hashlib.md5()
            print('Download Starting'.center(100, '='))
            with Open(DOWNLOADS_PATH + filename, 'wb', None) as fp:
                while received_size < filesize:
                    data = self.socket.recv(self.__buffer_size)
                    fp.write(data)
                    fp.flush()
                    received_size += len(data)
                    md5.update(data)
                    scale = received_size / filesize * 100
                    print('\r%%%.2f[%s%s]%.2fs' % (
                        scale,
                        int(scale) * lt,
                        (100 - int(scale)) * dot,
                        time.perf_counter() - starting
                    ), end='')
                print('\n', 'Download Ending'.center(100, '='), sep='')
                if self.compare_md5(header_dc['filemd5'], md5.hexdigest()):
                    print('MD5 verification successful!')
                    print('Please wait while opening the file for you'.center(100, '='))
                    os.system(f'start explorer {os.path.abspath(os.path.dirname(fp.name))}')
                    print('Done!'.center(100, '='))
                    return
                else:
                    print('MD5 verification unsuccessful!')
                    return
        else:
            print('Incorrect syntax, missing or too many parameters.')
            return

    def compare_md5(self, *args):
        """比较md5值"""
        if args[0] == args[1]:
            return True
        else:
            return False

    def put(self, args):
        """上传功能"""
        if args.__len__() == 2:
            self.socket.send(' '.join(args).encode(encoding=self.__encoding))
            recvs = self.socket.recv(5)
            if recvs == b'False':
                print('Please switch to home directory, then operate!')
                return
            self.cmd = args[0]
            self.filename = args[-1]
            self.file_path = os.path.abspath(UPLOADS_PATH + self.filename)
            if os.path.exists(self.file_path):
                self.filesize = os.path.getsize(self.file_path)
                print(self.filesize)
                self.filetype = os.path.splitext(self.file_path)[-1]
                header_bytes = self.__make_header()
                struct_header = struct.pack('i', len(header_bytes))
                self.socket.send(struct_header)
                self.socket.send(header_bytes)
                if self.socket.recv(5) == b'False':
                    print('The space is NOT enough!')
                    return

                # 上传开始
                readed_size = 0
                dot = '.'
                lt = '>'
                starting = time.perf_counter()
                print('Upload Starting'.center(100, '='))
                with Open(self.file_path, 'rb', None) as fp, \
                        Open(self.filestatus_path + '.bak', 'w', self.__encoding) as fp2:
                    self.filestatus[self.cur_user] = {
                        self.filename: {
                            'filepath': self.file_path,
                            'filesize': self.filesize,
                            'readed_size': 0}
                    }
                    try:
                        while readed_size < self.filesize:
                            data = fp.read(self.__buffer_size)
                            self.socket.send(data)
                            readed_size += len(data)
                            self.filestatus[self.cur_user][self.filename]['readed_size'] = readed_size
                            json.dump(self.filestatus, fp2)
                            fp2.flush()
                            fp2.truncate()
                            fp2.seek(0, 0)
                            scale = readed_size / self.filesize * 100
                            print('\r%%%.2f[%s%s]%.2fs' % (
                                scale,
                                int(scale) * lt,
                                (100 - int(scale)) * dot,
                                time.perf_counter() - starting
                            ), end='')
                        print()
                    except ConnectionResetError as e:
                        print(e)
                        print(e.__class__.__name__)
                    else:
                        self.filestatus[self.cur_user].pop(self.filename)
                        if not self.filestatus[self.cur_user]:
                            self.filestatus.pop(self.cur_user)
                            json.dump(self.filestatus, fp2)
                            fp2.flush()
                            fp2.truncate()
            else:
                print('File does not exist!')
                return
        else:
            print('Incorrect syntax, missing or too many parameters.')
            return

    def __make_header(self):
        """报头制作"""
        header = {
            'filename': self.filename,
            'filesize': self.filesize,
            'filetype': self.filetype,
            'filemd5': None,
            'command': self.cmd,
            'source': str(self.connected_address),
            'destination': str(self.socket.getpeername()),
        }
        if header.get('command') == 'put':
            readed_size = 0
            with Open(self.file_path, 'rb', None) as fp:
                md5 = hashlib.md5()
                while readed_size < self.filesize:
                    data = fp.read(self.__buffer_size)
                    md5.update(data)
                    readed_size += len(data)
                header['filemd5'] = md5.hexdigest()
        header_json = json.dumps(header)
        header_bytes = bytes(header_json, encoding=self.__encoding)
        return header_bytes

    def logout(self, *args):
        """断开连接"""
        self.__client_close()
        exit('Bye now!')

    def __client_close(self):
        """关闭客户端"""
        self.socket.close()
