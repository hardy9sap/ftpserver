"""FTP Server端

"""
from .parseini import CONCURRENCY
from .parseini import SHARES_PATH
from .parseini import FILESTATUS
from .parseini import HOME_PATH
from .parseini import ACCOUNT
from .parseini import INIPATH
# from threading import Thread
import configparser
import subprocess
import contextlib
import traceback
import threading
import hashlib
import socket
import struct
import queue
import hmac
import json
import sys
import os

StopEvent = object()


def callback(status, result):
    pass


class ThreadPool(object):
    """queue模拟线程池"""

    def __init__(self, max_num):
        self.q = queue.Queue()  # 最多创建的线程数（线程池最大容量）
        self.max_num = max_num

        self.terminal = False  # 如果为True 终止所有线程，不在获取新任务
        self.generate_list = []  # 真实创建的线程列表
        self.free_list = []  # 空闲线程数量

    def submit(self, func, args, callback=None):
        """
        线程池执行一个任务
        :param func: 任务函数
        :param args: 任务函数所需参数
        :param callback: 任务执行失败或成功后执行的回调函数，回调函数有两个参数
                         1、任务函数执行状态；
                         2、任务函数返回值（默认为None，即：不执行回调函数）
        :return: 如果线程池已经终止，则返回True否则None
        """

        if len(self.free_list) == 0 and len(self.generate_list) < self.max_num:
            self.generate_thread()  # 创建线程
        w = (func, args, callback)  # 把参数封装成元祖
        self.q.put(w)  # 添加到任务队列

    def generate_thread(self):
        """创建一个线程 """
        t = threading.Thread(target=self.call)
        t.start()

    def call(self):
        """循环去获取任务函数并执行任务函数 """
        current_thread = threading.currentThread  # 获取当前线程
        self.generate_list.append(current_thread)  # 添加到已经创建的线程里

        event = self.q.get()  # 取任务并执行
        while event != StopEvent:  # 是元组=》是任务；如果不为停止信号  执行任务

            func, arguments, callback = event  # 解开任务包； 分别取出值
            try:
                result = func(*arguments)  # 运行函数，把结果赋值给result
                status = True  # 运行结果是否正常
            except Exception as e:
                status = False  # 表示运行不正常
                result = e  # 结果为错误信息

            if callback is not None:  # 是否存在回调函数
                try:
                    callback(status, result)  # 执行回调函数
                except Exception as e:
                    pass

            if self.terminal:  # 默认为False，如果调用terminal方法
                event = StopEvent  # 等于全局变量，表示停止信号
            else:
                with self.worker_state(self.free_list, current_thread):
                    event = self.q.get()

        else:
            self.generate_list.remove(current_thread)  # 如果收到终止信号，就从已经创建的线程列表中删除

    def close(self):  # 终止线程
        num = len(self.generate_list)  # 获取总共创建的线程数
        while num:
            self.q.put(StopEvent)  # 添加停止信号，有多少线程添加多少表示终止的信号
            num -= 1

    def terminate(self):  # 终止线程（清空队列）

        self.terminal = True  # 把默认的False更改成True

        while self.generate_list:  # 如果有已经创建线程存活
            self.q.put(StopEvent)  # 有几个线程就发几个终止信号
        self.q.empty()  # 清空队列

    @contextlib.contextmanager
    def worker_state(self, state_list, worker_thread):
        state_list.append(worker_thread)
        try:
            yield
        finally:
            state_list.remove(worker_thread)


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
        """文件管理协议语句结束后，做系统资源回收，并且如果发生异常，程序照常执行"""
        self.fp.flush()
        self.fp.close()
        return True


class MyFTPServer(object):
    """FTPServer类

    Attributes:
        :param __protocol_type: socket协议类型
        :param __address_family: socket地址簇
        :param __allow_reure_addr: 是否能重用端口
        :param __link_quue_size: 允许的最大连接数
        :param __buffer_size: 默认读写字节数
        :param __encoding: 默认编码/解码
        :param func_dc: 功能映射字典
    """
    __protocol_type = socket.SOCK_STREAM

    __address_famliy = socket.AF_INET

    __allow_reuse_addr = True

    __link_queue_size = 5

    __buffer_size = 1024

    __encoding = sys.getdefaultencoding()

    __CONCURRENCY = CONCURRENCY

    func_dc = {
        'setcon': 'setconcurrency',
        'setquota': 'setquota',
        'exit': 'logout',
        'cd': 'change_dir',
        'ls': 'list_dir',
        'get': 'get',
        'put': 'put'
    }

    def __init__(self, server_address, bind_activate=True):
        """MyFTPServer实例对象初始化"""
        self.server_address = server_address
        self.socket = socket.socket(family=MyFTPServer.__address_famliy,
                                    type=MyFTPServer.__protocol_type)
        self.thread_pool = ThreadPool(os.cpu_count() * 5)  # ThreadingPoolExecutor默认为 (os.cpu_count() or 1) * 5
        self.num_of_client = 0
        self.cur_path = None
        self.cmd = None
        self.filename = None
        self.file_path = None
        self.filesize = None
        self.filetype = None

        if bind_activate:
            self.__server_bind()
            self.__server_activate()
        else:
            self.__server_close()

    def __server_bind(self):
        """绑定IP和端口，以及端口重用"""
        if MyFTPServer.__allow_reuse_addr:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    def __server_activate(self):
        """TCP连接监听"""
        self.socket.listen(self.__link_queue_size)

    def __get_request(self):
        """TCP三次握手建立全双工通道"""
        conn, addr = self.socket.accept()
        return conn, addr

    def server_interact(self, conn, addr):
        """socket通讯"""
        try:
            status = self.__check_client(conn=conn, addr=addr)
            if not status:
                self.__request_close(conn=conn, addr=addr)

            # 验证用户身份
            while not self.__check_identity(account=self.account_dc, conn=conn, addr=addr):
                pass

            # 检测get断点续传部分
            self.__check_get_bkpt_file(conn=conn, addr=addr)

            # 检查put断点续传部分
            self.__check_put_bkpt_file(conn=conn, addr=addr)

            # 交互开始
            while 1:
                try:
                    cmds = conn.recv(self.__buffer_size).decode(encoding=self.__encoding)
                    if not cmds:
                        self.__request_close(conn=conn)
                        break
                    cmds_ls = cmds.split()
                    cmd = self.func_dc.get(cmds_ls[0])
                    if cmd is None:
                        continue
                    if hasattr(self, cmd):
                        func = getattr(self, cmd)
                        func(cmds=cmds_ls, conn=conn, addr=addr)
                except Exception as e:
                    print(e)
                    print(e.__class__.__name__)
                    self.__request_close(conn=conn, addr=addr)
                    break
        except Exception as e:
            print(e)
            print(e.__class__.__name__)
            print(traceback.print_tb(e.__traceback__))

    def server_run(self):
        """请求、验证客户端、加载数据、验证身份、上传、下载、切换、查看、配额等功能分发器"""
        # 加载用户数据结构
        self.__load_userinfo()

        # 加载get断点续传文件
        self.__load_get_bkpt_file()

        while 1:
            conn, addr = self.__get_request()
            print(f'from: <{addr}>')
            if self.num_of_client >= MyFTPServer.__CONCURRENCY:  # 判断客户端连接数
                conn.send(b'False')
                continue
            else:
                conn.send(b'True')
            # Thread(
            #     group=None,
            #     target=self.server_interact,
            #     args=(conn, addr),
            #     kwargs={},
            #     name=f'{addr} - Thread'
            # ).start()
            self.thread_pool.submit(
                self.server_interact,
                (conn, addr),
                callback=callback
            )
            self.num_of_client += 1

    def __check_client(self, *args, **kwargs):
        """验证客户端"""
        conn = kwargs.get('conn')
        # addr = args[1]
        secret_key = 'luffycity'
        encrypting_bytes = os.urandom(32)
        server_crypt = hmac.digest(bytes(secret_key, self.__encoding), encrypting_bytes, 'md5')
        conn.send(encrypting_bytes)
        client_crypt = conn.recv(self.__buffer_size)
        if hmac.compare_digest(server_crypt, client_crypt):
            conn.send(b'True')
            return True
        else:
            conn.send(b'False')
            return False

    def __load_userinfo(self):
        """加载用户账号和密码"""
        with Open(ACCOUNT, 'rt', self.__encoding) as fp:
            account = json.load(fp)
            self.account_dc = account
            self.filestatus_path = FILESTATUS

    def __check_identity(self, *args, **kwargs):
        """验证用户身份"""
        account_dc = kwargs.get('account')
        conn = kwargs.get('conn')
        identity_struct = conn.recv(4)
        identity_len = struct.unpack('i', identity_struct)[0]
        identity_json = conn.recv(identity_len).decode(encoding=self.__encoding)
        identity_dc = json.loads(identity_json)
        username = identity_dc['account']
        if username in account_dc:
            if account_dc[username]['password'] == identity_dc['identity_code']:
                conn.send(b'True')
                MyFTPServer.root_dir = HOME_PATH
                MyFTPServer.shares_dir = SHARES_PATH
                self.cur_user = username
                self.home_path = os.path.abspath(MyFTPServer.root_dir + self.account_dc[self.cur_user]['home_dir'])
                self.cur_path = self.home_path
                self.forbiden_path = []
                for elm in self.account_dc:
                    if elm != self.cur_user:
                        path = os.path.abspath(os.path.join(MyFTPServer.root_dir, self.account_dc[elm].get('home_dir')))
                        self.forbiden_path.append(path)
                return True
            else:
                conn.send(b'False')
                return False
        else:
            conn.send(b'False')
            return False

    def __load_get_bkpt_file(self):
        """加载get功能断点数据"""
        with Open(self.filestatus_path, 'r', self.__encoding) as fp:
            self.filestatus = json.load(fp)

    def __check_get_bkpt_file(self, *args, **kwargs):
        """进行get功能断点续传"""
        conn = kwargs.get('conn')
        if not self.filestatus or self.cur_user not in self.filestatus:
            conn.send(b'False')
            return
        deleting_ls = []
        for elm in self.filestatus[self.cur_user]:
            conn.send(elm.encode(encoding=self.__encoding))
            code = conn.recv(self.__buffer_size)
            if code == b'y':
                filesize = self.filestatus[self.cur_user][elm]['filesize']
                filepath = self.filestatus[self.cur_user][elm]['filepath']
                header = {
                    'filename': elm,
                    'filesize': filesize,
                    'response': code.decode(encoding=self.__encoding)
                }
                header_bytes = json.dumps(header).encode(encoding=self.__encoding)
                struct_head = struct.pack('i', len(header_bytes))
                conn.send(struct_head)
                conn.send(header_bytes)
                struct_head = conn.recv(4)
                cur_pos = int(conn.recv(struct.unpack('i', struct_head)[0]).decode(encoding=self.__encoding))
                left_size = filesize - cur_pos
                with Open(filepath, 'rb', None) as fp:
                    fp.seek(cur_pos)
                    left_readed = 0
                    while left_readed < left_size:
                        data = fp.read(self.__buffer_size)
                        conn.send(data)
                        left_readed += len(data)
                conn.recv(2)
            deleting_ls.append(elm)
        with Open(self.filestatus_path, 'r+', self.__encoding) as fp:
            for elm in deleting_ls:
                self.filestatus[self.cur_user].pop(elm)
            if not self.filestatus[self.cur_user]:
                self.filestatus.pop(self.cur_user)
            json.dump(self.filestatus, fp)
            fp.truncate()
        conn.send(b'exit')
        return

    def __check_put_bkpt_file(self, *args, **kwargs):
        """执行put功能断点续传"""
        conn = kwargs.get('conn')
        while 1:
            code = conn.recv(1024)
            if code == b'y':
                struct_head = conn.recv(4)
                header_len = struct.unpack('i', struct_head)[0]
                header_dc = json.loads(conn.recv(header_len).decode(encoding=self.__encoding))
                cur_file_size = os.path.getsize(os.path.abspath(os.path.join(self.home_path, header_dc['filename'])))
                struct_head = struct.pack('i', str(cur_file_size).encode(encoding=self.__encoding).__len__())
                conn.send(struct_head)
                conn.send(str(cur_file_size).encode(encoding=self.__encoding))
                readed_size = cur_file_size
                filesize = header_dc['filesize']
                filepath = os.path.abspath(os.path.join(self.home_path, header_dc['filename']))
                with Open(filepath, 'ab', None) as fp:
                    while readed_size < filesize:
                        recvs = conn.recv(self.__buffer_size)
                        fp.write(recvs)
                        readed_size += len(recvs)
                if os.path.getsize(fp.name) == filesize:
                    conn.send(b'True')
                    os.system(f'start explorer {os.path.abspath(self.home_path)}')
                else:
                    conn.send(b'False')
                conn.send(b'OK')
            elif code == b'exit':
                return
            elif code == b'False':
                return
            else:
                filename = conn.recv(self.__buffer_size).decode(encoding=self.__encoding)
                os.remove(os.path.abspath(os.path.join(self.home_path, filename)))
                conn.send(b'True')

    def setquota(self, *args, **kwargs):
        """配额功能"""
        conn = kwargs.get('conn')
        cmds_ls = kwargs.get('cmds')
        amount = cmds_ls[-1][:-1]
        unit = cmds_ls[-1][-1]
        count = 0
        if unit in ('K', 'M', 'G'):
            count += 1
        if unit in ('M', 'G'):
            count += 1
        if unit in ('G',):
            count += 1
        size = int(amount) * pow(1024, count)
        self.account_dc[self.cur_user]['quota'] = size
        with Open(ACCOUNT + '.bak.json', 'w', self.__encoding) as fp:
            json.dump(self.account_dc, fp)
        os.remove(ACCOUNT)
        os.replace(fp.name, ACCOUNT)
        conn.send(b'True')
        return

    def setconcurrency(self, *args, **kwargs):
        """设置并发数"""
        conn = kwargs.get('conn')
        cmds_ls = kwargs.get('cmds')
        amount = cmds_ls[-1]
        config = configparser.ConfigParser()
        with Open(INIPATH, 'r+', self.__encoding) as config_fp:
            config.read_file(config_fp)
            config.set('DEFAULT', 'CONCURRENCY', amount)
            config_fp.seek(0, 0)
            config.write(config_fp)
        MyFTPServer.__CONCURRENCY = int(amount)
        conn.send(b'True')
        return

    def change_dir(self, *args, **kwargs):
        """切换目录"""
        args = kwargs.get('cmds')
        conn = kwargs.get('conn')
        if args.__len__() == 1:
            self.cur_path = self.home_path
            path = os.path.abspath(self.cur_path)
            conn.send(bytes(path, encoding=self.__encoding))
            return
        elif args.__len__() == 2:
            if args[-1] is '~':
                self.cur_path = self.home_path
                path = os.path.abspath(self.cur_path)
                conn.send(bytes(path, encoding=self.__encoding))
                return
            elif args[-1] is '.':
                path = os.path.abspath(self.cur_path)
                conn.send(bytes(path, encoding=self.__encoding))
                return
            elif args[-1] is '..':
                self.cur_path = os.path.dirname(self.cur_path)
                path = os.path.abspath(self.cur_path)
                conn.send(bytes(path, encoding=self.__encoding))
                return
            else:
                path = os.path.abspath(os.path.join(self.cur_path, args[-1]))
                if os.path.exists(path):
                    if path not in self.forbiden_path:
                        self.cur_path = path
                        conn.send(bytes(path, encoding=self.__encoding))
                    else:
                        conn.send(b'False')
                else:
                    conn.send(b'False')
        else:
            conn.send(b'False')
            return

    def list_dir(self, *args, **kwargs):
        """查看目录下的所有文件"""
        args = kwargs.get('cmds')
        conn = kwargs.get('conn')
        if args.__len__() == 1:
            result = subprocess.getoutput(f'dir {self.cur_path}').encode(encoding=self.__encoding)
            struct_bytes = struct.pack('i', len(result))
            conn.send(struct_bytes)
            conn.send(result)
            return
        elif args.__len__() == 2:
            if args[-1] is '.':
                result = subprocess.getoutput(f'dir {self.cur_path}').encode(encoding=self.__encoding)
                struct_bytes = struct.pack('i', len(result))
                conn.send(struct_bytes)
                conn.send(result)
                return
            elif args[-1] is '..':
                self.cur_path = os.path.dirname(self.cur_path)
                path = os.path.abspath(self.cur_path)
                result = subprocess.getoutput(f'dir {path}').encode(encoding=self.__encoding)
                struct_bytes = struct.pack('i', len(result))
                conn.send(struct_bytes)
                conn.send(result)
                return
            else:
                path = os.path.abspath(os.path.join(self.cur_path, args[-1]))
                if os.path.exists(path):
                    result = subprocess.getoutput(f'dir {path}').encode(encoding=self.__encoding)
                    struct_bytes = struct.pack('i', len(result))
                    conn.send(struct_bytes)
                    conn.send(result)
                else:
                    conn.send(b'False')
        else:
            conn.send(b'False')
            return

    def get(self, *args, **kwargs):
        """文件下载"""
        args = kwargs.get('cmds')
        conn = kwargs.get('conn')
        self.cmd = args[0]
        self.filename = args[-1]
        self.file_path = os.path.abspath(SHARES_PATH + self.filename)
        if os.path.exists(self.file_path):
            self.filesize = os.path.getsize(self.file_path)
            self.filetype = os.path.splitext(self.file_path)[-1]
            header_bytes = self.__make_header(conn=conn)
            struct_header = struct.pack('i', len(header_bytes))
            conn.send(struct_header)
            conn.send(header_bytes)
            # 传输开始
            readed_size = 0
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
                        conn.send(data)
                        readed_size += len(data)
                        self.filestatus[self.cur_user][self.filename]['readed_size'] = readed_size
                        json.dump(self.filestatus, fp2)
                        fp2.flush()
                        fp2.truncate()
                        fp2.seek(0, 0)
                except ConnectionResetError as e:
                    print(e)
                    print(e.__class__.__name__)
                    pass
                else:
                    self.filestatus[self.cur_user].pop(self.filename)
                    if not self.filestatus[self.cur_user]:
                        self.filestatus.pop(self.cur_user)
                        json.dump(self.filestatus, fp2)
                        fp2.flush()
                        fp2.truncate()
            os.replace(fp2.name, self.filestatus_path)
        else:
            self.cmd = 'False'
            header_bytes = self.__make_header(conn=conn)
            struct_header = struct.pack('i', len(header_bytes))
            conn.send(struct_header)
            conn.send(header_bytes)
            return

    def put(self, *args, **kwargs):
        """上传功能"""
        conn = kwargs.get('conn')
        if self.cur_path != self.home_path:
            conn.send(b'False')
            return
        conn.send(b'True')
        struct_head = conn.recv(4)
        header_len = struct.unpack('i', struct_head)[0]
        header_json = conn.recv(header_len).decode(encoding=self.__encoding)
        header_dc = json.loads(header_json)

        # 统计文件大小，是否超过额度
        item_ls = os.listdir(self.home_path)
        total_size = 0
        for elm in item_ls:
            total_size += os.path.getsize(os.path.join(self.home_path, elm))
        if (total_size + header_dc['filesize']) > self.account_dc[self.cur_user]['quota']:
            conn.send(b'False')
            return
        conn.send(b'True')

        # 传输开始
        received_size = 0
        filesize = header_dc['filesize']
        filename = header_dc['filename']
        md5 = hashlib.md5()
        filepath = os.path.abspath(os.path.join(self.home_path, filename))
        with Open(filepath, 'wb', None) as fp:
            while received_size < filesize:
                data = conn.recv(self.__buffer_size)
                fp.write(data)
                fp.flush()
                received_size += len(data)
                md5.update(data)
            if self.compare_md5(header_dc['filemd5'], md5.hexdigest()):
                print('MD5 verification successful!')
                print('Please wait while opening the file for you'.center(100, '='))
                os.system(f'start explorer {os.path.abspath(os.path.dirname(fp.name))}')
                print('Done!'.center(100, '='))
                return
            else:
                print('MD5 verification unsuccessful!')
                return

    def __make_header(self, conn):
        """制作报头"""
        header = {
            'filename': self.filename,
            'filesize': self.filesize,
            'filetype': self.filetype,
            'filemd5': None,
            'command': self.cmd,
            'source': str(self.server_address),
            'destination': str(conn.getpeername()),
        }
        if header.get('command') == 'get':
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

    @staticmethod
    def compare_md5(*args, **kwargs):
        """比较md5值"""
        if args[0] == args[1]:
            return True
        else:
            return False

    def logout(self, *args, **kwargs):
        """断开连接"""
        self.__request_close(*args, **kwargs)

    @staticmethod
    def __request_close(*args, **kwargs):
        """断开连接实体"""
        kwargs['conn'].close()

    def __server_close(self):
        """关闭服务器"""
        self.socket.close()
