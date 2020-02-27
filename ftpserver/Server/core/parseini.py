"""
配置文件解析
    HOST: 主机地址
    PORT：端口
    SHARES_PATH：Server端共享目录路径
    HOME_PATH：Server端每个用户的家目录起始路径
    ACCOUNT：用户账号密码路径
    FILESTATUS：断点续传文件路径
"""
import configparser

with open(file=r'./../conf/settings.ini', mode='rt', encoding='utf-8') as config_fp:
    config = configparser.ConfigParser()
    config.read_file(config_fp)
    HOST = eval(config.get('DEFAULT', 'HOST'))
    PORT = config.getint('DEFAULT', 'PORT')
    CONCURRENCY = config.getint('DEFAULT', 'CONCURRENCY')
    INIPATH = config.get('DEFAULT', 'INIPATH')
    SHARES_PATH = config.get('shares', 'SHARES_PATH')
    HOME_PATH = config.get('home', 'HOME_PATH')
    ACCOUNT = config.get('userinfo', 'ACCOUNT')
    FILESTATUS = config.get('userinfo', 'FILESTATUS')
