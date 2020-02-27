"""
解析配置
    HOST: 主机IP
    PORT：端口
    DOWNLOADS_PATH：下载目录
    UPLOADS_PATH：上传目录
    FILESTATUS：断点续传文件数据
"""
import configparser

with open(file=r'./../conf/settings.ini', mode='rt', encoding='utf-8') as config_fp:
    config = configparser.ConfigParser()
    config.read_file(config_fp)
    HOST = eval(config.get('DEFAULT', 'HOST'))
    PORT = config.getint('DEFAULT', 'PORT')
    DOWNLOADS_PATH = config.get('downloads', 'DOWNLOADS_PATH')
    UPLOADS_PATH = config.get('uploads', 'UPLOADS_PATH')
    FILESTATUS = config.get('userinfo', 'FILESTATUS')
