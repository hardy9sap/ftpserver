                     <center>FTP项目使用说明</center>

1) 开发环境
2) 功能实现
3) 启动方式
4) 登录用户信息
5) 程序运行效果
6) 常见问题



一、开发环境
    Windows 10(64位)
    Python(3.7.2)
    JetBrains PyCharm(2018.2.2 x64)
    
二、功能实现
特别说明：
    因上传时作业压缩包不能超过5M，只有小量数据：
        get pic.jpg
        put linux.pdf

1. 客户端的一致性校验

2. 允许多用户登录

3. 用户加密认证
    测试用户信息：
        username        password
        
        alex            alex3714
        egon            egon123
        peiqi           peiqi123
        taibai          taibai123
        
4. 每个用户都有自己的家目录，且只能访问自己的家目录
    
5. 对用户进行磁盘分配，每个用户的可用空间可以自己设置
    使用语法：
        setquota 100M 
        主命令：setquota
        参数：正整数 + 单位（K / M / G）大写
        
6. 允许用户在ftp server上随意切换目录
    使用语法：
        1. cd  直接切换到家目录
        2. cd ~  直接切换到家目录
        3. cd .   切换到当前目录
        4. cd ..   切换到上一级目录
        5. cd [directory]  切换到当前目录下的指定目录
        
7. 允许用户查看自己家目录下的文件
    使用语法：
        1. ls   查看当前目录下所有的文件
        2. ls [directory]  查看当前目录下的目录中的文件
        
8. 允许用户上传和下载，保护文件的一致性（MD5）
    使用语法：
        下载
        1. get [file]
            get netease.exe
            get linux.pdf
            get pic.jpg
            
        上传：使用前提，必须切回家目录
        1. put [file]
            put pdf.zip
            put pycharm.exe
            
9. 文件上传、下载过程中显示进度条
    形式：
        百分比 [>>>>>>..................] 时间s
    
10. 文件支持断点续传
    （上传的断点续传请使用cmd方式测试）
    根据提示：
        y：继续下载/下载该文件
        
        n以及其他字符：删除该文件

11. 支持多并发

12. 使用queue模拟线程池

13. 允许用户配置最大并发数
    语法：
        setcon 10

三、启动方式
1. PyCharm中
    1. 首先启动服务端：右击ftpserver/Server/bin/start.py ----> run
    2. 再启动客户端：右击ftpserver/Client/bin/start.py ----> run
    
2. CMD中
    python2:
        1. 首先启动服务端：python start.py
        2. 再启动客户端：pythhon start.py 
        
    python3:
        1. 首先启动服务端：python3 start.py
        2. 再启动客户端：pythhon3 start.py 
        
四、用户登录信息

五、程序运行效果

六、常见问题