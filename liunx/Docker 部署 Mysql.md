## Docker 部署 Mysql

1. 下载镜像(默认最新版本)

   ```shell
   docker pull mysql
   ```

2. 创建 Mysql 容器映射目录

   /opt/mysql/data : 挂载数据文件
   /opt/mysql/conf：挂载配置文件
   /opt/mysql/log : 挂载日志文件
   /opt/mysql/mysql-files : 挂载存储文件

   ```shell
   mkdir -p /opt/mysql/data /opt/mysql/conf /opt/mysql/log /opt/mysql/mysql-files
   ```

3. 创建映射配置文件

   ```shell
   vi /opt/mysql/conf/mysql.cnf
   ```

   ```ini
   [mysqld]
   user=root
   character-set-server=utf8
   default_authentication_plugin=mysql_native_password
   sql_mode=ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
   lower_case_table_names=1 #忽略表名大小写
    
   [client]
   default-character-set=utf8
   [mysql]
   default-character-set=utf8
   ```

4. 创建mysql实例

   -p 3306:3306：将容器的3306端口映射到主机的3306端口
   -e MYSQL_ROOT_PASSWORD=123456：初始化root用户的密码
   -d: 后台运行容器，并返回容器ID

   ```shell
   docker run -p 3306:3306 --restart=always --name mysql -v /opt/mysql/data:/var/lib/mysql -v /opt/mysql/mysql-files:/var/lib/mysql-files/ -v /opt/mysql/conf:/etc/mysql -v /opt/mysql/log:/var/log -e MYSQL_ROOT_PASSWORD=root -d mysql
   ```

5. 查看容器状态

   ```shell
   docker ps -a 
   ```

   

