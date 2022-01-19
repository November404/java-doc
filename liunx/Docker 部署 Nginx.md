## Docker 部署 Nginx

1. 下载镜像并启动，检查运行状态

   ```shell
   docker pull nginx
   docker run --name nginx -p 80:80 -d nginx
   # 访问ip可以看到 “Welcome to nginx!”
   docker ps -a
   ```

   

2. 创建本地映射目录，然后将容器中的相应文件复制到刚创建的管理目录中

   ```shell
   mkdir -p /opt/nginx /opt/nginx/www /opt/nginx/conf /opt/nginx/logs
   docker cp nginx:/etc/nginx/nginx.conf /opt/nginx/
   docker cp nginx:/etc/nginx/conf.d /opt/nginx/conf/
   docker cp nginx:/usr/share/nginx/html/ /opt/nginx/www/
   docker cp nginx:/var/log/nginx/ /opt/nginx/logs/
   ```

   

3. 停止并移除容器

   ```shell
   docker stop nginx
   docker rm nginx
   ```

   

4. 重新启动容器并配置目录挂载

   ```shell
   docker run --name nginx -p 80:80 --restart=always -v /opt/nginx/nginx.conf:/etc/nginx/nginx.conf -v /opt/nginx/www/:/usr/share/nginx/html/ -v /opt/nginx/logs/:/var/log/nginx/ -v /opt/nginx/conf/:/etc/nginx/conf.d --privileged=true -d nginx
   ```

   

