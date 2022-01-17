## Docker 部署 Redis

1. 下载镜像

   ```shell
   docker pull redis
   ```

2. 创建 Redis 管理目录

   ```shell
   mkdir -p /opt/redis/data
   ```

3. 启动容器

   ```shell
   docker run -p 6379:6379 --name redis -v /opt/redis/redis.conf:/etc/redis/redis.conf -v /opt/redis/data:/data -d redis redis-server /etc/redis/redis.conf --appendonly yes
   ```

4. 查看 Redis 容器启动状态

   ```shell
   docker ps -a
   ```

   

