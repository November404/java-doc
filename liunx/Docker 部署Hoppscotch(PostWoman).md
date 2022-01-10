## Docker 部署Hoppscotch(PostWoman)

1. 拉取postwoman镜像容器

   ```shell
   docker pull liyasthomas/postwoman
   ```

2. 运行docker容器

   ```shell
   docker run -p 3000:3000 --restart=always liyasthomas/postwoman:latest
   ```

3. *可能会出现跨域请求问题

   Chrome 下载 Hoppscotch 插件并配置 http://localhost:3000 来解决。

