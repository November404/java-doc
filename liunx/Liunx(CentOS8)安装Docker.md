## Liunx(CentOS8)安装Docker

1. 删除 Podman (CentOS 8 中安装 docker 和 Podman 冲突)

   ```shell
   # 查看是否安装 Podman
   rpm -q podman
   # 删除Podman
   dnf remove podman
   ```

2. 重装 Docker

   ```shell
   sudo yum install -y yum-utils  device-mapper-persistent-data  lvm2
    
   sudo yum-config-manager  --add-repo   https://download.docker.com/linux/centos/docker-ce.repo
    
   sudo yum install docker-ce docker-ce-cli containerd.io
    
   sudo yum install docker-ce docker-ce-cli
   ```

3. *添加镜像仓(可选)

   ```json
   {
   
   "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn"]
   
   }
   ```

4. 启动 Docker

   ```shell
   sudo systemctl start docker
   ```

5. 查看版本

   ```shell
   docker -v
   ```

6. 开机自启

   ```shell
   sudo systemctl enable docker
   ```

   

