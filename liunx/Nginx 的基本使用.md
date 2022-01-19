## Nginx 的基本使用

#### 基本使用

1. 正向代理

   正向代理：内网服务器主动去请求外网的服务的一种行为光看概念，可能有读者还是搞不明白：什么叫做“正向”，什么叫做“代理”，我们分别来理解一下这两个名词。

   正向：相同的或一致的方向

   代理：自己做不了的事情或者自己不打算做的事情，委托或依靠别人来完成。

   ​	借助解释，回归到nginx的概念，正向代理其实就是说客户端无法主动或者不打算完成主动去向某服务器发起请求，而是委托了nginx代理服务器去向服务器发起请求，并且获得处理结果，返回给客户端。

   举个栗子：广大社会主义接班人都知道，为了保护祖国的花朵不受外界的乌烟瘴气熏陶，国家对网络做了一些“优化”，正常情况下是不能外网的，但作为程序员的我们如果没有谷歌等搜索引擎的帮助，再销魂的代码也会因此失色，因此，网络上也曾出现过一些fan qiang技术和软件供有需要的人使用，如某VPN等，其实VPN的原理大体上也类似于一个正向代理，也就是需要访问外网的电脑，发起一个访问外网的请求，通过本机上的VPN去寻找一个可以访问国外网站的代理服务器，代理服务器向外国网站发起请求，然后把结果返回给本机。

   ```
   server { 
       #指定DNS服务器IP地址   
       resolver 114.114.114.114;    
       #指定代理端口     
       listen 8080;   
       location / { 
           #设定代理服务器的协议和地址（固定不变）     
           proxy_pass http://$http_host$request_uri;  
       }   
   }
   ```

   

2. 反向代理

   反向代理：reverse proxy，是指用代理服务器来接受客户端发来的请求，然后将请求转发给内网中的上游服务器，上游服务器处理完之后，把结果通过nginx返回给客户端。

   上面讲述了正向代理的原理，相信对于反向代理，就很好理解了吧。

   反向代理是对于来自外界的请求，先通过nginx统一接受，然后按需转发给内网中的服务器，并且把处理请求返回给外界客户端，此时代理服务器对外表现的就是一个web服务器，客户端根本不知道“上游服务器”的存在。

   举个栗子：一个服务器的80端口只有一个，而服务器中可能有多个项目，如果A项目是端口是8081，B项目是8082，C项目是8083，假设指向该服务器的域名为www.xxx.com，此时访问B项目是www.xxx.com:8082，以此类推其它项目的URL也是要加上一个端口号，这样就很不美观了，这时我们把80端口给nginx服务器，给每个项目分配一个独立的子域名，如A项目是a.xxx.com，并且在nginx中设置每个项目的转发配置，然后对所有项目的访问都由nginx服务器接受，然后根据配置转发给不同的服务器处理。

   ```
   server { 
       #监听端口 
       listen 80; 
       #服务器名称，也就是客户端访问的域名地址 
       server_name  a.xxx.com; 
       #nginx日志输出文件 
       access_log  logs/nginx.access.log  main; 
       #nginx错误日志输出文件 
       error_log  logs/nginx.error.log; 
       root   html; 
       index  index.html index.htm index.php; 
       location / { 
           #被代理服务器的地址 
           proxy_pass  http://localhost:8081; 
           #对发送给客户端的URL进行修改的操作 
           proxy_redirect     off; 
           proxy_set_header   Host             $host; 
           proxy_set_header   X-Real-IP        $remote_addr; 
           proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for; 
           proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504; 
           proxy_max_temp_file_size 0; 
      } 
   }
   ```

3. 透明代理

   透明代理：也叫做简单代理，意思客户端向服务端发起请求时，请求会先到达透明代理服务器，代理服务器再把请求转交给真实的源服务器处理，也就是是客户端根本不知道有代理服务器的存在。

   举个栗子：它的用法有点类似于拦截器，如某些制度严格的公司里的办公电脑，无论我们用电脑做了什么事情，安全部门都能拦截我们对外发送的任何东西，这是因为电脑在对外发送时，实际上先经过网络上的一个透明的服务器，经过它的处理之后，才接着往外网走，而我们在网上冲浪时，根本没有感知到有拦截器拦截我们的数据和信息。

   ​	有人说透明代理和反向代理有点像，都是由代理服务器先接受请求，再转发到源服务器。其实本质上是有区别的，透明代理是客户端感知不到代理服务器的存在，而反向代理是客户端感知只有一个代理服务器的存在，因此他们一个是隐藏了自己，一个是隐藏了源服务器。事实上，透明代理和正向代理才是相像的，都是由客户端主动发起请求，代理服务器处理;他们差异点在于：正向代理是代理服务器代替客户端请求，而透明代理是客户端在发起请求时，会先经过透明代理服务器，再达到服务端，在这过程中，客户端是感知不到这个代理服务器的。

4. 负载均衡

   负载均衡：将服务器接收到的请求按照规则分发的过程，称为负载均衡。负载均衡是反向代理的一种体现。

   可能绝大部分人接触到的web项目，刚开始时都是一台服务器就搞定了，但当网站访问量越来越大时，单台服务器就扛不住了，这时候需要增加服务器做成集群来分担流量压力，而在架设这些服务器时，nginx就充当了接受流量和分流的作用了，当请求到nginx服务器时，nginx就可以根据设置好的负载信息，把请求分配到不同的服务器，服务器处理完毕后，nginx获取处理结果返回给客户端，这样，用nginx的反向代理，即可实现了负载均衡。

   nginx实现负载均衡有几种模式：

   - 轮询：每个请求按时间顺序逐一分配到不同的后端服务器，也是nginx的默认模式。轮询模式的配置很简单，只需要把服务器列表加入到upstream模块中即可。

     下面的配置是指：负载中有三台服务器，当请求到达时，nginx按照时间顺序把请求分配给三台服务器处理。

     ```
     upstream serverList { 
         server 1.2.3.4; 
         server 1.2.3.5; 
         server 1.2.3.6; 
     } 
     ```

   - ip_hash：每个请求按访问IP的hash结果分配，同一个IP客户端固定访问一个后端服务器。可以保证来自同一ip的请求被打到固定的机器上，可以解决session问题。

     下面的配置是指：负载中有三台服务器，当请求到达时，nginx优先按照ip_hash的结果进行分配，也就是同一个IP的请求固定在某一台服务器上，其它则按时间顺序把请求分配给三台服务器处理。

     ```
     upstream serverList { 
         ip_hash 
         server 1.2.3.4; 
         server 1.2.3.5; 
         server 1.2.3.6; 
     }
     ```

   - url_hash：按访问url的hash结果来分配请求，相同的url固定转发到同一个后端服务器处理。

     ```
     upstream serverList { 
         server 1.2.3.4; 
         server 1.2.3.5; 
         server 1.2.3.6; 
         hash $request_uri;  
         hash_method crc32;  
     }
     ```

   - fair：按后端服务器的响应时间来分配请求，响应时间短的优先分配。

     ```
     upstream serverList { 
         server 1.2.3.4; 
         server 1.2.3.5; 
         server 1.2.3.6; 
         fair; 
     }
     ```

     而在每一种模式中，每一台服务器后面的可以携带的参数有：

     1. down: 当前服务器暂不参与负载
     2. weight: 权重，值越大，服务器的负载量越大。
     3. max_fails：允许请求失败的次数，默认为1。
     4. fail_timeout:max_fails次失败后暂停的时间。
     5. backup：备份机， 只有其它所有的非backup机器down或者忙时才会请求backup机器。

     如下面的配置是指：负载中有三台服务器，当请求到达时，nginx按时间顺序和权重把请求分配给三台服务器处理，例如有100个请求，有30%是服务器4处理，有50%的请求是服务器5处理，有20%的请求是服务器6处理。

     ```
     upstream serverList { 
         server 1.2.3.4 weight=30; 
         server 1.2.3.5 weight=50; 
        	server 1.2.3.6 weight=20; 
     } 
     ```

     如下面的配置是指：负载中有三台服务器，服务器4的失败超时时间为60s，服务器5暂不参与负载，服务器6只用作备份机。

     ```
     upstream serverList { 
         server 1.2.3.4 fail_timeout=60s; 
         server 1.2.3.5 down; 
         server 1.2.3.6 backup; 
     } 
     ```

     

#### Nginx 带注释的配置

###### Nginx 进程配置

​	除了可以使用 ulimit 命令对内核参数进行配置，nginx 也支持对自身使用内核资源进行配置。

​	nginx 默认使用一个 cpu 资源，即开启一个进程处理 web 请求，默认进程打开的最大连接数为 1024，这在生产上面是远远不够的。

​	配置如下：

```
#user
user nobody;
#pid file 
pid logs/nginx.pid;

#--------------------------- 进程---------------------------
#worker进程数，通常设置参考服务器 CPU 数量，auto为自动检测
#worker_process 1;
worker_processes auto;
#进程分配的 cpu
worker_cpu_affinity 000000001 00000010 00000100 00010000 00100000 01000000 10000000;
#worker进程打开最大文件描述符数，最好与 ulimit -u 保持一致
worker_rlimit_nofile 100000;
#全局错误日志
error_log  logs/error.log;

#events模块中包含nginx中所有处理连接的设置
events {
    #worker进程同时打开的最大连接数，理论上每台 nginx 服务器的最大连接数为 worker_process * worker_connections
    worker_connections 102400;
    #告诉nginx收到一个新链接通知后接受尽可能多的链接
    multi_accept on;
    #设置用于复用客户端线程的轮训方法，使用 epoll 的 I/O 模型
    use epoll;
}
```

###### Http 域配置

​	http 模块配置 nginx 处理 http 请求，是 nginx 的核心配置，也是优化 nginx 的关键，大多数 nginx 的功能都是围绕着 http 域来进行的。

```
http {
    #打开或关闭错误页面中的nginx版本号，生产环境中这些是需要关闭的，降低版本号带来的漏洞概率。
    server_tokens off;
    #server_tag off;
    #server_info off;
    #优化磁盘IO设置，指定nginx是否调用sendfile函数来输出文件，普通应用设为on，下载等磁盘IO高的应用，可设为off
    sendfile on;
    #设置nginx在一个数据包里发送所有头文件，而不是一个接一个的发送
    tcp_nopush on;
    #设置nginx不要缓存数据，而是一段一段的发送，当需要及时发送数据时，就应该给应用设置这个属性，这样发送一小块数据信息时就不能立即得到返回值
    tcp_nodelay on;

    #---------------------------日志---------------------------
    #设置nginx是否记录访问日志，关闭这个可以让读取磁盘IO操作更快
    access_log on;
    #设置nginx只记录严重错误
    #error_log logs/error.log crit;
    #定义日志格式，变量的意思另附博客详解，定义的日志格式可在 access_log logs/access.log main 中选取
    log_format main '$remote_addr - $remote_user [$time_local] '
                                 ' "$request"  $status  $body_bytes_sent  '
                                 ' "$http_referer"   "$http_user_agent" ';
    log_format porxy '$http_x_forwarded_for - $remote_user [$time_local] '
                                 ' "$request" $status $body_bytes_sent '
                                 ' "$http_referer" "$http_user_agent" '; 
    #设置日志文件缓存（默认是 off），max 设置缓存中最大文件描述符数量，inactive 存活时间，valid 检查频率，min_users 在 inactive 时间内最少使用次数，达到的日志文件描述符记入缓存
    open_log_file_cache max=1000 inactive=20s valid=1m min_users=2;  
    #记录重写日志
    rewrite_log off;        

     
    #给客户端分配keep-alive链接超时时间
    keepalive_timeout 30;

    #--------------------------- 限流 ---------------------------
    #limit_conn 和 limit_req 可添加到特定 Server 或 location 节点
    #1、控制 session
    #设置用户保存各种key的共享内存的参数，5m指的是5兆，$binary_remote_addr 根据远程客户端地址，$server_name 根据服务器名称
    limit_conn_zone $binary_remote_addr zone=addr:5m;
    #为给定的key设置最大的连接数，这里的key是addr，设定的值是100，根据上面的定义说允许每一个IP地址最多同时打开100个连接，如果共享内存定义的是 $server_name 那么这里是允许服务器最多同时打开100个连接。
    limit_conn addr 100;
    #限制流量
    limit_rate 100k;

    #2、漏桶方法
    #定义共享内存，与上面的一样，rate 定义请求次数（1 秒 20次）
    limit_req_zone $binary_remote_addr zone=addr:5m rate=20r/s;
    #burst=5 漏桶数为5，即如果第1、2、3、4秒请求为19，那么第5秒25次是可以允许的，nodelay 如果没有则严格使用平均速率限制请求数
    limit_raq zone=addr burst=5 nodelay;



    #include指在当前文件中包含另一个文件内容，一般 Server 域是放在另一个配置文件中的，主配置文件中包含下即可。
    include porxy.types;
    #设置文件使用默认的mine-type
    default_type text/html;
    #设置默认字符集
    charset UTF-8;

    #-----------------------------gzip 数据-----------------------------
    #设置nginx采用gzip压缩的形式发送数据，减少发送数据量，但会增加请求处理时间及CPU处理时间，需要权衡
    gzip on;
    #加vary给代理服务器使用，针对有的浏览器支持压缩，有个不支持，根据客户端的HTTP头来判断是否需要压缩
    gzip_vary on;
    #nginx在压缩资源之前，先查找是否有预先gzip处理过的资源
    #gzip_static on;
    #为指定的客户端禁用gzip功能
    gzip_disable "MSIE[1-6]\.";
    #允许或禁止压缩基于请求和相应的响应流，any代表压缩所有请求
    gzip_proxied any;
    #设置对数据启用压缩的最少字节数，如果请求小于10240字节则不压缩，会影响请求速度
    gzip_min_length 10240;
    #设置数据压缩等级，1-9之间，9最慢压缩比最大
    gzip_comp_level 2;
    #设置需要压缩的数据格式
    gzip_types text/plain text/css text/xml text/javascript  application/json application/x-javascript application/xml application/xml+rss; 

    #-----------------------------cache 文件-----------------------------
    #开发缓存的同时也指定了缓存文件的最大数量，20s如果文件没有请求则删除缓存
    open_file_cache max=100000 inactive=20s;
    #指多长时间检查一次缓存的有效信息
    open_file_cache_valid 60s;
    #文件缓存最小的访问次数，只有访问超过5次的才会被缓存
    open_file_cache_min_uses 5;
    #当搜索一个文件时是否缓存错误信息
    open_file_cache_errors on;

    #允许客户端请求的最大单文件字节数
    client_max_body_size 8m;
    #冲区代理缓冲用户端请求的最大字节数
    client_header_buffer_size 32k;

    #-----------------------------代理-----------------------------
    proxy_redirect off;
    #后端的Web服务器可以通过X-Forwarded-For获取用户真实IP，如果不配置那么web服务器只能获取到代理服务器的ip
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #nginx跟后端服务器连接超时时间(代理连接超时)
    proxy_connect_timeout 60;
    #连接成功后，后端服务器响应时间(代理接收超时)
    proxy_read_timeout 120;
    #后端服务器数据回传时间(代理发送超时)
    proxy_send_timeout 20;
    #设置代理服务器（nginx）保存用户头信息的缓冲区大小
    proxy_buffer_size 32k;
    #proxy_buffers缓冲区，网页平均在32k以下的设置
    proxy_buffers 4 128k;
    #高负荷下缓冲大小（proxy_buffers*2）
    proxy_busy_buffers_size 256k;
    #设定缓存文件夹大小，大于这个值，将从upstream服务器传
    proxy_temp_file_write_size 256k;
    #1G内存缓冲空间，3天不用删除，最大磁盘缓冲空间2G
    proxy_cache_path /home/cache levels=1:2 keys_zone=cache_one:1024m inactive=3d max_size=2g;


    #-----------------------------负载均衡-----------------------------
    #设定负载均衡服务器列表参考博客 nginx 负载均衡配置
    upstream myServer{
        #后端服务器访问规则
        #ip_hash;
        server 192.168.0.1:10001 weight=3 max_files=2 file_timeout=30;
        server 192.168.0.2:10002 weight=3 max_conns=10000;
        server 192.168.0.3:10003 weight=4;
        server 192.168.0.4:10004 backup;
    }
```

###### Server 域配置

​	虚拟主机配置模块，反向代理或负载均衡挂载的站点。

```
server {
        #虚拟主句监听的端口
        listen 80;
        #定义访问的域名
        server_name www.myserver.com;
        #设定本虚拟主机的访问日志，使用 main 格式
        access_log logs/myserver.com.access.log main;
    
        #可以在 Server 域中配置限流，具体通过什么方式限流是前面建立共享内存区时定义的，这里只是配置具体限流多少
        limit_raq zone=addr burst=5 nodelay;
        limit_conn addr 100;  
     
        #默认请求
        # 语法规则：location [=|~|~*|^~] /uri/ {...} 先匹配普通location，在匹配正则location
        # = 开头表示精确匹配
        # ^~ 开头表示uri以某个常规字符串开头，理解为匹配url路径即可，无需考虑编解码
        # ~ 开头表示区分大小写的正则匹配
        # ~* 开头表示不区分大小写的正则匹配
        # !~ 开头表示区分大小写的不匹配的正则
        # !~* 开头表示不区分大小写的不匹配的正则
        # / 通用匹配，任何请求都会被匹配到
        location / {
            #定义服务器的默认网站根目录位置
            root html;
            #定义首页索引文件的名称
            index index.html index.htm;
            #使用 myServer 负载均衡服务器组
            proxy_pass http://myServer;

            #当然也可以在 location 域中配置限流
            limit_raq zone=addr burst=5 nodelay;
            limit_conn addr 100; 
        }

        #定义错误提示页面
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root html;
        }
        #静态文件，nginx自己处理
        location ~ ^/(images|javascript|js|css|flash|media|static)/{
            root /var/www/virtual/htdocs;
            #过期时间1天
            expires 1d;
            #关闭媒体文件日志
            access_log off;
            log_not_found off;
        }
        #设定查看Nginx状态的地址
        location /NginxStatus {
            #!stub_status on; #无此关键字
            access_log off;
            auth_basic "NginxStatus";
            auth_basic_user_file conf/htpasswd;
        }
        #禁止访问的文件.htxxx
        location ~ /\.ht {
            deny all;
        }
    }
```

