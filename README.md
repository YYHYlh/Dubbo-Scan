# Dubbo-Scan

一款Apache Dubbo漏洞检测工具。包含了信息收集、参数爆破等功能，利用获取到的信息对Dubbo的Provider和Consumer进行漏洞利用检测。

## 免责申明

本工具仅用于个人学习行为，如您需要测试本工具的可用性，请自行搭建靶机环境。由于漏洞检测的过程中会存在修改目标服务的字节码、修改注册中心配置等有损行为，因此请勿在生产环境中进行测试。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## 项目背景
Dubbo在反序列化前需要对用户传入的服务和参数类型进行校验，导致很多Dubbo的漏洞没有通用的检测POC。由于漏洞均是反序列化漏洞，所以在发现漏洞->RCE这一步上存在着一些不便。因此通过编写本项目，学习Dubbo漏洞的信息收集和利用方式，覆盖完整利用过程。

## 项目功能

### 1.服务发现

- [x] Dubbo - Provider
- [x] Dubbo - QOS
- [x] Zookeeper
- [ ] Nacos
- [ ] Redis

### 2.信息收集

在上述发现的服务中搜集Dubbo信息，包括如下信息，利用如下信息从而后续对目标Dubbo服务进行漏洞探测。

|     IP     |端口|版本|服务名|服务参数|服务版本|
|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
|   dubbo    |√|√|√|√|×|√|
| zookeeper  |√|√|√|√|√|√|
| dubbo-qos  |√|√|√|√|×|×|

### 3.漏洞扫描

本项目只检测每种检测方式下，影响版本最新的漏洞。可以认为
#### Dubbo provider

1. 已知服务名、方法名以及参数类型或目标为3.x的Dubbo

- 利用漏洞：CVE-2023-2363
- 支持协议：hessian
- 支持版本：
  - Dubbo 2.7.x < 2.7.22
  - Dubbo 3.0.x < 3.0.14
  - Dubbo 3.1.x < 3.1.6
- 达到效果：
  - 修改目标的检测类代码，从而在发起新的泛化调用时，执行用户指定的任意命令并回显

2. 未知服务方法名

- 利用漏洞：CVE-2021-43297
- 支持协议：hessian
- 支持版本：
  - Dubbo 2.7.x < 2.7.14
- 达到效果:
  - 注入一个原生Netty HTTP内存马，默认为/dubbo.jar，该内存马支持蚁剑的Linux_RAW模式连接

#### Dubbo Consumer

- 利用漏洞：CVE-2021-36162
- 支持版本：
  - Dubbo 2.7.x < 2.7.13
  - Dubbo 3.0.x < 3.0.2
- 利用方式:
  通过往Zookeeper写入恶意的数据，从而使使用该Zookeeper的Consumer向指定的地址发起请求
- 达到效果:
  向指定的URL反弹shell


## 使用方法

1. 下载Releases版本代码，解压缩。
2. 完成target.txt和config.yaml的配置。
3. 执行jar -jar dubbo-scanner.jar。


  本项目不提供命令行参数，所有的配置通过修改同目录下的config.yaml和target.txt进行配置
  target.txt为需要检测的目标地址，每一行为一个IP:PORT，如果不提供Port，则会检测config.yaml中的usuallyPorts。
  
  config.yaml如下
  ```yaml
  timeout: 5 # 网络连接过程的超时时间
  usuallyPorts: # 默认检测端口
    - 2181
    - 22222
    - 20880
  methodParametersGuess: true # 是否开启参数爆破
  methodParametersGuessMaxLength: 3 # 参数列表最大长度
  methodParametersGuessList: # 猜测类型
    - java.lang.Object
    - java.lang.Integer
    - java.util.Map
    - java.lang.String
  reverse: # 攻击Consumer的回连模块，注释掉该模块，就不会调用对Consumer的漏洞检测
    shellIp: 127.0.0.1 # 回连shell地址，可以为任意的IP地址
    shellPort: 9999 # 回连端口
    fileIp: 127.0.0.1 # 回连文件服务IP，必须为本项目的IP
    filePort: 8888 # 回连文件服务端口
  #zookeeper: # zookeepr认证
  #  username: admin
  #  password: admin
  #  scheme: auth
  ```

