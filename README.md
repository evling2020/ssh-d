# 级联 ssh 动态端口转发

## 工具获取
```bash
git clone https://github.com/evling2020/ssh-d.git
cd ssh-d
go get
GO111MODULE=off go build -ldflags "-s -w"
```

## 场景演示
**单个 ssh 隧道 - 密码认证**

```bash
# ssh 服务器地址: 10.70.6.2
# 用户名: test
# 密码: test@4321!
# 入口端口：1080
# 入口协议：目前仅支持sock5
./ssh-d -L=:1080 -F=ssh://test:test@4321\!@10.70.6.2:22
```

**单个 ssh 隧道 - 公私钥认证**

```bash
# ssh 服务器地址: 10.70.6.2
# 用户名: test
# 私钥文件: /home/jmeade/.ssh/id_rsa
# 入口端口：1080
# 入口协议：目前仅支持sock5
./ssh-d -L=:1080 -F=ssh://test@10.70.6.2:22/home/jmeade/.ssh/id_rsa
```

**综合例子**

先连接出网口的 socks5 代理，再途径两个 ssh 远程跳板，最后访问目标
```bash
# 暂不支持出口代理认证
./ssh-d -L=:1080 -F=socks5://10.70.6.2:1080 -F=ssh://test:test@4321\!@10.70.6.3:22 -F=ssh://test@10.70.6.4:22/home/jmeade/.ssh/id_rsa
```

查看中间的 ssh 服务器 10.70.6.3 网络连接情况，可以看出 10.70.6.2 连入它的 22 端口，它又接着连接 10.70.6.4 的 22 端口，串联成功。

```bash
root@07-001-tpl-debian-privileged:~# netstat -ltnpa | grep test
tcp        0      0 10.70.6.3:22            10.70.6.2:59546         ESTABLISHED 692/sshd: test [pri 
tcp        0      0 10.70.6.3:40362         10.70.6.4:22            ESTABLISHED 709/sshd: test
```
配置本地代理访问目标的一个 web 资产


![Screen Shot 2022-09-17 at 22.50.16.png](images/Screen%20Shot%202022-09-17%20at%2022.50.16.png)

出口代理连接日志



![Screen Shot 2022-09-17 at 22.50.37.png](images/Screen%20Shot%202022-09-17%20at%2022.50.37.png)



查看目标web资产日志远程接入地址正式链条末端的 10.70.6.4，验证完毕。
```bash
{ "@timestamp": "2022-09-17T22:40:23+08:00","@source": "10.68.15.2","hostname": "02-015-share-center","http_x_forwarded_for": "-", "remote_addr": "10.70.6.4", "remote_user": "-", "request_method": "GET","scheme": "https","domain": "ldap.evling.tech","http_referer": "-", "request_uri": "/", "args": "-","body_bytes_sent": "153", "status": " 403", "http_user_agent": "curl/7.85.0", "https": "on", "time_local": "17/Sep/2022:22:40:23 +0800", "request_time": "0.000", "upstream_response_time": "-","upstream_addr": "-","trace_id": "-", "span_id": "-" }
```

## 法律免责声明
该项目仅用于学习研究，若用于身份隐匿未经授权入侵属于非法行为，后果自负。切记，自用！！！

## 更新日志
- **2022.09.17:** 首次创建项目

## 易雾山庄

该项目是易雾山庄-家庭基建的一部分，[**易雾山庄**](https://www.evling.tech)记录了家庭网络基础建设的种种实践，可以帮助更多有需要的人减少折腾。希望通过这个平台构建一只家庭基建小社群，共同优化我们的生活体验，增强个人数据安全保护意识，同时我们还要考虑环保节能问题，实实在在帮大家伙组建属于自己的家庭网络。欢迎关注微信公号《易雾山庄》，订阅易雾君的独家折腾！！！
