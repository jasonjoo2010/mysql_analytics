# mysql_analytics
一个用于mysql连接内容监控的程序。

可以通过指定目标mysql服务器的ip与port来进行自动嗅探，并对mysql协议进行分析和输出。

可在mysql服务器端运行，亦可在有流量访问的客户机运行。
既可用于性能优化，因为log有毫秒级时间，亦可进行查询性能监控和调优。

## 使用范例
mysql_analytics eth0 192.168.123.3 3306

对去往指定的mysql实例的流量进行分析。

如果多个目标，可同时运行多个程序。
## CentOS 5.x & 7.x
yum install mysql_analytics


