# Log4jScaner
一款关与 Log4j 相关的 CVE 扫描器，旨在帮助渗透测试人员对给定的目标执行测试。 

Usage：

  -h, --help            show this help message and exit 帮助菜单
  
  
  -u URL, --url URL     The target url                  目标地址
  
  
  -l USEDLIST, --list USEDLIST                          批量检测
                        
  -p PROXY, --proxy PROXY                               使用代理
  
                
  --ldap-addr CUSTOM_DNS_CALLBACK_ADDR                  DNSlog监测平台
  
                      
  --request-type get，post，all                          请求数据类型(all为全部）
                        
                        
用法如图
![图片](https://user-images.githubusercontent.com/83112602/182009189-a46209d3-11bb-41c4-9e9c-6fea1204082f.png)
如何判断成功
去DNSlog平台查看有无通讯流量
![图片](https://user-images.githubusercontent.com/83112602/182009221-6f17227a-aa08-4c55-bd73-0b3a53bd26d1.png)
