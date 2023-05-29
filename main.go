package main

import (
	"crypto/tls"
	"fmt"
	"github.com/zhaoyumi/jolokia_Realm_JNDI_RCE_Check/poc"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
)

//判断版本
func getStatusCode(url string) int {
	// 忽略证书验证错误
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error sending request to %s: %s\n", url, err)
		return -1
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func checkVul(url string) int {
	version1 := poc.RemoveTrailingSlash(url) + "/env"
	version2 := poc.RemoveTrailingSlash(url) + "/actuator/env"

	statusCode1 := getStatusCode(version1)
	statusCode2 := getStatusCode(version2)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}
	if statusCode1 == 200 {
		req, err := client.Get(version1)
		if err != nil {
			panic(err)
		}
		defer req.Body.Close()
		// 执行请求
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			panic(err)
		}

		// 验证漏洞是否存在
		vulUrl := poc.RemoveTrailingSlash(url) + "/jolokia/list"
		req2, err := client.Get(vulUrl)
		if err != nil {
			panic(err)
		}
		defer req2.Body.Close()

		body2, err := ioutil.ReadAll(req2.Body)
		if err != nil {
			panic(err)
		}

		if req2.StatusCode == 200 && req.StatusCode == 200 {
			//验证漏洞是否存在
			if strings.Contains(string(body2), "type=MBeanFactory") && strings.Contains(string(body2), "createJNDIRealm") {
				log.Println("[+] 漏洞 jolokia-logback-JNDI-RCE 可能存在，请自行验证")
			} else {
				log.Println("[-] 漏洞 jolokia-logback-JNDI-RCE 不存在")
			}

			//查看java版本
			str := string(body)
			re := regexp.MustCompile(`"java\.runtime\.version":{"value":"(.*?)"}`)
			matches := re.FindAllStringSubmatch(str, -1)
			for _, submatches := range matches {
				log.Println("jdk版本：", submatches[1])
			}

		} else {
			log.Println("[-]Error: 漏洞不存在或请求网络问题")
		}
		// 创建一个 GET 请求对象
		return 1
	} else if statusCode2 == 200 {
		req, err := client.Get(version2)
		if err != nil {
			panic(err)
		}
		defer req.Body.Close()
		// 执行请求
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			panic(err)
		}

		// 验证漏洞是否存在
		vulUrl := poc.RemoveTrailingSlash(url) + "/actuator/jolokia/list"
		req2, err := client.Get(vulUrl)
		if err != nil {
			panic(err)
		}
		defer req2.Body.Close()

		body2, err := ioutil.ReadAll(req2.Body)
		if err != nil {
			panic(err)
		}

		if req2.StatusCode == 200 && req.StatusCode == 200 {
			//验证漏洞是否存在
			if strings.Contains(string(body2), "type=MBeanFactory") && strings.Contains(string(body2), "createJNDIRealm") {
				log.Println("[+] 漏洞 jolokia-logback-JNDI-RCE 存在")
			} else {
				log.Println("[-] 漏洞 jolokia-logback-JNDI-RCE 不存在")
			}

			//查看java版本
			str := string(body)
			re := regexp.MustCompile(`"java\.runtime\.version":{"value":"(.*?)"}`)
			matches := re.FindAllStringSubmatch(str, -1)
			for _, submatches := range matches {
				log.Println("jdk版本：", submatches[1])
			}

		} else {
			log.Println("[-]Error: 漏洞不存在或请求网络问题")
		}
		return 2
	}
	return statusCode2
}

func main() {
	var url string
	fmt.Print("输入url: ")
	fmt.Scan(&url)
	poc.GetPasswd1(checkVul(url), url)
}
