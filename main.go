package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Node struct {
	Protocol string `json:"protocol"` // 协议类型，例如 vmess、vless、trojan
	Version  string `json:"v"`        // 协议版本（仅 vmess）
	Remark   string `json:"ps"`       // 节点备注
	Address  string `json:"add"`      // 节点地址
	Port     string `json:"port"`     // 节点端口（字符串类型）
	UUID     string `json:"id"`       // 用户的 UUID（适用于 vmess 和 vless）
	AlterID  string `json:"aid"`      // vmess 的 alterId（字符串类型）
	Network  string `json:"net"`      // 网络类型，例如 tcp、ws
	Type     string `json:"type"`     // 额外类型，例如 none
	Host     string `json:"host"`     // WebSocket 主机
	Path     string `json:"path"`     // WebSocket 路径
	TLS      string `json:"tls"`      // 是否启用 TLS（字符串类型）
	SNI      string `json:"sni"`      // SNI 信息
	Password string `json:"password"` // trojan 的密码
}

// 解析通用节点链接
func parseNodeLink(link string) (Node, error) {
	if strings.HasPrefix(link, "vmess://") {
		node, err := parseVMessLink(link)
		if err == nil {
			node.Protocol = "vmess"
		}
		return node, err
	} else if strings.HasPrefix(link, "vless://") {
		node, err := parseVLessLink(link)
		if err == nil {
			node.Protocol = "vless"
		}
		return node, err
	} else if strings.HasPrefix(link, "trojan://") {
		node, err := parseTrojanLink(link)
		if err == nil {
			node.Protocol = "trojan"
		}
		return node, err
	}
	return Node{}, fmt.Errorf("unsupported protocol in link: %s", link)
}

// 解析 VMess 链接
func parseVMessLink(link string) (Node, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return Node{}, fmt.Errorf("failed to decode VMess link: %v", err)
	}

	// fmt.Printf("Decoded VMess content: %s\n", decoded)

	var node Node
	if err := json.Unmarshal(decoded, &node); err != nil {
		return Node{}, fmt.Errorf("failed to parse VMess JSON: %v", err)
	}

	node.Protocol = "vmess"
	node.Version = "2"
	return node, nil
}

// 解析 VLess 链接
func parseVLessLink(link string) (Node, error) {
	// vless://<uuid>@<address>:<port>?encryption=none&security=tls&sni=<sni>&type=<network>&path=<path>
	parts := strings.Split(strings.TrimPrefix(link, "vless://"), "@")
	if len(parts) != 2 {
		return Node{}, fmt.Errorf("invalid VLess link: %s", link)
	}

	uuid := parts[0]
	addressParts := strings.Split(parts[1], ":")
	if len(addressParts) < 2 {
		return Node{}, fmt.Errorf("invalid VLess address: %s", parts[1])
	}

	address := addressParts[0]
	port := addressParts[1]

	node := Node{
		Protocol: "vless",
		Version:  "2",
		Address:  address,
		Port:     port,
		UUID:     uuid,
		TLS:      "tls",
	}

	// 解析 SNI 和其他参数
	if strings.Contains(link, "sni=") {
		node.SNI = extractQueryParam(link, "sni")
	}
	if strings.Contains(link, "path=") {
		node.Path = extractQueryParam(link, "path")
	}

	return node, nil
}

// 解析 Trojan 链接
func parseTrojanLink(link string) (Node, error) {
	// trojan://<password>@<address>:<port>?security=<tls>&type=<network>&headerType=<headerType>#<remark>
	parts := strings.Split(strings.TrimPrefix(link, "trojan://"), "@")
	if len(parts) != 2 {
		return Node{}, fmt.Errorf("invalid Trojan link: %s", link)
	}

	password := parts[0]
	addressParts := strings.Split(parts[1], ":")
	if len(addressParts) < 2 {
		return Node{}, fmt.Errorf("invalid Trojan address: %s", parts[1])
	}

	address := addressParts[0]
	portParts := strings.Split(addressParts[1], "?")
	if len(portParts) < 2 {
		return Node{}, fmt.Errorf("invalid Trojan port or parameters: %s", addressParts[1])
	}

	port := portParts[0]
	queryAndFragment := portParts[1]
	queryParts := strings.Split(queryAndFragment, "#")
	query := queryParts[0]
	remark := ""
	if len(queryParts) > 1 {
		remark = queryParts[1]
	}

	node := Node{
		Protocol: "trojan",
		Address:  address,
		Port:     port,
		Password: password,
		Remark:   remark,
	}

	// 解析查询参数
	if strings.Contains(query, "security=") {
		node.TLS = extractQueryParam(query, "security")
	}
	if strings.Contains(query, "type=") {
		node.Network = extractQueryParam(query, "type")
	}

	return node, nil
}

// 提取 URL 查询参数
func extractQueryParam(link, key string) string {
	parts := strings.Split(link, "?")
	if len(parts) < 2 {
		return ""
	}

	query := parts[1]
	for _, param := range strings.Split(query, "&") {
		if strings.HasPrefix(param, key+"=") {
			return strings.TrimPrefix(param, key+"=")
		}
	}
	return ""
}

// 读取订阅地址并获取节点列表
func fetchNodes(subscriptionURL string) ([]Node, error) {
	resp, err := http.Get(subscriptionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch subscription: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// 解码 Base64 内容
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// 按行解析链接
	lines := strings.Split(string(decoded), "\n")
	var nodes []Node
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析单个节点链接
		node, err := parseNodeLink(line)
		if err != nil {
			fmt.Printf("Warning: Failed to parse link: %v\n", err)
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// 过滤带 TLS 的节点
func filterTLSNodes(nodes []Node) []Node {
	var filtered []Node
	for _, node := range nodes {
		if node.TLS == "tls" {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

// 修改节点的 SNI
func modifySNI(nodes []Node, newSNI string) []Node {
	for i := range nodes {
		nodes[i].SNI = newSNI
	}
	return nodes
}

// 导出节点配置
func exportNodes(nodes []Node) (string, error) {
	var urls []string

	for _, node := range nodes {
		switch node.Protocol {
		case "vmess":
			// 将 Node 转换为 VMess 链接
			vmessConfig := map[string]string{
				"v":    node.Version,
				"ps":   node.Remark,
				"add":  node.Address,
				"port": node.Port,
				"id":   node.UUID,
				"aid":  node.AlterID,
				"net":  node.Network,
				"type": node.Type,
				"host": node.Host,
				"path": node.Path,
				"tls":  node.TLS,
				"sni":  node.SNI,
			}
			jsonData, err := json.Marshal(vmessConfig)
			if err != nil {
				return "", fmt.Errorf("failed to marshal VMess config: %v", err)
			}
			urls = append(urls, "vmess://"+base64.StdEncoding.EncodeToString(jsonData))

		case "vless":
			// 将 Node 转换为 VLess 链接
			vlessURL := fmt.Sprintf(
				"vless://%s@%s:%s?encryption=none&security=%s&sni=%s&type=%s&path=%s",
				node.UUID, node.Address, node.Port, node.TLS, node.SNI, node.Network, node.Path,
			)
			urls = append(urls, vlessURL)

		case "trojan":
			// 将 Node 转换为 Trojan 链接
			trojanURL := fmt.Sprintf(
				"trojan://%s@%s:%s?security=%s&type=%s&headerType=%s&sni=%s#%s",
				node.Password, node.Address, node.Port, node.TLS, node.Network, node.Type, node.SNI, node.Remark,
			)
			urls = append(urls, trojanURL)

		default:
			return "", fmt.Errorf("unsupported protocol: %s", node.Protocol)
		}
	}

	// 将所有链接合并为一个字符串，每行一个链接
	return strings.Join(urls, "\n"), nil
}

func main() {
	// 定义命令行参数
	subscriptionURL := flag.String("url", "", "The v2ray subscription URL")
	sni := flag.String("sni", "baidu.com", "The SNI to set for nodes")
	flag.Parse()

	// 检查是否提供了订阅地址
	if *subscriptionURL == "" {
		fmt.Println("Error: Subscription URL is required. Use -url to specify it.")
		flag.Usage()
		os.Exit(1)
	}

	// 获取节点列表
	nodes, err := fetchNodes(*subscriptionURL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 过滤带 TLS 的节点
	tlsNodes := filterTLSNodes(nodes)

	// 修改 SNI
	modifiedNodes := modifySNI(tlsNodes, *sni)

	// 导出节点配置
	exported, err := exportNodes(modifiedNodes)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Println("Exported Nodes Configuration:")
	fmt.Println(exported)
}
