import os
import sys
from signature_scanner import SignatureScanner

def print_help():
    """显示帮助信息"""
    print("数字签名扫描工具")
    print("用法:")
    print(r"  python scan_signnature.py [目录路径或文件路径]")
    print(r"  python scan_signnature.py [目录路径或文件路径] --quiet")
    print(r"  python scan_signnature.py --help")
    print()
    print("参数:")
    print(r"  目录路径或文件路径    要扫描的目录或文件路径 (可选，默认: C:\Users\Administrator\Downloads\Programs)")
    print("  --quiet              静默模式，只显示扫描结果")
    print("  --help               显示此帮助信息")
    print()
    print("示例:")
    print(r"  python scan_signnature.py C:\Windows\System32")
    print(r"  python scan_signnature.py D:\Downloads\test.exe")
    print(r"  python scan_signnature.py E:\Scripts --quiet")

def scan_file(file_path, scanner):
    """扫描单个文件"""
    try:
        threat, signature = scanner.scan_file(file_path)
        if threat:
            return {
                'file': file_path,
                'threat': threat,
                'signature': signature
            }
    except Exception as e:
        pass
    return None

def scan_directory(directory, scanner):
    """扫描目录"""
    threats = []
    file_count = 0
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_count += 1
            
            threat_info = scan_file(file_path, scanner)
            if threat_info:
                threats.append(threat_info)
    
    return threats, file_count

def main():
    """主函数"""
    # 默认参数
    target = r"C:\Users\Administrator\Downloads\Programs"
    quiet = False
    
    # 解析命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print_help()
            return
        
        if len(sys.argv) > 2 and sys.argv[2] == "--quiet":
            target = sys.argv[1]
            quiet = True
        else:
            target = sys.argv[1]
    
    # 初始化扫描器
    scanner = SignatureScanner(debug=False)
    
    # 检查目标
    if not os.path.exists(target):
        print(f"错误: 路径不存在 - {target}")
        return
    
    threats = []
    file_count = 0
    
    if os.path.isfile(target):
        # 扫描单个文件
        if not quiet:
            print(f"正在扫描文件: {target}")
            print("-" * 50)
        
        threat_info = scan_file(target, scanner)
        if threat_info:
            threats.append(threat_info)
        file_count = 1
    else:
        # 扫描目录
        if not quiet:
            print(f"正在扫描目录: {target}")
            print("-" * 50)
        
        threats, file_count = scan_directory(target, scanner)
    
    # 显示扫描结果
    if not quiet:
        print("-" * 50)
        print()
    
    print("扫描完成！")
    print(f"扫描文件总数: {file_count}")
    print(f"检测到威胁数: {len(threats)}")
    
    if threats:
        print()
        print("=== 威胁列表 ===")
        for threat_info in threats:
            print(f"  {threat_info['threat']} - {threat_info['file']}")
    
    # 按回车键退出
    if not quiet:
        input("\n按回车键退出...")

if __name__ == "__main__":
    main()
