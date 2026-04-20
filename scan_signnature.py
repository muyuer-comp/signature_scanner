import os
import sys
from signature_scanner import SignatureScanner

def scan_directory(directory_path, debug=False):
    """扫描指定目录下的所有 PE 文件"""
    scanner = SignatureScanner(debug=debug)

    if not os.path.exists(directory_path):
        print(f"错误：目录不存在 - {directory_path}")
        return

    print(f"正在扫描目录: {directory_path}")
    print("-" * 50)

    threats_found = []
    files_scanned = 0
    files_with_signatures = 0
    files_without_signatures = 0

    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()

            if ext not in ['.exe', '.dll', '.sys', '.ocx']:
                continue

            files_scanned += 1

            if debug:
                print(f"\n正在扫描: {file_path}")

            result = scanner.scan_file(file_path)

            if result:
                threats_found.append((file_path, result))
                print(f"[威胁] {file_path}")
                print(f"      类型: {result}")
                print(f"      签名: {os.path.basename(file_path)}")
            else:
                if debug:
                    print(f"[无威胁] {file_path}")

    print("-" * 50)
    print(f"\n扫描完成！")
    print(f"扫描文件总数: {files_scanned}")
    print(f"检测到威胁数: {len(threats_found)}")

    if threats_found:
        print("\n=== 威胁列表 ===")
        for path, threat_type in threats_found:
            print(f"  {threat_type} - {path}")

    return threats_found

def print_help():
    """显示帮助信息"""
    print("数字签名扫描工具")
    print("用法:")
    print("  python scan_programs.py [目录路径] [--debug]")
    print("  python scan_programs.py --help")
    print("")
    print("参数:")
    print("  目录路径    要扫描的目录路径 (可选，默认: C:\\Users\\Administrator\\Downloads\\Programs)")
    print("  --debug     启用调试模式，显示详细信息")
    print("  --help      显示此帮助信息")
    print("")
    print("示例:")
    print("  python scan_programs.py C:\\Windows\\System32")
    print("  python scan_programs.py D:\\Downloads --debug")

if __name__ == "__main__":
    # 默认目录
    default_dir = r"C:\Users\Administrator\Downloads\Programs"
    target_dir = default_dir
    debug_mode = False

    # 解析命令行参数
    args = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    flags = [arg for arg in sys.argv[1:] if arg.startswith('--')]

    # 处理目录参数
    if args:
        target_dir = args[0]

    # 处理标志
    if "--debug" in flags:
        debug_mode = True
    if "--help" in flags:
        print_help()
        sys.exit(0)

    # 扫描目录
    scan_directory(target_dir, debug=debug_mode)

    input("\n按回车键退出...")
