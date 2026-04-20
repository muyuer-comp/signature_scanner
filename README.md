# muyuer-数字签名查杀引擎（muyuer-signature_scanner）
数字签名查杀引擎 - 基于 PE 文件数字签名检测的轻量级威胁识别工具。

## 功能特性

- **数字签名检测**：从 PE 文件中提取数字签名信息
- **签名匹配**：支持自定义签名库快速匹配威胁
- **多格式支持**：支持 .exe、.dll、.sys、.ocx 等 PE 文件格式
- **轻量高效**：采用快速加载模式，最小化资源占用
- **易于集成**：简洁的 API 设计，方便集成到其他项目中

## 项目结构

```
.
├── signature_scanner.py    # 核心扫描引擎
├── sign                    # 签名库文件（一行一个签名）
└──scan_programs.py         # 调用器程序（非必需）
```

## 快速开始

### 安装依赖

```bash
pip3 install pefile cryptography
```

### 准备签名文件

在项目根目录创建 `sign` 文件（文本类型），每行包含一个要检测的签名关键词：

```
SoftCnApp
恶意签名1
恶意签名2
```
**温馨提示：** 仓库提供了部分PUA软件的数字签名，***其真实性未经严格测试***，请自行判断使用。


### 使用示例

```python
from signature_scanner import SignatureScanner

# 初始化扫描器
scanner = SignatureScanner(debug=True)

# 扫描单个文件
result = scanner.scan_file(r"C:\path\to\file.exe")
if result:
    print(f"检测到威胁: {result}")
else:
    print("未检测到威胁")
```

### 命令行使用

```bash
python -c "
from signature_scanner import SignatureScanner
import sys

scanner = SignatureScanner(debug=True)
result = scanner.scan_file(sys.argv[1] if len(sys.argv) > 1 else 'test.exe')
print(f'扫描结果: {result}')
" C:\path\to\file.exe
```

## API 参考

### SignatureScanner

#### 构造函数

```python
SignatureScanner(quiet=True, debug=False)
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| quiet | bool | True | 静默模式 |
| debug | bool | False | 调试模式，输出详细运行信息 |

调用器在quiet参数下输出的内容：
<img width="914" height="298" alt="image" src="https://github.com/user-attachments/assets/17ba9ce7-9094-4a20-be99-79ecb1b1f72c" />

调用器在debug参数下输出的内容：
<img width="883" height="210" alt="image" src="https://github.com/user-attachments/assets/0f9b44b3-0e29-48ba-99de-4d6b70600eb8" />

#### 方法

- `scan_file(file_path)` - 扫描指定文件

#### 返回值

| 情况 | 返回值 | 说明 |
|------|--------|------|
| 检测到威胁 | `"PUA.SoftCnApp"` | 文件数字签名匹配到签名库中的恶意签名 |
| 没有威胁 | `None` | 文件有有效签名但未匹配到任何恶意签名 |
| 扫描失败 | `None` | 文件不存在、不是 PE 格式、无法获取签名信息等 |

#### 示例

```python
result = scanner.scan_file(r"C:\path\to\file.exe")

if result:
    print(f"检测到威胁: {result}")      # 输出: 检测到威胁: PUA.SoftCnApp
else:
    print("未检测到威胁或扫描失败")      # 文件无威胁或无法扫描
```

**注意**：由于失败和未检测到威胁都返回 `None`，如需区分这两种情况，请启用 `debug=True` 模式查看详细日志输出。


## 工作原理

1. **签名加载**：从本地 `sign` 文件加载签名库到内存
2. **PE 解析**：使用 pefile 库快速解析 PE 文件结构
3. **证书提取**：从安全目录中提取 PKCS#7/X.509 证书信息
4. **签名匹配**：提取证书的使用者 CN 名称，与签名库进行匹配
5. **结果返回**：匹配成功返回威胁类型，失败返回 None

## 支持的文件格式

- `.exe` - 可执行文件
- `.dll` - 动态链接库
- `.sys` - 系统驱动文件
- `.ocx` - ActiveX 控件

## 技术栈

- [pefile](https://github.com/erocarrera/pefile) - PE 文件解析
- [cryptography](https://github.com/pyca/cryptography) - 密码学操作（证书解析）

## 注意事项

- 签名文件 `sign` 必须存在于程序运行目录
- 程序仅检测具有有效数字签名的 PE 文件
- 签名匹配采用模糊匹配（不区分大小写）

## License

LGPL v2.1
