import os
from pathlib import Path

class SignatureScanner:
    """数字签名查杀引擎"""

    def __init__(self, quiet=True, debug=False):
        """初始化数字签名扫描引擎

        Args:
            quiet (bool): 是否静默模式
            debug (bool): 是否调试模式
        """
        self.quiet = quiet
        self.debug = debug
        self.signatures = set()
        self.sign_file = self._get_sign_file_path()
        self.update_signatures()
        self._load_signatures()

    def _get_sign_file_path(self):
        """获取签名文件路径"""
        # 直接从本地运行目录获取签名文件
        return os.path.join(os.getcwd(), 'sign')

    def update_signatures(self):
        """从本地运行目录获取签名文件"""
        if self.debug:
            print(f"[数字签名引擎] 正在从本地运行目录加载签名文件：{self.sign_file}")
        # 检查签名文件是否存在
        if not os.path.exists(self.sign_file):
            if self.debug:
                print(f"[数字签名引擎] 签名文件不存在：{self.sign_file}")
            return
        if self.debug:
            print(f"[数字签名引擎] 签名文件加载成功：{self.sign_file}")

    def _load_signatures(self):
        """从 sign 文件加载数字签名列表"""
        if not os.path.exists(self.sign_file):
            if self.debug:
                print(f"[数字签名引擎] 签名文件不存在：{self.sign_file}")
            return

        try:
            with open(self.sign_file, 'r', encoding='utf-8') as f:
                for line in f:
                    signature = line.strip()
                    if signature:
                        self.signatures.add(signature)

            if self.debug:
                print(f"[数字签名引擎] 加载了 {len(self.signatures)} 个签名")
        except Exception as e:
            if self.debug:
                print(f"[数字签名引擎] 加载签名文件失败：{e}")

    def _get_signer_info(self, file_path):
        """获取 PE 文件的数字签名者信息（只返回 CN 参数）"""
        try:
            import pefile
            
            # 使用 fast_load 快速解析，只读取必要信息
            pe = pefile.PE(file_path, fast_load=True)
            
            # 方法 2：检查安全目录（证书表），使用 cryptography 库解析
            if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
                security_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
                
                if security_dir_size > 0 and security_dir_size < 65536:  # 限制最大 64KB
                    try:
                        cert_data = pe.get_data(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress, min(security_dir_size, 65536))
                        if cert_data:
                            # 尝试使用 cryptography 库解析证书
                            try:
                                from cryptography import x509
                                from cryptography.hazmat.backends import default_backend
                                from cryptography.hazmat.primitives.serialization import pkcs7
                                
                                # 跳过 WIN_CERTIFICATE 头部（8 字节）
                                cert_content = cert_data[8:]
                                
                                # 尝试解析为 PKCS#7 格式
                                try:
                                    p7 = pkcs7.load_der_pkcs7_certificates(cert_content, default_backend())
                                    for cert in p7:
                                        # 提取使用者（Subject）的 CN 参数
                                        try:
                                            # 方法 1：使用 get_attributes_for_oid
                                            from cryptography.x509.oid import NameOID
                                            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                            if cn_attrs:
                                                return cn_attrs[0].value
                                        except:
                                            # 方法 2：遍历所有属性
                                            for attr in cert.subject:
                                                if hasattr(attr.oid, '_name') and attr.oid._name == 'commonName':
                                                    return attr.value
                                                elif str(attr.oid).endswith('commonName'):
                                                    return attr.value
                                except Exception:
                                    # PKCS#7 解析失败，尝试直接解析为 X.509 证书
                                    try:
                                        cert = x509.load_der_x509_certificate(cert_content, default_backend())
                                        # 提取使用者（Subject）的 CN 参数
                                        try:
                                            # 方法 1：使用 get_attributes_for_oid
                                            from cryptography.x509.oid import NameOID
                                            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                            if cn_attrs:
                                                return cn_attrs[0].value
                                        except:
                                            # 方法 2：遍历所有属性
                                            for attr in cert.subject:
                                                if hasattr(attr.oid, '_name') and attr.oid._name == 'commonName':
                                                    return attr.value
                                                elif str(attr.oid).endswith('commonName'):
                                                    return attr.value
                                    except:
                                        pass
                            except ImportError:
                                pass
                            except:
                                pass
                    except:
                        pass
            
            # 方法 1：快速检查版本信息中的公司名称（备选方案）
            try:
                pe.parse_data_directories()
                if hasattr(pe, 'FileInfo') and pe.FileInfo:
                    for file_info in pe.FileInfo:
                        # 尝试多种方式获取 StringTable
                        string_tables = []
                        if hasattr(file_info, 'StringTable'):
                            string_tables = file_info.StringTable
                        elif hasattr(file_info, '__iter__'):
                            for item in file_info:
                                if hasattr(item, 'StringTable'):
                                    string_tables = item.StringTable
                                    break
                        
                        for st in string_tables:
                            if hasattr(st, 'entries'):
                                for key, value in st.entries.items():
                                    key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else str(key)
                                    value_str = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)
                                    
                                    # 检查公司名称
                                    if key_str == 'CompanyName' and value_str.strip():
                                        return value_str
                                break
                        break
            except:
                pass
            
            return None
                
        except:
            return None

    def scan_file(self, file_path):
        """扫描文件数字签名

        Args:
            file_path (str): 文件路径

        Returns:
            str or None: 病毒名，如果未检测到威胁则返回 None
        """
        if not self.signatures:
            return None

        if not os.path.exists(file_path):
            return None

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ['.exe', '.dll', '.sys', '.ocx']:
            return None

        signer_info = self._get_signer_info(file_path)
        if not signer_info:
            return None

        try:
            for sig in self.signatures:
                if sig.lower() in signer_info.lower():
                    return "PUA.SoftCnApp"
        except:
            pass

        return None
