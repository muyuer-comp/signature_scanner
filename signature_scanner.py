import os
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=UserWarning)

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
        """获取 PE 文件的数字签名者信息"""
        try:
            import pefile

            pe = pefile.PE(file_path, fast_load=True)

            # 方法1：检查安全目录（证书表），使用 cryptography 库解析
            if hasattr(pe, 'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER:
                security_dir_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size

                if security_dir_size > 0 and security_dir_size < 65536:
                    try:
                        cert_data = pe.get_data(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress, min(security_dir_size, 65536))
                        if cert_data:
                            try:
                                from cryptography import x509
                                from cryptography.hazmat.backends import default_backend
                                from cryptography.hazmat.primitives.serialization import pkcs7

                                cert_content = cert_data[8:]

                                # 尝试 PKCS#7 格式
                                try:
                                    p7 = pkcs7.load_der_pkcs7_certificates(cert_content)
                                    if self.debug:
                                        print(f"[数字签名引擎] PKCS#7 证书数量: {len(p7)}")
                                    
                                    # 遍历所有证书，找到实际的代码签名证书
                                    for i, cert in enumerate(p7):
                                        if self.debug:
                                            print(f"[数字签名引擎] 证书 {i+1} Subject: {cert.subject}")
                                        
                                        # 尝试提取 CN
                                        try:
                                            from cryptography.x509.oid import NameOID
                                            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                            if cn_attrs:
                                                cn_value = cn_attrs[0].value
                                                if self.debug:
                                                    print(f"[数字签名引擎] 证书 {i+1} CN: {cn_value}")
                                                # 排除 DigiCert 等根证书，只返回实际的代码签名证书
                                                if not any(keyword in cn_value for keyword in ['DigiCert', 'GlobalSign', 'Symantec', 'VeriSign', 'GeoTrust', 'Thawte', 'Sectigo', 'Let\'s Encrypt']):
                                                    return cn_value
                                        except:
                                            for attr in cert.subject:
                                                if hasattr(attr.oid, '_name') and attr.oid._name == 'commonName':
                                                    cn_value = attr.value
                                                    if self.debug:
                                                        print(f"[数字签名引擎] 证书 {i+1} CN: {cn_value}")
                                                    # 排除 DigiCert 等根证书
                                                    if not any(keyword in cn_value for keyword in ['DigiCert', 'GlobalSign', 'Symantec', 'VeriSign', 'GeoTrust', 'Thawte', 'Sectigo', 'Let\'s Encrypt']):
                                                        return cn_value
                                                elif str(attr.oid).endswith('commonName'):
                                                    cn_value = attr.value
                                                    if self.debug:
                                                        print(f"[数字签名引擎] 证书 {i+1} CN: {cn_value}")
                                                    # 排除 DigiCert 等根证书
                                                    if not any(keyword in cn_value for keyword in ['DigiCert', 'GlobalSign', 'Symantec', 'VeriSign', 'GeoTrust', 'Thawte', 'Sectigo', 'Let\'s Encrypt']):
                                                        return cn_value
                                except Exception as e:
                                    if self.debug:
                                        print(f"[数字签名引擎] PKCS#7 解析失败: {e}")
                                    pass

                                # 尝试 X.509 格式
                                try:
                                    cert = x509.load_der_x509_certificate(cert_content, default_backend())
                                    if self.debug:
                                        print(f"[数字签名引擎] X.509 解析成功")
                                    try:
                                        from cryptography.x509.oid import NameOID
                                        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                        if cn_attrs:
                                            return cn_attrs[0].value
                                    except:
                                        for attr in cert.subject:
                                            if hasattr(attr.oid, '_name') and attr.oid._name == 'commonName':
                                                return attr.value
                                            elif str(attr.oid).endswith('commonName'):
                                                return attr.value
                                except Exception as e:
                                    if self.debug:
                                        print(f"[数字签名引擎] X.509 解析失败: {e}")
                                    pass

                            except ImportError as e:
                                if self.debug:
                                    print(f"[数字签名引擎] cryptography 库未安装: {e}")
                                pass
                            except Exception as e:
                                if self.debug:
                                    print(f"[数字签名引擎] 证书解析失败: {e}")
                                pass
                    except Exception as e:
                        if self.debug:
                            print(f"[数字签名引擎] 获取证书数据失败: {e}")
                        pass

            # 只有当安全目录大小 > 0 时，才尝试从版本信息获取（作为备选）
            # 这样可以确保只有有数字签名的文件才会被检测
            if security_dir_size > 0:
                # 方法2：从版本信息获取公司名称（备选）
                try:
                    pe.parse_data_directories()
                    if hasattr(pe, 'FileInfo') and pe.FileInfo:
                        for file_info in pe.FileInfo:
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

                                        if key_str == 'CompanyName' and value_str.strip():
                                            if self.debug:
                                                print(f"[数字签名引擎] 从版本信息获取公司名称: {value_str}")
                                            return value_str
                                    break
                            break
                except Exception as e:
                    if self.debug:
                        print(f"[数字签名引擎] 版本信息获取失败: {e}")
                    pass

            return None

        except Exception as e:
            if self.debug:
                print(f"[数字签名引擎] 文件解析失败: {e}")
            return None

    def _levenshtein_distance(self, s1, s2):
        """计算两个字符串的编辑距离"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _fuzzy_match(self, sig, info):
        """模糊匹配算法

        Args:
            sig (str): 签名关键词
            info (str): 待匹配信息

        Returns:
            float: 相似度分数 (0-1)
        """
        # 移除常见公司后缀
        suffixes = [
            'co., ltd.', 'ltd.', 'inc.', 'corp.', 'technology', 'tech',
            'network', 'software', '公司', '科技', '网络', '技术',
            '(', ')', '（', '）', ',', '，', '.', '。'
        ]

        info_clean = info.lower()
        sig_clean = sig.lower()

        for suffix in suffixes:
            info_clean = info_clean.replace(suffix, '')
            sig_clean = sig_clean.replace(suffix, '')

        info_clean = info_clean.strip()
        sig_clean = sig_clean.strip()

        if not info_clean or not sig_clean:
            return 0.0

        # 1. 精确包含匹配（最优先）
        if sig_clean in info_clean or info_clean in sig_clean:
            return 1.0

        # 2. 短签名精确匹配（数字类，如 "360"、"2345"）
        if len(sig_clean) <= 6 and sig_clean.isdigit():
            if sig_clean in info_clean:
                return 1.0

        # 3. 编辑距离相似度（只在字符串长度相近时计算）
        len_ratio = min(len(sig_clean), len(info_clean)) / max(len(sig_clean), len(info_clean))
        if len_ratio >= 0.5:  # 长度至少相差不超过一半
            max_len = max(len(sig_clean), len(info_clean))
            if max_len > 3:  # 只对长度大于3的字符串计算编辑距离
                distance = self._levenshtein_distance(sig_clean, info_clean)
                similarity = 1.0 - (distance / max_len)
                if similarity >= 0.8:  # 提高阈值到0.8
                    return similarity

        # 4. 连续子串匹配（只对较长的字符串）
        if len(sig_clean) >= 4 and len(info_clean) >= 4:
            if self._common_substring_ratio(sig_clean, info_clean) >= 0.7:  # 提高阈值到0.7
                return 0.8

        return 0.0

    def _common_substring_ratio(self, s1, s2):
        """计算两个字符串的公共子序列占比"""
        if not s1 or not s2:
            return 0.0

        # 找最长公共子串
        m, n = len(s1), len(s2)
        if m > 100 or n > 100:
            # 对于过长的字符串，只检查前30个字符
            s1 = s1[:30]
            s2 = s2[:30]
            m, n = len(s1), len(s2)

        # 动态规划找最长公共子串
        dp = [[0] * (n + 1) for _ in range(2)]
        max_len = 0

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i % 2][j] = dp[(i-1) % 2][j-1] + 1
                    max_len = max(max_len, dp[i % 2][j])

        # 返回最长公共子串占较短字符串的比例
        min_len = min(m, n)
        if min_len > 0:
            return max_len / min_len
        return 0.0

    def _match_signature(self, signer_info):
        """匹配签名

        Args:
            signer_info (str): 签名者信息（公司名称等）

        Returns:
            tuple: (是否匹配成功, 匹配的签名, 威胁类型)
        """
        if not signer_info or not self.signatures:
            return False, None, None

        best_score = 0.0
        best_match = None

        for sig in self.signatures:
            score = self._fuzzy_match(sig, signer_info)
            if score > best_score:
                best_score = score
                best_match = sig

            if self.debug and score > 0.5:
                print(f"[数字签名引擎] 匹配调试: '{sig}' vs '{signer_info}' = {score:.2f}")

            if score >= 0.8:  # 提高阈值到0.8
                # 确定威胁类型
                threat_type = "PUA.SoftCnApp"
                if '火绒' in sig or 'Huorong' in sig:
                    threat_type = "Riskware.Huorong"
                return True, sig, threat_type

        if self.debug:
            print(f"[数字签名引擎] 最佳匹配分数: {best_score:.2f}")

        return False, best_match, None

    def scan_file(self, file_path):
        """扫描文件数字签名

        Args:
            file_path (str): 文件路径

        Returns:
            tuple: (病毒名, 匹配的签名) 如果未检测到威胁则返回 (None, None)
        """
        if not self.signatures:
            return None, None

        if not os.path.exists(file_path):
            return None, None

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ['.exe', '.dll', '.sys', '.ocx']:
            return None, None

        signer_info = self._get_signer_info(file_path)
        if not signer_info:
            return None, None

        matched, matched_signature, threat_type = self._match_signature(signer_info)
        if matched:
            return threat_type, matched_signature

        return None, None
