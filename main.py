#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, Union

import yaml


class RcloneError(Exception):
    """Rclone 相关错误的基类"""
    pass


class RcloneNotFoundError(RcloneError):
    """找不到 rclone 可执行文件"""
    pass


class RcloneConfigError(RcloneError):
    """Rclone 配置错误"""
    pass


class RcloneAlistDecryptor:
    """AList Crypt 解密工具类"""

    def __init__(
        self,
        config_file: Optional[str] = None,
        password: Optional[str] = None,
        salt: Optional[str] = None,
        filename_encryption: str = "off",
        directory_encryption: bool = False,
        suffix: str = ".bin",
        filename_encoding: str = "base64",
        plaintext_password: bool = False
    ):
        """
        初始化解密工具

        Args:
            config_file: 配置文件路径
            password: AList Crypt 密码
            salt: AList Crypt 盐值
            filename_encryption: 文件名加密方式 ['off', 'standard', 'obfuscate']
            directory_encryption: 是否加密目录名
            suffix: 加密文件后缀
            filename_encoding: 文件名编码方式 ['base64', 'base32', 'base32768']
            plaintext_password: 是否使用明文密码
        """
        # 设置默认值
        self.default_decrypt_dir = ".Decrypt"
        
        if config_file:
            self._load_config(config_file)
        else:
            self._set_manual_config(
                password, salt, filename_encryption,
                directory_encryption, suffix, filename_encoding,
                plaintext_password
            )
        
        # 验证配置
        self._validate_config()
        # 检查 rclone 是否可用
        self._check_rclone()

    def _load_config(self, config_file: str) -> None:
        """从配置文件加载设置"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                
            self.plaintext_password = config.get('plaintext_password', False)
            self.password = config.get('password', '')
            self.salt = config.get('salt', '')
            self.filename_encryption = config.get('filename_encryption', 'off')
            self.directory_encryption = config.get('directory_name_encryption', False)
            self.suffix = config.get('encrypted_suffix', '.bin')
            self.filename_encoding = config.get('filename_encoding', 'base64')
            self.encrypt_dir = config.get('encrypt', '')
            self.decrypt_dir = config.get('decrypt', '')
        except Exception as e:
            raise RcloneConfigError(f"无法加载配置文件: {e}")

    def _set_manual_config(
        self,
        password: Optional[str],
        salt: Optional[str],
        filename_encryption: str,
        directory_encryption: bool,
        suffix: str,
        filename_encoding: str,
        plaintext_password: bool
    ) -> None:
        """手动设置配置参数"""
        self.plaintext_password = plaintext_password
        self.password = password or ''
        self.salt = salt or ''
        self.filename_encryption = filename_encryption
        self.directory_encryption = directory_encryption
        self.suffix = suffix
        self.filename_encoding = filename_encoding
        self.encrypt_dir = ""
        self.decrypt_dir = ""

    def _validate_config(self) -> None:
        """验证配置是否有效"""
        if not self.password:
            raise RcloneConfigError("未设置密码")
        
        if self.filename_encryption not in ['off', 'standard', 'obfuscate']:
            raise RcloneConfigError("无效的文件名加密方式")
        
        if self.filename_encoding not in ['base64', 'base32', 'base32768']:
            raise RcloneConfigError("无效的文件名编码方式")

    def _check_rclone(self) -> None:
        """检查 rclone 是否可用"""
        try:
            subprocess.run(
                ["rclone", "--version"],
                capture_output=True,
                check=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            raise RcloneNotFoundError(
                "找不到 rclone。请确保 rclone 已安装并在 PATH 中可用。"
                "请从 https://rclone.org/downloads/ 下载安装。"
            )

    def _create_rclone_config(self, source_dir: str) -> str:
        """
        创建 rclone 配置文件

        Args:
            source_dir: 源目录路径

        Returns:
            str: 配置文件路径
        """
        config: Dict[str, Any] = {
            "type": "crypt",
            "remote": source_dir,
            "filename_encryption": self.filename_encryption,
            "directory_name_encryption": "true" if self.directory_encryption else "false",
            "filename_encoding": self.filename_encoding,
            "suffix": self.suffix
        }

        # 处理密码和盐值
        self._process_credentials(config)

        # 创建临时配置文件
        return self._write_config_file(config)

    def _process_credentials(self, config: Dict[str, Any]) -> None:
        """处理密码和盐值的混淆"""
        if self.password:
            config["password"] = self._process_credential(
                self.password, "密码"
            )
        
        if self.salt:
            config["password2"] = self._process_credential(
                self.salt, "盐值"
            )

    def _process_credential(self, value: str, name: str) -> str:
        """处理单个凭证的混淆"""
        if self.plaintext_password:
            try:
                result = subprocess.run(
                    ["rclone", "obscure", value],
                    capture_output=True,
                    text=True,
                    check=True
                )
                return result.stdout.strip()
            except subprocess.SubprocessError as e:
                print(f"警告：无法混淆{name}: {e}，将直接使用明文")
                return value
        elif value.startswith("___Obfuscated___"):
            return value[len("___Obfuscated___"):]
        return value

    def _write_config_file(self, config: Dict[str, Any]) -> str:
        """写入 rclone 配置文件"""
        config_file = tempfile.NamedTemporaryFile(
            mode='w+',
            delete=False,
            suffix='.conf'
        )
        config_file.write("[alist_crypt]\n")
        for key, value in config.items():
            config_file.write(f"{key} = {value}\n")
        config_file.close()
        return config_file.name

    def decrypt(self, source_dir: Optional[str] = None,
               target_dir: Optional[str] = None) -> bool:
        """
        执行解密操作

        Args:
            source_dir: 源目录路径，如果为 None 则使用配置文件中的路径
            target_dir: 目标目录路径，如果为 None 则使用配置文件中的路径或默认路径

        Returns:
            bool: 解密是否成功
        """
        src = source_dir or self.encrypt_dir
        
        # 确定目标目录
        if not target_dir and not self.decrypt_dir:
            dst = os.path.join(src, self.default_decrypt_dir)
        else:
            dst = target_dir or self.decrypt_dir

        # 验证路径
        if not src or not os.path.exists(src):
            raise FileNotFoundError(f"源目录不存在: {src}")
        if not dst:
            raise ValueError("目标目录未指定")

        # 创建目标目录
        os.makedirs(dst, exist_ok=True)

        # 执行解密
        return self._run_rclone_decrypt(src, dst)

    def _run_rclone_decrypt(self, src: str, dst: str) -> bool:
        """执行 rclone 解密命令"""
        config_path = self._create_rclone_config(src)
        
        try:
            cmd = [
                "rclone", "copy",
                "--progress",
                "--log-level", "ERROR",
                "--stats", "1s",
                "--filter", f"- /{self.default_decrypt_dir}/**",
                "--filter", f"- {self.default_decrypt_dir}/**",
                "--filter", f"- {self.default_decrypt_dir}/",
                "--config", config_path,
                "alist_crypt:", dst
            ]
            
            print("\n" + "="*50)
            print("开始执行解密操作")
            print("-"*50)
            print(f"源目录：{src}")
            print(f"目标目录：{dst}")
            print("-"*50)
            
            process = subprocess.run(cmd, check=True)
            
            if process.returncode == 0:
                print("="*50)
                print("解密操作已完成")
                print("="*50 + "\n")
                return True
            
            print("\n" + "="*50)
            print(f"解密失败，返回码：{process.returncode}")
            print("="*50 + "\n")
            return False
            
        except subprocess.SubprocessError as e:
            print("\n" + "="*50)
            print(f"执行失败：{e}")
            print("="*50 + "\n")
            return False
        finally:
            os.unlink(config_path)


def parse_args() -> argparse.ArgumentParser:
    """
    解析命令行参数
    
    Returns:
        argparse.ArgumentParser: 参数解析器对象
    """
    parser = argparse.ArgumentParser(
        description='AList Crypt 解密工具 (基于rclone)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', help='配置文件路径')
    parser.add_argument('--password', help='AList Crypt 密码')
    parser.add_argument('--salt', help='AList Crypt 盐值')
    parser.add_argument('--input', help='要解密的目录路径')
    parser.add_argument('--output', help='解密输出路径')
    parser.add_argument(
        '--filename-encryption',
        choices=['off', 'standard', 'obfuscate'],
        help='文件名加密方式'
    )
    parser.add_argument(
        '--directory-encryption',
        action='store_true',
        help='是否加密目录名'
    )
    parser.add_argument('--suffix', help='加密文件后缀')
    parser.add_argument(
        '--filename-encoding',
        choices=['base64', 'base32', 'base32768'],
        help='文件名编码方式'
    )
    parser.add_argument(
        '--plaintext-password',
        action='store_true',
        help='密码和盐值是否为明文'
    )
    
    return parser


def main() -> None:
    """主函数"""
    parser = parse_args()
    args = parser.parse_args()
    
    # 如果没有任何参数，显示帮助信息并退出
    if not any(vars(args).values()):
        parser.print_help()
        return
    
    try:
        if args.config:
            decryptor = RcloneAlistDecryptor(config_file=args.config)
            decryptor.decrypt()
        else:
            if not args.input or not args.output:
                parser.print_help()
                return
                
            decryptor = RcloneAlistDecryptor(
                password=args.password,
                salt=args.salt,
                filename_encryption=args.filename_encryption,
                directory_encryption=args.directory_encryption,
                suffix=args.suffix,
                filename_encoding=args.filename_encoding,
                plaintext_password=args.plaintext_password
            )
            
            decryptor.decrypt(args.input, args.output)
            
    except Exception as e:
        print(f"\n错误: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())