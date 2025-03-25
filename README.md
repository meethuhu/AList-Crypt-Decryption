# AList Crypt 解密工具

用于解密 AList Crypt 加密的文件，使用 rclone 作为后端。支持明文密码和混淆密码，完全兼容 AList 的加密设置。

## 依赖

- Python 3.7+
- rclone

## 安装

1. 安装 Python 依赖
```bash
pip install -r requirements.txt
```

2. 安装 rclone
- 从 [rclone.org/downloads](https://rclone.org/downloads/) 下载并安装
- 确保 rclone 在系统 PATH 中可用

## 使用方法

### 使用配置文件

1. 复制并修改配置文件
```bash
cp config.example.yaml config.yaml
```

2. 运行程序
```bash
python main.py --config config.yaml
```

### 使用命令行参数

```bash
python main.py --input /path/to/encrypted --output /path/to/decrypted --password your_password
```

### 可用参数
--config 配置文件路径
--password AList Crypt 密码
--salt AList Crypt 盐值
--input 要解密的目录路径
--output 解密输出路径
--filename-encryption [off/standard/obfuscate] 文件名加密方式
--directory-encryption 是否加密目录名
--suffix 加密文件后缀
--filename-encoding [base64/base32/base32768] 文件名编码方式
--plaintext-password 密码和盐值是否为明文

## 许可证
WTFPL v2 License