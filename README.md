# AList Crypt 解密器

解密 [Alist](https://github.com/AlistGo/alist) / [OpenList](https://github.com/OpenListTeam/OpenList) 的 Crypt 加密存储。
Go + [MyGo](https://github.com/egoist/mygo) 原生界面，**单个可执行文件，不需要 Python，也不需要装 rclone**。

![界面截图](docs/screenshot.png)

## 它解决什么问题

Alist / OpenList 的 Crypt 存储底层就是 rclone crypt。以前要解开这些文件，得装 Python、装 pyyaml、
再从 rclone.org 下载一个 50 MB 的 rclone 并配好 PATH，然后记住一堆命令行参数。

现在只要下载一个 10 MB 的程序，双击打开，选目录、填密码，就能看到解密后的文件名。

## 特点

**内嵌解密实现，零外部依赖**。scrypt 密钥派生、NaCl secretbox 分块解密、AES-EME 文件名解密
全部用 Go 实现，不再调用 rclone。支持 rclone crypt 的全部配置组合：

| 配置项 | 支持的值 |
|---|---|
| 文件名加密 | `off` / `standard` / `obfuscate` |
| 文件名编码 | `base64` / `base32` / `base32768` |
| 目录名加密 | 开 / 关 |
| 盐值 | 自定义 / 留空用内置默认盐 |
| 加密后缀 | 任意（仅 `off` 模式生效） |

**先看文件名，再决定解密**。填完密码立刻列出解密后的文件名。密码或编码填错时一眼就能看出来，
不用等整批文件跑完才发现解出来全是乱码。

**多核并行、可取消、进度可见**。按 CPU 核数并行解密，显示文件数、速度和剩余量，随时可以停下。

## 使用方法

1. 从 [Releases](../../releases) 下载对应平台的安装包
2. 选择加密目录（也可以直接把文件夹拖进输入框）
3. 选择输出目录，默认是加密目录下的 `.Decrypt`
4. 填写密码；如果存储配置里设了盐值，一并填入
5. 如果预览里显示的文件名不对，展开「高级选项」，把文件名加密方式和编码调成与存储端一致

输出的文件名和目录结构会还原成加密前的样子，同名文件默认覆盖。

## 从源码构建

需要 Go 1.27 或更高版本：

```bash
go run .                 # 直接运行
go test ./...            # 跑测试
go tool mygo build       # 打包当前平台的安装包到 build/
```

界面用 MyGo 的原生 UI（`ui` 包）写成，没有 HTML、没有 JS、不需要前端构建链。

## 正确性验证

解密算法是照着 rclone 的格式重新实现的，所以必须证明它和 rclone 解出来的完全一样。
仓库里带了一个对拍脚本：用真实的 rclone 生成加密样本，再用本项目的实现解密，最后逐字节比对。

```bash
# 需要本机有 rclone
RCLONE=/path/to/rclone bash tools/verify.sh
```

它覆盖 8 组配置（三种编码、三种文件名模式、目录名加解密、自定义/默认盐），
以及 0 字节、1 字节、64 KB 整块、64 KB+1、1 MB、中文文件名、嵌套目录等边界样本。

另有一个走界面的端到端脚本，会真的点「开始解密」再比对输出：

```bash
bash tools/e2e.sh
```

## 1.0 去哪了

`main` 分支是 1.0：一个 369 行的 Python 命令行脚本，依赖外部 rclone，适合放进脚本或服务器里用。
它仍然可用。这个分支是 2.0，换成 Go 重写并加了图形界面。

## 许可证

原项目沿用 WTFPL v2。解密算法参考了 [rclone](https://github.com/rclone/rclone)（MIT）的实现。
