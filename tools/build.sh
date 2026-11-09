#!/usr/bin/env bash
# 打包成单个可执行文件，不生成安装包。
# 这种小工具直接发 exe 最省事：双击即用，删掉就是卸载。
set -eu

cd "$(dirname "$0")/.."
go tool mygo build -skip-installer "$@"
