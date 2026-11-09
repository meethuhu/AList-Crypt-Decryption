//go:build e2e

// 这个文件只在带 e2e 标签时参与编译，用来开启 mygo 的 automation 协议，
// 方便在开发期用 mygo-automation 命令行驱动界面、截图做端到端验证。
// 正式构建不会包含它。
package main

import _ "github.com/egoist/mygo/plugins/automation"
