//go:build e2e

// 这个文件只在带 e2e 标签时参与编译，用来开启 mygo 的 automation 协议，
// 方便在开发期用 mygo-automation 命令行驱动界面、截图做端到端验证。
// 正式构建不会包含它。
package main

import (
	"os"
	"strings"

	_ "github.com/egoist/mygo/plugins/automation"
)

func init() {
	// 系统文件对话框没法用 automation 点，用环境变量预置一批文件，
	// 以便对「手选文件」这一屏做截图和端到端验证。
	if v := os.Getenv("MYGO_E2E_FILES"); v != "" {
		e2eFiles = strings.Split(v, ";")
	}
}
