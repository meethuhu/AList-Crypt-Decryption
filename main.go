package main

import (
	"log"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// e2eFiles 只在 e2e 构建下由 e2e_automation.go 填充，
// 用来预置「手选文件」的状态，方便截图和自动化验证。
var e2eFiles []string

func main() {
	a := newApp()

	mygo.App.WhenReady(func() {
		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     appName,
			Width:     920,
			Height:    690,
			MinWidth:  760,
			MinHeight: 560,
			// 记住用户上次的窗口位置和大小
			StateKey: "main-v2",
			Content:  ui.View(a.view),
		})
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
