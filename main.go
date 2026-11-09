package main

import (
	"log"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func main() {
	a := newApp()

	mygo.App.WhenReady(func() {
		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     appName,
			Width:     800,
			Height:    840,
			MinWidth:  640,
			MinHeight: 560,
			// 记住用户上次的窗口位置和大小
			StateKey: "main",
			Content:  ui.View(a.view),
		})
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
