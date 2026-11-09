package main

import (
	"fmt"

	"github.com/egoist/mygo/ui"
	"github.com/meethuhu/alist-crypt-decryption/internal/cryptjob"
)

// appName 是窗口标题和界面上显示的名字。
const appName = "Crypt 加解密器"

// 左栏宽度。参数名和输入框竖排，这个宽度刚好放得下路径。
const sidebarWidth = 252

// 布局分三层：顶部标题栏、中间左右两栏（参数 / 预览）、底部固定操作栏。
// 参数固定宽度，预览吃掉剩余空间，这样长文件名有地方显示；
// 操作栏不随内容浮动，按钮永远在同一个位置。
func (a *app) view(c *ui.Context) {
	t := c.Theme()

	ui.Column(c).Fill().Children(func() {
		a.buildHeader(c, t)
		ui.Row(c).Grow(1).Children(func() {
			a.buildSidebar(c, t)
			ui.Divider(c)
			a.buildPreview(c, t)
		})
		a.buildActionBar(c, t)
	})

	// 守卫式收尾：只在有新消息时弹一次
	if a.toastSeq != a.toastShown {
		a.toastShown = a.toastSeq
		c.Toast(a.toastMsg)
	}
}

func (a *app) buildHeader(c *ui.Context, t *ui.Theme) {
	ui.Row(c).AlignItems(ui.Center).Gap(10).Padding(11, 16).Children(func() {
		ui.Text(c, appName).FontSize(15).Bold()
		ui.Text(c, "rclone crypt").FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, "").Grow(1)

		idx := a.modeIndex()
		if ui.Segmented(c, &idx, "解密", "加密").Label("操作").Changed() {
			a.setMode(modeAt(idx))
		}
	})
	ui.Divider(c)
}

// buildSidebar 是左栏：所有参数和状态都在这里，可滚动。
func (a *app) buildSidebar(c *ui.Context, t *ui.Theme) {
	ui.Scroll(c).Width(sidebarWidth).FillHeight().Padding(14).Gap(12).Children(func() {
		a.fieldSource(c, t)
		a.fieldOutput(c, t)
		a.fieldPassword(c, t)
		a.fieldSalt(c, t)
		a.fieldAdvanced(c, t)
		a.fieldStatus(c, t)
	})
}

// smallLabel 是左栏里每个字段上方的小标题。
func smallLabel(c *ui.Context, t *ui.Theme, text string) {
	ui.Text(c, text).FontSize(11).TextColor(t.TextMuted)
}

func (a *app) fieldSource(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(6).Children(func() {
		smallLabel(c, t, "来源")

		byFiles := len(a.files) > 0
		idx := 0
		if byFiles {
			idx = 1
		}
		if ui.Segmented(c, &idx, "目录", "文件").Label("来源类型").Changed() {
			if idx == 1 {
				a.pickFiles()
			} else {
				a.clearFiles()
			}
		}

		if byFiles {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				ui.Textf(c, "已选 %d 个文件", len(a.files)).FontSize(12).Grow(1)
				if ui.Button(c, "添加").Clicked() {
					a.pickFiles()
				}
			})
		} else {
			if ui.TextInput(c.Key("src"), &a.srcDir).Changed() {
				a.schedulePreview()
			}
		}
	})
}

func (a *app) fieldOutput(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(6).Children(func() {
		smallLabel(c, t, "输出到")
		ui.Row(c).Gap(6).Children(func() {
			if ui.TextInput(c.Key("dst"), &a.dstDir).Grow(1).Changed() {
				a.schedulePreview()
			}
			if ui.Button(c, "…").Width(34).Clicked() {
				a.pickDir(&a.dstDir, "选择输出目录")
			}
		})
	})
}

func (a *app) fieldPassword(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(6).Children(func() {
		smallLabel(c, t, "密码")
		ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
			var changed bool
			if a.showPassword {
				changed = ui.TextInput(c.Key("pw"), &a.password).Grow(1).Changed()
			} else {
				changed = ui.TextInput(c.Key("pw"), &a.password).Grow(1).Password().Changed()
			}
			if changed {
				a.schedulePreview()
			}
			ui.Checkbox(c, &a.showPassword, "显示")
		})
	})
}

func (a *app) fieldSalt(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(6).Children(func() {
		smallLabel(c, t, "盐值")
		if ui.TextInput(c.Key("salt"), &a.salt).Placeholder("留空则用默认盐").Changed() {
			a.schedulePreview()
		}
	})
}

func (a *app) fieldAdvanced(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(6).Children(func() {
		// 折叠时不占地方，但把当前配置摘要直接写出来，
		// 因为「和存储端不一致」恰恰是最常见的错误来源。
		summary := a.nameEnc + " · " + a.encoding
		if a.mode == cryptjob.Decrypt && a.dirEnc {
			summary += " · 目录名加密"
		}
		if a.mode == cryptjob.Encrypt && a.nameEnc == "off" && a.suffix != "" {
			summary += " · " + a.suffix
		}

		if ui.Button(c, "高级选项").Width(96).Clicked() {
			a.advanced = !a.advanced
		}
		ui.Text(c, summary).FontSize(11).TextColor(t.TextMuted).SingleLine()

		if !a.advanced {
			return
		}

		// 标签在左、控件在右，比上下排列省一半高度
		ui.Column(c).Gap(8).Children(func() {
			labelWidth := float32(72)
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, "文件名加密").FontSize(11).TextColor(t.TextMuted).Width(labelWidth)
				if ui.Select(c, &a.nameEnc, nameEncOptions).Grow(1).Changed() {
					a.schedulePreview()
				}
			})
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, "编码").FontSize(11).TextColor(t.TextMuted).Width(labelWidth)
				if ui.Select(c, &a.encoding, encodingOptions).Grow(1).Changed() {
					a.schedulePreview()
				}
			})
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, "后缀").FontSize(11).TextColor(t.TextMuted).Width(labelWidth)
				if ui.TextInput(c.Key("suffix"), &a.suffix).Grow(1).Changed() {
					a.schedulePreview()
				}
			})
			ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Text(c, "目录名加密").FontSize(11).TextColor(t.TextMuted).Width(labelWidth)
				if ui.Switch(c, &a.dirEnc).Label("目录名也加密").Changed() {
					a.schedulePreview()
				}
			})
		})
	})
}

// fieldStatus 展示当前还能不能开始，以及错误和失败明细。
func (a *app) fieldStatus(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Gap(4).Children(func() {
		if a.errorMsg != "" {
			ui.Text(c, a.errorMsg).FontSize(11).TextColor(t.Danger)
		}
		for _, line := range a.logs {
			ui.Text(c, line).FontSize(11).TextColor(t.Danger)
		}
	})
}

// buildPreview 是右栏：文件名的映射结果。
func (a *app) buildPreview(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Grow(1).FillHeight().Children(func() {
		byFiles := len(a.files) > 0
		removeIdx := -1

		ui.Row(c).AlignItems(ui.Center).Gap(8).Padding(11, 14).Children(func() {
			if byFiles {
				ui.Text(c, "已选的文件").FontSize(12).Bold()
			} else {
				ui.Text(c, "文件名预览").FontSize(12).Bold()
			}
			switch {
			case a.previewing:
				ui.Text(c, "识别中…").FontSize(11).TextColor(t.TextMuted)
			case a.totalFiles > 0:
				ui.Textf(c, "共 %d 个", a.totalFiles).FontSize(11).TextColor(t.TextMuted)
			}
			if a.previewNote != "" {
				ui.Text(c, a.previewNote).FontSize(11).TextColor(t.TextMuted)
			}
			ui.Text(c, "").Grow(1)
			if byFiles {
				if ui.Button(c, "清空").Clicked() {
					a.clearFiles()
				}
			}
		})
		ui.Divider(c)

		if a.previewErr != "" {
			ui.Text(c, a.previewErr).FontSize(11).TextColor(t.Danger).Padding(0, 14)
		} else if a.allPreviewFailed() {
			ui.Column(c).Gap(2).Children(func() {
				ui.Text(c, "这些文件名都处理不了，通常是密码、盐值或编码设置和存储端不一致。").
					FontSize(11).TextColor(t.Danger).Padding(0, 14)
				if detail := a.firstPreviewError(); detail != "" {
					ui.Text(c, "首个错误：" + detail).FontSize(11).TextColor(t.TextMuted).
						SingleLine().Padding(0, 14)
				}
			})
		}

		if len(a.previews) == 0 && !a.previewing {
			ui.Column(c).Grow(1).Center().Gap(6).Children(func() {
				hint := "选择加密文件所在的目录或文件，填上密码，这里会列出解密后的文件名"
				if a.mode == cryptjob.Encrypt {
					hint = "选择要加密的目录或文件，填上密码，这里会列出加密后的文件名"
				}
				ui.Text(c, hint).FontSize(12).TextColor(t.TextMuted)
			})
			return
		}

		ui.List(c, nil, len(a.previews), func(i int) {
			it := a.previews[i]
			ui.Row(c).Gap(10).AlignItems(ui.Center).Padding(5, 14).Children(func() {
				ui.Text(c, it.Source).FontSize(11).Width(250).SingleLine().TextColor(t.TextMuted)
				ui.Text(c, "→").FontSize(11).TextColor(t.TextMuted)
				if it.Err != nil {
					ui.Text(c, "无法"+a.actionWord()).FontSize(11).TextColor(t.Danger).Grow(1)
				} else {
					ui.Text(c, it.Target).FontSize(11).SingleLine().Grow(1)
				}
				if byFiles {
					if ui.Button(c, "×").Width(28).Clicked() {
						removeIdx = i
					}
				}
			})
		}).Grow(1)

		// 先记下来，等列表建完再改，避免一边遍历一边改集合
		if removeIdx >= 0 {
			a.removeFile(removeIdx)
		}
	})
}

// buildActionBar 是底部固定栏：进度、结果摘要、主操作。
func (a *app) buildActionBar(c *ui.Context, t *ui.Theme) {
	ui.Divider(c)

	ui.Row(c).AlignItems(ui.Center).Gap(12).Padding(10, 16).Children(func() {
		if a.running {
			ui.Progress(c, a.progress.Percent()/100).Label(a.actionWord() + "进度").Grow(1)
			ui.Textf(c, "%.0f%%", a.progress.Percent()).FontSize(11).TextColor(t.TextMuted)
			ui.Textf(c, "%d / %d", a.progress.DoneFiles, a.progress.TotalFiles).
				FontSize(11).TextColor(t.TextMuted)
			if a.progress.FailedFiles > 0 {
				ui.Textf(c, "%d 个失败", a.progress.FailedFiles).FontSize(11).TextColor(t.Danger)
			}
			if s := formatSpeed(a.progress.BytesPerSec); s != "" {
				ui.Text(c, s).FontSize(11).TextColor(t.TextMuted)
			}
			if ui.Button(c, "取消").Clicked() {
				a.stop()
			}
			return
		}

		if a.result != nil {
			switch {
			case len(a.result.Failed) == 0:
				ui.Textf(c, "完成：%d 个文件已%s", a.result.Success, a.actionWord()).
					FontSize(11).TextColor(t.TextMuted)
			default:
				ui.Textf(c, "完成：成功 %d 个，失败 %d 个", a.result.Success, len(a.result.Failed)).
					FontSize(11).TextColor(t.Danger)
			}
		}

		if hint := a.readyHint(); hint != "" {
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Text(c, "").Grow(1)
		if ui.PrimaryButton(c, "开始"+a.actionWord()).Disabled(!a.valid()).Clicked() {
			a.start()
		}
	})
}

// actionWord 是当前操作的动词，用来拼按钮和提示文案。
func (a *app) actionWord() string {
	if a.mode == cryptjob.Encrypt {
		return "加密"
	}
	return "解密"
}

func formatSpeed(bytesPerSec float64) string {
	switch {
	case bytesPerSec <= 0:
		return ""
	case bytesPerSec < 1024:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	case bytesPerSec < 1024*1024:
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/1024)
	default:
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/(1024*1024))
	}
}
