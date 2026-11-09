package main

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

// view 根据 app 的状态构建整个窗口。
// 它是即时模式的：每一帧都从头跑一遍，所以这里不保存任何跨帧数据。
func (a *app) view(c *ui.Context) {
	t := c.Theme()

	ui.Column(c).Fill().Gap(12).Padding(20).Children(func() {
		a.buildHeader(c, t)
		a.buildForm(c, t)
		a.buildPreview(c, t)
		a.buildFooter(c, t)
	})

	// 守卫式收尾：只在有新消息时弹一次，避免每帧重复弹窗
	if a.toastSeq != a.toastShown {
		a.toastShown = a.toastSeq
		c.Toast(a.toastMsg)
	}
}

func (a *app) buildHeader(c *ui.Context, t *ui.Theme) {
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, "AList Crypt 解密器").FontSize(19).Bold()
		ui.Text(c, "兼容 Alist / OpenList").FontSize(12).TextColor(t.TextMuted)
	})
	ui.Divider(c)
}

func (a *app) buildForm(c *ui.Context, t *ui.Theme) {
	ui.Form(c, func() {
		ui.Field(c, "加密目录", func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				if ui.TextInput(c.Key("src"), &a.srcDir).Grow(1).Changed() {
					a.schedulePreview()
				}
				if ui.Button(c, "选择").Clicked() {
					a.pickDir(&a.srcDir, "选择加密目录")
				}
			})
		})

		ui.Field(c, "输出目录", func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				if ui.TextInput(c.Key("dst"), &a.dstDir).Grow(1).Changed() {
					a.schedulePreview()
				}
				if ui.Button(c, "选择").Clicked() {
					a.pickDir(&a.dstDir, "选择输出目录")
				}
			})
		})

		ui.Field(c, "密码", func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
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

		ui.Field(c, "盐值", func() {
			if ui.TextInput(c.Key("salt"), &a.salt).Changed() {
				a.schedulePreview()
			}
		}).Description("可选。留空则使用 rclone 的内置盐值。")
	})

	// 高级选项
	c.Key("advanced")
	ui.Collapsible(c, "高级选项", &a.advanced, func() {
		ui.Form(c, func() {
			ui.Field(c, "文件名加密", func() {
				if ui.Select(c, &a.nameEnc, nameEncOptions).Width(140).Changed() {
					a.schedulePreview()
				}
			})
			ui.Field(c, "文件名编码", func() {
				if ui.Select(c, &a.encoding, encodingOptions).Width(140).Changed() {
					a.schedulePreview()
				}
			})
			ui.Field(c, "加密后缀", func() {
				if ui.TextInput(c.Key("suffix"), &a.suffix).Width(110).Changed() {
					a.schedulePreview()
				}
			})
			ui.Field(c, "目录名", func() {
				if ui.Switch(c, &a.dirEnc).Label("目录名也加密").Changed() {
					a.schedulePreview()
				}
			}).Description("关闭后，只有文件名被加密，目录结构保持原样。")
		})
	})
}

func (a *app) buildPreview(c *ui.Context, t *ui.Theme) {
	ui.Column(c).Grow(1).Gap(6).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "文件名预览").FontSize(13).Bold()
			switch {
			case a.previewing:
				ui.Text(c, "识别中…").FontSize(12).TextColor(t.TextMuted)
			case a.totalFiles > 0:
				ui.Textf(c, "共 %d 个文件", a.totalFiles).FontSize(12).TextColor(t.TextMuted)
			}
			if a.previewNote != "" {
				ui.Text(c, a.previewNote).FontSize(12).TextColor(t.TextMuted)
			}
		})

		if a.previewErr != "" {
			ui.Text(c, a.previewErr).FontSize(12).TextColor(t.Danger)
		} else if a.allPreviewFailed() {
			ui.Text(c, "这些文件名都解不开，通常是密码、盐值或编码设置和存储端不一致。").
				FontSize(12).TextColor(t.Danger)
		}

		// 没有内容时，把提示放在整块空白区域的正中间
		if len(a.previews) == 0 && !a.previewing {
			ui.Column(c).Grow(1).Center().Gap(6).Children(func() {
				ui.Text(c, "选择加密目录并填写密码后，这里会列出解密后的文件名").
					FontSize(13).TextColor(t.TextMuted)
				ui.Text(c, "先用预览确认密码是否正确，再开始整批解密").
					FontSize(12).TextColor(t.TextMuted)
			})
			return
		}

		ui.List(c, nil, len(a.previews), func(i int) {
			it := a.previews[i]
			ui.Row(c).Gap(10).AlignItems(ui.Center).Padding(4, 8).Children(func() {
				ui.Text(c, it.Encrypted).FontSize(12).Width(310).SingleLine().TextColor(t.TextMuted)
				ui.Text(c, "→").FontSize(12).TextColor(t.TextMuted)
				if it.Err != nil {
					ui.Text(c, "无法解密").FontSize(12).TextColor(t.Danger)
				} else {
					ui.Text(c, it.Decrypted).FontSize(12).SingleLine().Grow(1)
				}
			})
		}).Grow(1)
	})
}

// allPreviewFailed 报告预览里是否一个都没解开——这通常意味着参数不对。
func (a *app) allPreviewFailed() bool {
	if len(a.previews) == 0 {
		return false
	}
	for _, it := range a.previews {
		if it.Err == nil {
			return false
		}
	}
	return true
}

func (a *app) buildFooter(c *ui.Context, t *ui.Theme) {
	ui.Divider(c)

	if a.running {
		ui.Progress(c, a.progress.Percent()/100).Label("解密进度")
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Textf(c, "%d / %d 个文件", a.progress.DoneFiles, a.progress.TotalFiles).
				FontSize(12).TextColor(t.TextMuted)
			if a.progress.FailedFiles > 0 {
				ui.Textf(c, "%d 个失败", a.progress.FailedFiles).FontSize(12).TextColor(t.Danger)
			}
			ui.Text(c, formatSpeed(a.progress.BytesPerSec)).FontSize(12).TextColor(t.TextMuted).Grow(1)
			ui.Textf(c, "%.0f%%", a.progress.Percent()).FontSize(12).TextColor(t.TextMuted)
		})
	}

	if a.errorMsg != "" {
		ui.Text(c, a.errorMsg).FontSize(12).TextColor(t.Danger)
	}

	if !a.running && a.result != nil {
		switch {
		case len(a.result.Failed) == 0:
			ui.Textf(c, "完成：%d 个文件已解密到 %s", a.result.Success, a.dstDir).
				FontSize(12).TextColor(t.TextMuted)
		default:
			ui.Textf(c, "完成：成功 %d 个，失败 %d 个", a.result.Success, len(a.result.Failed)).
				FontSize(12).TextColor(t.Danger)
		}
	}

	for _, line := range a.logs {
		ui.Text(c, line).FontSize(12).TextColor(t.Danger)
	}

	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		if a.running {
			ui.Text(c, a.progress.CurrentFile).FontSize(12).TextColor(t.TextMuted).Grow(1)
			if ui.Button(c, "取消").Clicked() {
				a.stop()
			}
			return
		}
		hint := a.readyHint()
		if hint != "" {
			ui.Text(c, hint).FontSize(12).TextColor(t.TextMuted)
		}
		ui.Text(c, "").Grow(1)
		if ui.PrimaryButton(c, "开始解密").Disabled(!a.valid()).Clicked() {
			a.start()
		}
	})
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
