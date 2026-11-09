package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
	"github.com/meethuhu/alist-crypt-decryption/internal/cryptjob"
	"github.com/meethuhu/alist-crypt-decryption/internal/rcrypt"
)

var (
	nameEncOptions   = []string{"off", "standard", "obfuscate"}
	encodingOptions  = []string{"base64", "base32", "base32768"}
	previewFileLimit = 300
	previewDebounce  = 260 * time.Millisecond
)

// previewItem 是文件名预览里的一行。
type previewItem struct {
	Source string
	Target string
	Err    error
}

// app 是窗口展示的全部状态。view 每帧都从它重建界面。
type app struct {
	// 当前是加密还是解密
	mode cryptjob.Mode

	// 表单
	srcDir       string
	dstDir       string
	password     string
	salt         string
	showPassword bool
	advanced     bool
	nameEnc      string
	encoding     string
	suffix       string
	dirEnc       bool

	// 文件名预览
	previews    []previewItem
	previewErr  string
	previewing  bool
	previewSeq  int
	totalFiles  int
	previewNote string

	// 解密过程
	running  bool
	progress cryptjob.Progress
	result   *cryptjob.Result
	cancel   context.CancelFunc
	errorMsg string
	logs     []string

	// Toast 用序号驱动：view 在每帧末尾检查，只弹一次
	toastMsg   string
	toastSeq   int
	toastShown int

	win *mygo.Window
}

func newApp() *app {
	a := &app{
		nameEnc:  "standard",
		encoding: "base64",
		suffix:   ".bin",
		dirEnc:   true,
	}
	// 默认就在当前目录干活：把程序丢进一堆文件里，双击打开即可，
	// 不用先去挑目录。
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	a.srcDir = wd
	a.dstDir = filepath.Join(wd, defaultOutName(a.mode))
	return a
}

// defaultOutName 是每种模式默认的输出目录名。
func defaultOutName(m cryptjob.Mode) string {
	if m == cryptjob.Encrypt {
		return "encrypted"
	}
	return "decrypted"
}

// modeIndex 把当前模式映射成分段控件的下标。
func (a *app) modeIndex() int {
	if a.mode == cryptjob.Encrypt {
		return 1
	}
	return 0
}

// modeAt 把分段控件的下标还原成模式。
func modeAt(i int) cryptjob.Mode {
	if i == 1 {
		return cryptjob.Encrypt
	}
	return cryptjob.Decrypt
}

// setMode 切换加解密方向。输出目录如果还是默认名字，就跟着一起换。
func (a *app) setMode(m cryptjob.Mode) {
	if a.mode == m {
		return
	}
	if a.dstDir != "" && filepath.Base(a.dstDir) == defaultOutName(a.mode) {
		a.dstDir = filepath.Join(filepath.Dir(a.dstDir), defaultOutName(m))
	}
	a.mode = m
	a.result = nil
	a.errorMsg = ""
	a.schedulePreview()
}

func (a *app) cipherOptions() rcrypt.Options {
	mode, err := rcrypt.ParseNameEncryption(a.nameEnc)
	if err != nil {
		mode = rcrypt.NameEncryptionStandard
	}
	return rcrypt.Options{
		Password:          a.password,
		Salt:              a.salt,
		NameEncryption:    mode,
		DirNameEncryption: a.dirEnc,
		EncryptedSuffix:   a.suffix,
		NameEncoding:      a.encoding,
	}
}

// valid 报告当前表单是否已经可以开始解密。
func (a *app) valid() bool {
	return a.password != "" && a.srcDir != "" && a.dstDir != "" && a.srcDir != a.dstDir
}

// readyHint 给出还不能开始的原因，用于按钮旁的提示。
func (a *app) readyHint() string {
	switch {
	case a.password == "":
		return "请填写密码"
	case a.srcDir == "":
		if a.mode == cryptjob.Encrypt {
			return "请选择要加密的目录"
		}
		return "请选择加密文件所在的目录"
	case a.dstDir == "":
		return "请选择输出目录"
	case a.srcDir == a.dstDir:
		return "输出目录不能和源目录相同"
	}
	return ""
}

// schedulePreview 在用户改动参数后，延迟重新计算文件名预览。
//
// 每次调用都会让上一次的预览作废（通过序号），所以连续输入密码时
// 只有最后一次真正去扫目录。
func (a *app) schedulePreview() {
	a.previewSeq++
	seq := a.previewSeq

	if a.password == "" || a.srcDir == "" {
		a.previews = nil
		a.previewErr = ""
		a.previewing = false
		a.totalFiles = 0
		return
	}

	a.previewing = true
	a.previewErr = ""

	go func() {
		time.Sleep(previewDebounce)

		items, total, note, err := buildPreview(a.srcDir, a.dstDir, a.cipherOptions(), a.mode, previewFileLimit)

		a.updateUI(func() {
			if seq != a.previewSeq {
				return // 已有更新的请求，丢弃这次结果
			}
			a.previewing = false
			a.previews = items
			a.totalFiles = total
			a.previewNote = note
			if err != nil {
				a.previewErr = err.Error()
			} else {
				a.previewErr = ""
			}
		})
	}()
}

// buildPreview 扫描源目录，预览前若干个文件名会变成什么。
func buildPreview(src, dst string, opts rcrypt.Options, mode cryptjob.Mode, limit int) ([]previewItem, int, string, error) {
	c, err := rcrypt.New(opts)
	if err != nil {
		return nil, 0, "", err
	}

	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return nil, 0, "", err
	}
	dstAbs, _ := filepath.Abs(dst)

	var (
		items []previewItem
		total int
	)

	walkErr := filepath.WalkDir(srcAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 单个目录读不了就跳过，不打断预览
		}
		if d.IsDir() {
			if path == dstAbs || cryptjob.ShouldSkip(d.Name(), true) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || cryptjob.ShouldSkip(d.Name(), false) {
			return nil
		}

		rel, err := filepath.Rel(srcAbs, path)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		var mapped string
		if mode == cryptjob.Decrypt {
			mapped, err = c.DecryptFileName(relSlash)
			if err != nil {
				if errors.Is(err, rcrypt.ErrNotEncrypted) {
					return nil // 不是加密文件，跳过
				}
				total++
				if len(items) < limit {
					items = append(items, previewItem{Source: relSlash, Err: err})
				}
				return nil
			}
		} else {
			mapped, err = c.EncryptFileName(relSlash)
			if err != nil {
				total++
				if len(items) < limit {
					items = append(items, previewItem{Source: relSlash, Err: err})
				}
				return nil
			}
		}

		total++
		if len(items) < limit {
			items = append(items, previewItem{Source: relSlash, Target: mapped})
		}
		return nil
	})

	if walkErr != nil {
		return items, total, "", walkErr
	}

	note := ""
	if total == 0 {
		if mode == cryptjob.Encrypt {
			note = "这个目录里没有可加密的文件"
		} else {
			note = "这个目录里没有找到可解密的文件"
		}
	} else if total > len(items) {
		note = fmt.Sprintf("共 %d 个文件，仅预览前 %d 个", total, len(items))
	}

	return items, total, note, nil
}

// start 启动一次解密。
func (a *app) start() {
	if a.running || !a.valid() {
		return
	}

	c, err := rcrypt.New(a.cipherOptions())
	if err != nil {
		a.errorMsg = err.Error()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.running = true
	a.result = nil
	a.errorMsg = ""
	a.logs = nil
	a.progress = cryptjob.Progress{}

	src, dst, mode := a.srcDir, a.dstDir, a.mode

	go func() {
		res, runErr := cryptjob.Run(ctx, src, dst, c, cryptjob.Options{
			Mode:      a.mode,
			Overwrite: true,
			OnProgress: func(p cryptjob.Progress) {
				a.updateUI(func() { a.progress = p })
			},
			OnFileDone: func(fr cryptjob.FileResult) {
				if fr.Err == nil {
					return
				}
				msg := fmt.Sprintf("%s：%v", fr.Source, fr.Err)
				a.updateUI(func() { a.pushLog(msg) })
			},
		})

		a.updateUI(func() {
			a.running = false
			a.result = res
			switch {
			case runErr != nil && errors.Is(runErr, context.Canceled):
				a.pushLog("已取消")
				a.showToast("已取消")
			case runErr != nil:
				a.errorMsg = runErr.Error()
				a.showToast(mode.String() + "失败：" + runErr.Error())
			case res != nil && len(res.Failed) > 0:
				a.pushLog(fmt.Sprintf("完成，%d 个文件失败", len(res.Failed)))
				a.showToast(fmt.Sprintf("完成：成功 %d 个，失败 %d 个", res.Success, len(res.Failed)))
			case res != nil:
				a.showToast(fmt.Sprintf("完成：%d 个文件已%s", res.Success, mode))
			}
		})
	}()
}

func (a *app) stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *app) pushLog(msg string) {
	a.logs = append(a.logs, msg)
	if len(a.logs) > 200 {
		a.logs = a.logs[len(a.logs)-200:]
	}
}

// showToast 安排在下一帧弹一条提示。必须在主线程调用。
func (a *app) showToast(msg string) {
	a.toastMsg = msg
	a.toastSeq++
}

// updateUI 把一次状态修改搬到主线程并触发重绘。
// 窗口还没建好时（例如测试里）直接执行，方便脱离窗口跑视图逻辑。
func (a *app) updateUI(fn func()) {
	if a.win == nil {
		fn()
		return
	}
	a.win.Update(fn)
}

// pickDir 打开系统目录选择框。对话框是阻塞的，必须放在 goroutine 里。
func (a *app) pickDir(target *string, title string) {
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent:    a.win,
			Title:     title,
			Directory: true,
		})
		if err != nil || len(paths) == 0 {
			return
		}
		chosen := paths[0]
		a.updateUI(func() {
			isSource := target == &a.srcDir
			*target = chosen
			// 选完源目录后，如果输出目录还是空的，给个默认值
			if isSource && a.dstDir == "" {
				a.dstDir = filepath.Join(chosen, ".Decrypt")
			}
			a.schedulePreview()
		})
	}()
}
