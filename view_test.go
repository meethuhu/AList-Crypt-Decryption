package main

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// 视图能在没有窗口的情况下渲染，这保证了界面代码本身不会 panic。
func TestViewRenders(t *testing.T) {
	a := newApp()
	tt := ui.NewTester(a.view, 800, 840)

	if !tt.HasText("AList Crypt 解密器") {
		t.Errorf("缺少标题，当前文本：%q", tt.Texts())
	}
	if !tt.HasText("开始解密") {
		t.Errorf("缺少开始按钮，当前文本：%q", tt.Texts())
	}
	if !tt.HasText("文件名预览") {
		t.Errorf("缺少预览区，当前文本：%q", tt.Texts())
	}
}

// 展开高级选项后应该出现加密模式和编码选择。
func TestAdvancedOptions(t *testing.T) {
	a := newApp()
	tt := ui.NewTester(a.view, 800, 840)

	if err := tt.Click("高级选项"); err != nil {
		t.Fatal(err)
	}
	if !a.advanced {
		t.Fatal("点击后高级选项没有展开")
	}
	for _, want := range []string{"文件名加密", "编码", "加密后缀"} {
		if !tt.HasText(want) {
			t.Errorf("展开后缺少 %q，当前文本：%q", want, tt.Texts())
		}
	}
}

// 表单校验：只有密码、源目录、输出目录都合法时才允许开始。
func TestValid(t *testing.T) {
	a := newApp()

	cases := []struct {
		name     string
		setup    func()
		valid    bool
		wantHint string
	}{
		{"空表单", func() {}, false, "请填写密码"},
		{"只填密码", func() { a.password = "pw" }, false, "请选择加密目录"},
		{"缺输出目录", func() { a.srcDir = "C:/enc" }, false, "请选择输出目录"},
		{"源和输出相同", func() { a.dstDir = "C:/enc" }, false, "输出目录不能和源目录相同"},
		{"完整", func() { a.dstDir = "C:/out" }, true, ""},
	}

	for _, tc := range cases {
		tc.setup()
		if got := a.valid(); got != tc.valid {
			t.Errorf("%s: valid() = %v，期望 %v", tc.name, got, tc.valid)
		}
		if got := a.readyHint(); got != tc.wantHint {
			t.Errorf("%s: readyHint() = %q，期望 %q", tc.name, got, tc.wantHint)
		}
	}
}

// 密码为空时不启动预览，避免无意义的扫盘。
func TestPreviewSkippedWithoutPassword(t *testing.T) {
	a := newApp()
	a.srcDir = t.TempDir()
	a.previews = []previewItem{{Encrypted: "stale"}}

	a.schedulePreview()

	if len(a.previews) != 0 {
		t.Errorf("没有密码时预览应被清空，实际还有 %d 条", len(a.previews))
	}
	if a.previewing {
		t.Error("没有密码时不该进入识别状态")
	}
}

// 解密引擎参数应该和表单选择保持一致。
func TestCipherOptions(t *testing.T) {
	a := newApp()
	a.password = "pw"
	a.salt = "s"
	a.nameEnc = "obfuscate"
	a.encoding = "base32768"
	a.suffix = ".enc"
	a.dirEnc = false

	opts := a.cipherOptions()
	if opts.Password != "pw" || opts.Salt != "s" {
		t.Errorf("凭证传递错误: %+v", opts)
	}
	if opts.NameEncoding != "base32768" || opts.EncryptedSuffix != ".enc" {
		t.Errorf("编码或后缀传递错误: %+v", opts)
	}
	if opts.DirNameEncryption {
		t.Error("目录名加密应为 false")
	}
}
