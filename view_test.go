package main

import (
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/meethuhu/alist-crypt-decryption/internal/cryptjob"
	"github.com/meethuhu/alist-crypt-decryption/internal/rcrypt"
)

// 视图能在没有窗口的情况下渲染，这保证了界面代码本身不会 panic。
func TestViewRenders(t *testing.T) {
	a := newApp()
	tt := ui.NewTester(a.view, 800, 840)

	if !tt.HasText(appName) {
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
	cases := []struct {
		name     string
		password string
		src      string
		dst      string
		valid    bool
		wantHint string
	}{
		{"什么都没有", "", "", "", false, "请填写密码"},
		{"只填密码", "pw", "", "", false, "请选择加密文件所在的目录，或直接选文件"},
		{"缺输出目录", "pw", "C:/enc", "", false, "请选择输出目录"},
		{"源和输出相同", "pw", "C:/enc", "C:/enc", false, "输出目录不能和源目录相同"},
		{"完整", "pw", "C:/enc", "C:/out", true, ""},
	}

	for _, tc := range cases {
		a := newApp()
		a.password, a.srcDir, a.dstDir = tc.password, tc.src, tc.dst

		if got := a.valid(); got != tc.valid {
			t.Errorf("%s: valid() = %v，期望 %v", tc.name, got, tc.valid)
		}
		if got := a.readyHint(); got != tc.wantHint {
			t.Errorf("%s: readyHint() = %q，期望 %q", tc.name, got, tc.wantHint)
		}
	}
}

// 加密模式下的提示文案和默认输出目录都应该跟着变。
func TestEncryptMode(t *testing.T) {
	a := newApp()
	base := a.dstDir
	if filepath.Base(base) != "decrypted" {
		t.Errorf("解密模式默认输出目录应为 decrypted，实际 %q", filepath.Base(base))
	}

	a.setMode(cryptjob.Encrypt)

	if filepath.Base(a.dstDir) != "encrypted" {
		t.Errorf("切到加密后默认输出目录应为 encrypted，实际 %q", filepath.Base(a.dstDir))
	}
	if a.actionWord() != "加密" {
		t.Errorf("actionWord() = %q，期望 加密", a.actionWord())
	}
	a.password, a.srcDir = "pw", "C:/in"
	if hint := a.readyHint(); hint != "" {
		t.Errorf("参数齐全时不该有提示，实际 %q", hint)
	}

	// 空源目录时，提示要说「要加密」
	b := newApp()
	b.setMode(cryptjob.Encrypt)
	b.password, b.srcDir = "pw", ""
	if hint := b.readyHint(); hint != "请选择要加密的目录或文件" {
		t.Errorf("加密模式提示 = %q", hint)
	}
}

// 密码为空时不启动预览，避免无意义的扫盘。
func TestPreviewSkippedWithoutPassword(t *testing.T) {
	a := newApp()
	a.srcDir = t.TempDir()
	a.previews = []previewItem{{Source: "stale"}}

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

// 手动选文件时不需要源目录，删除与清空要能正确维护列表。
func TestFileSelection(t *testing.T) {
	a := newApp()
	a.password = "pw"
	a.srcDir = ""
	a.files = []string{"C:/x/a.txt", "C:/y/b.txt"}

	if !a.valid() {
		t.Error("选了文件、有密码和输出目录就该可以开始")
	}

	a.removeFile(0)
	if len(a.files) != 1 || a.files[0] != "C:/y/b.txt" {
		t.Errorf("删除第 0 个后剩下 %v", a.files)
	}

	a.clearFiles()
	if len(a.files) != 0 {
		t.Errorf("清空后还有 %d 个", len(a.files))
	}
	if a.valid() {
		t.Error("清空且没有源目录时不该有效")
	}
}

// 选中的文件按文件名平铺，并给出加解密后的名字。
func TestPreviewForFiles(t *testing.T) {
	opts := rcrypt.Options{
		Password:        "pw",
		NameEncryption:  rcrypt.NameEncryptionStandard,
		NameEncoding:    "base64",
		EncryptedSuffix: ".bin",
	}
	items, err := buildPreviewForFiles([]string{"C:/a/说明.txt", "D:/b/photo.jpg"}, opts, cryptjob.Encrypt)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("应有 2 条预览，实际 %d", len(items))
	}
	if items[0].Source != "说明.txt" {
		t.Errorf("源名应只取文件名，实际 %q", items[0].Source)
	}
	for _, it := range items {
		if it.Err != nil {
			t.Errorf("%s 预览失败: %v", it.Source, it.Err)
		}
		if it.Target == "" {
			t.Errorf("%s 没有生成目标名", it.Source)
		}
	}
}
