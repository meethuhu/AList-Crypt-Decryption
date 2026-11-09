package rcrypt

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func testConfigs() []struct {
	name string
	opts Options
} {
	base := func(mode NameEncryptionMode, enc string, dirEnc bool) Options {
		return Options{
			Password:          "round-trip-password",
			Salt:              "round-trip-salt",
			NameEncryption:    mode,
			DirNameEncryption: dirEnc,
			EncryptedSuffix:   ".bin",
			NameEncoding:      enc,
		}
	}
	return []struct {
		name string
		opts Options
	}{
		{"standard/base64/目录加密", base(NameEncryptionStandard, "base64", true)},
		{"standard/base32/目录加密", base(NameEncryptionStandard, "base32", true)},
		{"standard/base32768/目录加密", base(NameEncryptionStandard, "base32768", true)},
		{"standard/base64/目录不加密", base(NameEncryptionStandard, "base64", false)},
		{"obfuscate/base32/目录加密", base(NameEncryptionObfuscated, "base32", true)},
		{"off/base64/目录不加密", base(NameEncryptionOff, "base64", false)},
	}
}

// 加密再解密必须还原出完全一样的文件名。
func TestFileNameRoundTrip(t *testing.T) {
	names := []string{
		"a.txt",
		"说明.txt",
		"带 空格 的名字.txt",
		"很长的文件名" + strings.Repeat("x", 80) + ".pdf",
		"符号!@#$%^&().txt",
		"sub/嵌套文件.txt",
		"a/b/c/深/层.txt",
	}

	for _, cfg := range testConfigs() {
		t.Run(cfg.name, func(t *testing.T) {
			c, err := New(cfg.opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range names {
				enc, err := c.EncryptFileName(want)
				if err != nil {
					t.Fatalf("加密 %q 失败: %v", want, err)
				}
				got, err := c.DecryptFileName(enc)
				if err != nil {
					t.Fatalf("解密 %q（来自 %q）失败: %v", want, enc, err)
				}
				if got != want {
					t.Errorf("往返不一致：原文 %q → 密文 %q → 还原 %q", want, enc, got)
				}
			}
		})
	}
}

// 目录名按配置决定是否加密，且加密后仍能还原。
func TestDirNameRoundTrip(t *testing.T) {
	for _, dirEnc := range []bool{true, false} {
		c, err := New(Options{
			Password:          "pw",
			NameEncryption:    NameEncryptionStandard,
			DirNameEncryption: dirEnc,
			NameEncoding:      "base64",
			EncryptedSuffix:   ".bin",
		})
		if err != nil {
			t.Fatal(err)
		}
		enc, err := c.EncryptDirName("photos/2024")
		if err != nil {
			t.Fatal(err)
		}
		if !dirEnc && enc != "photos/2024" {
			t.Errorf("目录名不该被加密，实际得到 %q", enc)
		}
		got, err := c.DecryptDirName(enc)
		if err != nil {
			t.Fatal(err)
		}
		if got != "photos/2024" {
			t.Errorf("目录名往返不一致：%q → %q → %q", "photos/2024", enc, got)
		}
	}
}

// 内容加密再解密必须逐字节一致，重点是分块边界。
func TestContentRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 65535, 65536, 65537, 131072, 300000}

	for _, cfg := range testConfigs() {
		t.Run(cfg.name, func(t *testing.T) {
			c, err := New(cfg.opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, size := range sizes {
				plain := pattern(size)

				var enc bytes.Buffer
				n, err := c.EncryptStream(&enc, bytes.NewReader(plain))
				if err != nil {
					t.Fatalf("加密 %d 字节失败: %v", size, err)
				}
				if want := EncryptedSize(int64(size)); n != want {
					t.Errorf("%d 字节加密后应为 %d 字节，实际 %d", size, want, n)
				}

				d, err := c.NewDecrypter(bytes.NewReader(enc.Bytes()))
				if err != nil {
					t.Fatalf("读取加密流失败: %v", err)
				}
				got, err := io.ReadAll(d)
				if err != nil {
					t.Fatalf("解密 %d 字节失败: %v", size, err)
				}
				if !bytes.Equal(got, plain) {
					t.Errorf("%d 字节往返内容不一致：得到 %d 字节", size, len(got))
				}
			}
		})
	}
}

// 密码不对时必须报错，而不是返回垃圾数据。
func TestWrongPasswordFails(t *testing.T) {
	opts := Options{
		Password:       "right",
		NameEncryption: NameEncryptionStandard,
		NameEncoding:   "base64",
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if _, err := c.EncryptStream(&enc, bytes.NewReader(pattern(1000))); err != nil {
		t.Fatal(err)
	}

	wrong := opts
	wrong.Password = "wrong"
	c2, err := New(wrong)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c2.NewDecrypter(bytes.NewReader(enc.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(d); err == nil {
		t.Error("密码错误时解密应当失败")
	}
}

// 加密结果必须带上 rclone 的文件头标识。
func TestEncryptedHeader(t *testing.T) {
	c, err := New(Options{Password: "pw", NameEncryption: NameEncryptionOff, EncryptedSuffix: ".bin"})
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if _, err := c.EncryptStream(&enc, bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	if got := string(enc.Bytes()[:8]); got != fileMagic {
		t.Errorf("文件头标识错误：%q", got)
	}
	if enc.Len() != fileHeaderSize+blockHeaderSize+5 {
		t.Errorf("加密后长度 %d，期望 %d", enc.Len(), fileHeaderSize+blockHeaderSize+5)
	}
}

// pattern 生成一段可复现的数据。
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/7)
	}
	return b
}
