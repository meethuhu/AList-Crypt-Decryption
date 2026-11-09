package rcrypt

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Max-Sum/base32768"
)

// FileNameEncoding 对应 rclone crypt 的 filename_encoding 配置。
type FileNameEncoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

// base32Encoding 是 RFC4648 base32 的变体：小写、去掉 padding。
// rclone 选它是因为大小写不敏感的远端（Windows、Dropbox 等）也能存。
type base32Encoding struct{}

func (base32Encoding) EncodeToString(src []byte) string {
	return strings.ToLower(strings.TrimRight(base32.HexEncoding.EncodeToString(src), "="))
}

func (base32Encoding) DecodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, ErrBadBase32
	}
	// 补齐到 8 的倍数后再解码
	pad := (len(s) + 7) &^ 7
	s = strings.ToUpper(s) + strings.Repeat("=", pad-len(s))
	return base32.HexEncoding.DecodeString(s)
}

// base32768Encoding 是 rclone 自有的紧凑编码，一个字符能装 15 bit。
type base32768Encoding struct{}

func (base32768Encoding) EncodeToString(src []byte) string {
	return base32768.SafeEncoding.EncodeToString(src)
}

func (base32768Encoding) DecodeString(s string) ([]byte, error) {
	return base32768.SafeEncoding.DecodeString(s)
}

// ParseFileNameEncoding 把配置里的字符串转成编码器。
func ParseFileNameEncoding(name string) (FileNameEncoding, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "base64":
		return base64.RawURLEncoding, nil
	case "base32":
		return base32Encoding{}, nil
	case "base32768":
		return base32768Encoding{}, nil
	default:
		return nil, fmt.Errorf("未知的文件名编码 %q（可选 base64 / base32 / base32768）", name)
	}
}

// ParseNameEncryption 把配置里的字符串转成文件名加密模式。
func ParseNameEncryption(name string) (NameEncryptionMode, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "off":
		return NameEncryptionOff, nil
	case "standard":
		return NameEncryptionStandard, nil
	case "obfuscate":
		return NameEncryptionObfuscated, nil
	default:
		return NameEncryptionOff, fmt.Errorf("未知的文件名加密方式 %q（可选 off / standard / obfuscate）", name)
	}
}
