package rcrypt

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
)

// obfuscate 模式不是加密，只是按一个由文件名和密钥共同决定的偏移量
// 把字符轮转一下。安全性接近于零，但能挡住"扫一眼就看到内容"。
const obfuscQuoteRune = '!'

// deobfuscateSegment 还原一个被混淆的路径段。
func (c *Cipher) deobfuscateSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	num, body, ok := strings.Cut(ciphertext, ".")
	if !ok {
		return "", ErrNotEncrypted
	}
	if num == "!" {
		// 原文不是合法 UTF-8，没做轮转，直接返回
		return body, nil
	}

	dir, err := strconv.Atoi(num)
	if err != nil {
		return "", errors.New("文件名不是合法的混淆格式")
	}
	// 真正的偏移量还要叠加密钥，所以光看文件名推不出原文
	for i := 0; i < len(c.nameKey); i++ {
		dir += int(c.nameKey[i])
	}

	var out bytes.Buffer
	quoted := false

	for _, r := range body {
		switch {
		case quoted:
			out.WriteRune(r)
			quoted = false

		case r == obfuscQuoteRune:
			quoted = true

		case r >= '0' && r <= '9':
			shift := (dir % 9) + 1
			nr := '0' + r - '0' - rune(shift)
			if nr < '0' {
				nr += 10
			}
			out.WriteRune(nr)

		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			shift := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6
			}
			pos -= shift
			if pos < 0 {
				pos += 52
			}
			if pos >= 26 {
				pos += 6
			}
			out.WriteRune(rune('A' + pos))

		case r >= 0xA0 && r <= 0xFF:
			shift := (dir % 95) + 1
			nr := 0xA0 + int(r) - 0xA0 - shift
			if nr < 0xA0 {
				nr += 96
			}
			out.WriteRune(rune(nr))

		case r >= 0x100:
			shift := (dir % 127) + 1
			base := int(r) - int(r)%256
			nr := base + (int(r) - base - shift)
			if nr < base {
				nr += 256
			}
			out.WriteRune(rune(nr))

		default:
			out.WriteRune(r)
		}
	}

	return out.String(), nil
}
