package rcrypt

import (
	"crypto/rand"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"
)

// EncryptFileName 加密一个相对路径（用 / 分隔），返回加密后的路径。
func (c *Cipher) EncryptFileName(in string) (string, error) {
	if c.mode == NameEncryptionOff {
		return in + c.encryptedSuffix, nil
	}
	return c.encryptPath(in)
}

// EncryptDirName 加密目录路径。目录名不加密时原样返回。
func (c *Cipher) EncryptDirName(in string) (string, error) {
	if c.mode == NameEncryptionOff || !c.dirNameEncrypt {
		return in, nil
	}
	return c.encryptPath(in)
}

// encryptPath 逐段加密路径，规则与解密对称：
// 目录名不加密时，除最后一段外都保持原样。
func (c *Cipher) encryptPath(in string) (string, error) {
	segments := strings.Split(in, "/")
	last := len(segments) - 1

	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if !c.dirNameEncrypt && i != last {
			continue
		}
		if c.mode == NameEncryptionStandard {
			segments[i] = c.encryptSegment(seg)
		} else {
			segments[i] = c.obfuscateSegment(seg)
		}
	}
	return strings.Join(segments, "/"), nil
}

// encryptSegment 加密单个路径段：PKCS#7 填充 → AES-EME → 编码。
func (c *Cipher) encryptSegment(plaintext string) string {
	padded := pkcs7Pad(nameCipherBlockSize, []byte(plaintext))
	ciphertext := eme.Transform(c.block, c.nameTweak[:], padded, eme.DirectionEncrypt)
	return c.fileNameEnc.EncodeToString(ciphertext)
}

// obfuscateSegment 按字符类别做轮转。它不是加密，只是让人扫一眼看不出内容。
func (c *Cipher) obfuscateSegment(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	// 非法 UTF-8 没法逐字符轮转，直接标记后原样保留
	if !utf8.ValidString(plaintext) {
		return "!." + plaintext
	}

	// 用一个由文件名算出的数字写在前面，真正的偏移量还要叠加密钥
	var dir int
	for _, r := range plaintext {
		dir += int(r)
	}
	dir %= 256

	var out strings.Builder
	out.WriteString(strconv.Itoa(dir))
	out.WriteByte('.')

	for i := 0; i < len(c.nameKey); i++ {
		dir += int(c.nameKey[i])
	}

	for _, r := range plaintext {
		switch {
		case r == obfuscQuoteRune:
			out.WriteRune(obfuscQuoteRune)
			out.WriteRune(obfuscQuoteRune)

		case r >= '0' && r <= '9':
			shift := (dir % 9) + 1
			out.WriteRune(rune('0' + (int(r)-'0'+shift)%10))

		case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
			shift := dir%25 + 1
			pos := int(r - 'A')
			if pos >= 26 {
				pos -= 6 // 小写字母
			}
			pos = (pos + shift) % 52
			if pos >= 26 {
				pos += 6
			}
			out.WriteRune(rune('A' + pos))

		case r >= 0xA0 && r <= 0xFF:
			shift := (dir % 95) + 1
			out.WriteRune(rune(0xA0 + (int(r)-0xA0+shift)%96))

		case r >= 0x100:
			shift := (dir % 127) + 1
			base := int(r) - int(r)%256
			nr := rune(base + (int(r)-base+shift)%256)
			if !utf8.ValidRune(nr) {
				out.WriteRune(obfuscQuoteRune)
				out.WriteRune(r)
			} else {
				out.WriteRune(nr)
			}

		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// EncryptStream 把 src 的明文加密后写入 dst，返回写入的字节数。
//
// 输出格式与 rclone 一致：8 字节 magic + 24 字节随机 nonce，
// 之后是若干个 64 KB 分块，每块用 secretbox 加密，nonce 逐块递增。
func (c *Cipher) EncryptStream(dst io.Writer, src io.Reader) (int64, error) {
	var nonce [fileNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}

	header := make([]byte, 0, fileHeaderSize)
	header = append(header, fileMagic...)
	header = append(header, nonce[:]...)

	written, err := dst.Write(header)
	var total int64 = int64(written)
	if err != nil {
		return total, err
	}

	plain := make([]byte, blockDataSize)
	sealed := make([]byte, blockSize)

	for {
		n, readErr := io.ReadFull(src, plain)
		if n > 0 {
			out := secretbox.Seal(sealed[:0], plain[:n], &nonce, &c.dataKey)
			w, writeErr := dst.Write(out)
			total += int64(w)
			if writeErr != nil {
				return total, writeErr
			}
			incrementNonce(&nonce)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// incrementNonce 按小端顺序给 24 字节 nonce 加一，与 rclone 的 carry(0) 一致。
func incrementNonce(n *[fileNonceSize]byte) {
	for i := 0; i < len(n); i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// EncryptedSize 计算加密后的文件大小，用于进度估算。
func EncryptedSize(plainSize int64) int64 {
	if plainSize <= 0 {
		return int64(fileHeaderSize)
	}
	blocks := plainSize / int64(blockDataSize)
	remainder := plainSize % int64(blockDataSize)
	total := int64(fileHeaderSize) + blocks*int64(blockSize)
	if remainder > 0 {
		total += int64(blockHeaderSize) + remainder
	}
	return total
}
