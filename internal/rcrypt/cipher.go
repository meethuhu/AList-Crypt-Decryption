// Package rcrypt 实现与 rclone crypt 后端兼容的解密逻辑。
//
// AList / OpenList 的 Crypt 存储底层就是 rclone crypt，因此这里严格复刻
// rclone 的格式：scrypt 派生密钥、NaCl secretbox 分块加密内容、
// AES-EME 加密文件名。格式细节见 https://rclone.org/crypt/
package rcrypt

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"errors"
	"fmt"
	"strings"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/scrypt"
)

// NameEncryptionMode 对应 rclone 的 filename_encryption。
type NameEncryptionMode int

const (
	NameEncryptionOff NameEncryptionMode = iota
	NameEncryptionStandard
	NameEncryptionObfuscated
)

func (m NameEncryptionMode) String() string {
	switch m {
	case NameEncryptionStandard:
		return "standard"
	case NameEncryptionObfuscated:
		return "obfuscate"
	default:
		return "off"
	}
}

const (
	nameCipherBlockSize = aes.BlockSize
	fileMagic           = "RCLONE\x00\x00"
	fileMagicSize       = len(fileMagic)
	fileNonceSize       = 24
	fileHeaderSize      = fileMagicSize + fileNonceSize

	// blockHeaderSize 是 secretbox 的认证标签长度，每块都要带。
	blockHeaderSize = 16
	// blockDataSize 是 rclone 选定的明文块大小。
	blockDataSize = 64 * 1024
	blockSize     = blockHeaderSize + blockDataSize
)

// defaultSalt 是 rclone 在用户没填 salt 时使用的内置盐值。
var defaultSalt = []byte{
	0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
	0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
}

var (
	ErrBadMagic    = errors.New("不是加密文件：文件头标识不匹配")
	ErrBadBlock    = errors.New("分块认证失败：密码或盐值不正确")
	ErrBadHeader   = errors.New("加密文件已损坏：分块头被截断")
	ErrTooShort    = errors.New("加密文件已损坏：长度不足以包含文件头")
	ErrBadPadding  = errors.New("文件名解密失败：填充非法")
	ErrBadBase32   = errors.New("文件名不是合法的 base32 编码")
	ErrNotEncrypted = errors.New("文件名不符合加密后缀规则")
)

// Options 是一组解密参数，对应 AList Crypt 的存储配置。
type Options struct {
	// Password 是 Crypt 存储的密码。
	Password string
	// Salt 是密码盐值，留空则使用 rclone 的内置盐。
	Salt string
	// NameEncryption 对应 filename_encryption。
	NameEncryption NameEncryptionMode
	// DirNameEncryption 对应 directory_name_encryption。
	DirNameEncryption bool
	// EncryptedSuffix 是加密文件的后缀，例如 .bin。
	EncryptedSuffix string
	// NameEncoding 对应 filename_encoding：base64 / base32 / base32768。
	NameEncoding string
}

// Cipher 持有一组派生好的密钥，可以反复用于解密。
type Cipher struct {
	dataKey  [32]byte
	nameKey  [32]byte
	nameTweak [16]byte

	block gocipher.Block

	mode            NameEncryptionMode
	dirNameEncrypt  bool
	encryptedSuffix string
	fileNameEnc     FileNameEncoding
}

// New 派生密钥并构造 Cipher。
//
// scrypt 是故意设计得慢的（N=16384 约需几十毫秒），所以一个 Cipher
// 应当被整个解密过程复用，不要每个文件都新建。
func New(opts Options) (*Cipher, error) {
	if opts.Password == "" {
		return nil, errors.New("密码不能为空")
	}
	if opts.EncryptedSuffix == "" {
		opts.EncryptedSuffix = ".bin"
	}
	if !strings.HasPrefix(opts.EncryptedSuffix, ".") {
		return nil, fmt.Errorf("加密后缀必须以点开头，当前是 %q", opts.EncryptedSuffix)
	}

	enc, err := ParseFileNameEncoding(opts.NameEncoding)
	if err != nil {
		return nil, err
	}

	c := &Cipher{
		mode:            opts.NameEncryption,
		dirNameEncrypt:  opts.DirNameEncryption,
		encryptedSuffix: opts.EncryptedSuffix,
		fileNameEnc:     enc,
	}

	if err := c.deriveKey(opts.Password, opts.Salt); err != nil {
		return nil, err
	}
	return c, nil
}

// deriveKey 用 scrypt 派生 80 字节密钥，切成数据密钥、文件名密钥和 tweak。
func (c *Cipher) deriveKey(password, salt string) error {
	const keySize = 32 + 32 + 16

	saltBytes := defaultSalt
	if salt != "" {
		saltBytes = []byte(salt)
	}

	key, err := scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, keySize)
	if err != nil {
		return fmt.Errorf("派生密钥失败: %w", err)
	}

	copy(c.dataKey[:], key[0:32])
	copy(c.nameKey[:], key[32:64])
	copy(c.nameTweak[:], key[64:80])

	c.block, err = aes.NewCipher(c.nameKey[:])
	if err != nil {
		return fmt.Errorf("初始化文件名加密器失败: %w", err)
	}
	return nil
}

// DecryptFileName 解密一个相对路径（用 / 分隔）。
//
// 后缀只在 filename_encryption=off 时存在：那种模式下文件名原样保留，
// 只靠 .bin 之类的后缀标识这是加密文件。standard 和 obfuscate 模式下
// 文件名本身已经被改得面目全非，rclone 不再追加后缀。
func (c *Cipher) DecryptFileName(in string) (string, error) {
	if c.mode == NameEncryptionOff {
		if c.encryptedSuffix != "" {
			if !strings.HasSuffix(in, c.encryptedSuffix) {
				return "", ErrNotEncrypted
			}
			in = strings.TrimSuffix(in, c.encryptedSuffix)
		}
		if in == "" {
			return "", ErrNotEncrypted
		}
		return in, nil
	}
	return c.decryptPath(in)
}

// DecryptDirName 解密目录路径。目录名不加密时原样返回。
func (c *Cipher) DecryptDirName(in string) (string, error) {
	if c.mode == NameEncryptionOff || !c.dirNameEncrypt {
		return in, nil
	}
	return c.decryptPath(in)
}

// decryptPath 逐段解密路径。rclone 是分段加密的，每段独立处理。
func (c *Cipher) decryptPath(in string) (string, error) {
	segments := strings.Split(in, "/")
	last := len(segments) - 1

	for i, seg := range segments {
		// 目录名不加密时，除最后一段外都保持原样
		if !c.dirNameEncrypt && i != last {
			continue
		}
		var (
			out string
			err error
		)
		if c.mode == NameEncryptionStandard {
			out, err = c.decryptSegment(seg)
		} else {
			out, err = c.deobfuscateSegment(seg)
		}
		if err != nil {
			return "", fmt.Errorf("解密路径 %q 的第 %d 段失败: %w", in, i+1, err)
		}
		segments[i] = out
	}

	return strings.Join(segments, "/"), nil
}

// decryptSegment 解密单个路径段：base32 解码 → AES-EME 解密 → 去填充。
func (c *Cipher) decryptSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	raw, err := c.fileNameEnc.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadBase32, err)
	}
	if len(raw) == 0 {
		return "", ErrBadPadding
	}
	if len(raw)%nameCipherBlockSize != 0 {
		return "", ErrBadPadding
	}
	// rclone 自己也限制 2048 字节，超出说明不是合法密文
	if len(raw) > 2048 {
		return "", ErrBadPadding
	}

	padded := eme.Transform(c.block, c.nameTweak[:], raw, eme.DirectionDecrypt)
	plain, err := pkcs7Unpad(nameCipherBlockSize, padded)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// NameEncryption 返回当前的加密模式。
func (c *Cipher) NameEncryption() NameEncryptionMode { return c.mode }

// EncryptedSuffix 返回当前使用的加密后缀。
func (c *Cipher) EncryptedSuffix() string { return c.encryptedSuffix }
