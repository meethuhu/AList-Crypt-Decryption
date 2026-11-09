package rcrypt

import (
	"bytes"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Decrypter 把一个加密文件的字节流解成明文流。
//
// 它实现了 io.Reader，内部按 64 KB 分块处理，因此解大文件时内存占用恒定。
type Decrypter struct {
	r   io.Reader
	c   *Cipher
	nonce [fileNonceSize]byte

	readBuf []byte
	outBuf  []byte
	pending []byte
	err     error
}

// NewDecrypter 读取文件头（magic + nonce）并校验。
func (c *Cipher) NewDecrypter(r io.Reader) (*Decrypter, error) {
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return nil, ErrTooShort
		}
		return nil, err
	}
	if !bytes.Equal(header[:fileMagicSize], []byte(fileMagic)) {
		return nil, ErrBadMagic
	}

	d := &Decrypter{
		r:       r,
		c:       c,
		readBuf: make([]byte, blockSize),
		outBuf:  make([]byte, blockDataSize),
	}
	copy(d.nonce[:], header[fileMagicSize:])
	return d, nil
}

// Read 实现 io.Reader。
func (d *Decrypter) Read(p []byte) (int, error) {
	for len(d.pending) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		d.err = d.fill()
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// fill 读取并解密下一个分块。
func (d *Decrypter) fill() error {
	n, err := io.ReadFull(d.r, d.readBuf)
	switch err {
	case nil:
	case io.EOF:
		return io.EOF
	case io.ErrUnexpectedEOF:
		// 最后一块不足整块，属于正常情况，继续处理
	default:
		return err
	}

	// 只剩认证标签没有数据，说明文件被截断了
	if n <= blockHeaderSize {
		if err == io.ErrUnexpectedEOF {
			return ErrBadHeader
		}
		return io.EOF
	}

	out, ok := secretbox.Open(d.outBuf[:0], d.readBuf[:n], &d.nonce, &d.c.dataKey)
	if !ok {
		return ErrBadBlock
	}

	d.pending = out
	d.incrementNonce()
	return nil
}

// incrementNonce 让 nonce 前进一格，实现见 encrypt.go。
func (d *Decrypter) incrementNonce() {
	incrementNonce(&d.nonce)
}

// DecryptedSize 根据加密后的文件大小推算明文大小，用于进度估算。
func DecryptedSize(encryptedSize int64) (int64, error) {
	if encryptedSize < int64(fileHeaderSize) {
		return 0, ErrTooShort
	}
	body := encryptedSize - int64(fileHeaderSize)
	blocks := body / int64(blockSize)
	remainder := body % int64(blockSize)
	if remainder != 0 {
		if remainder <= int64(blockHeaderSize) {
			return 0, ErrBadHeader
		}
		blocks++
		remainder -= int64(blockHeaderSize)
	}
	return blocks*int64(blockDataSize) + remainder, nil
}
