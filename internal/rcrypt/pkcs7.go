package rcrypt

import "bytes"

// pkcs7Pad 把数据填充到 blockSize 的整数倍。
// 即便长度已经对齐也要补满一整块，这是 PKCS#7 的规定。
func pkcs7Pad(blockSize int, data []byte) []byte {
	n := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

// pkcs7Unpad 去掉 PKCS#7 填充，并校验填充是否合法。
func pkcs7Unpad(blockSize int, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrBadPadding
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return nil, ErrBadPadding
	}
	if !bytes.Equal(data[len(data)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, ErrBadPadding
	}
	return data[:len(data)-n], nil
}
