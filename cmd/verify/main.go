// Command verify 是一个开发期对拍工具：用本项目的解密实现解开
// rclone 生成的加密目录，再和原始明文逐字节比对。
//
// 用法见 tools/verify.sh。
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"

	"io/fs"
	"os"
	"path/filepath"

	"github.com/meethuhu/alist-crypt-decryption/internal/decryptor"
	"github.com/meethuhu/alist-crypt-decryption/internal/rcrypt"
)

func main() {
	src := flag.String("src", "", "加密目录")
	plain := flag.String("plain", "", "原始明文目录，用于逐字节比对")
	password := flag.String("password", "", "Crypt 密码")
	salt := flag.String("salt", "", "Crypt 盐值")
	mode := flag.String("mode", "standard", "文件名加密：off / standard / obfuscate")
	encoding := flag.String("encoding", "base32", "文件名编码：base64 / base32 / base32768")
	suffix := flag.String("suffix", ".bin", "加密后缀")
	dirEnc := flag.Bool("dir-enc", true, "目录名是否加密")
	flag.Parse()

	if *src == "" || *plain == "" {
		fatal("必须指定 -src 和 -plain")
	}

	m, err := rcrypt.ParseNameEncryption(*mode)
	if err != nil {
		fatal(err.Error())
	}
	c, err := rcrypt.New(rcrypt.Options{
		Password:          *password,
		Salt:              *salt,
		NameEncryption:    m,
		DirNameEncryption: *dirEnc,
		EncryptedSuffix:   *suffix,
		NameEncoding:      *encoding,
	})
	if err != nil {
		fatal(err.Error())
	}

	out, err := os.MkdirTemp("", "rcrypt-verify-*")
	if err != nil {
		fatal(err.Error())
	}
	defer os.RemoveAll(out)

	res, err := decryptor.Run(context.Background(), *src, out, c, decryptor.Options{Overwrite: true})
	if err != nil {
		fatal("解密失败: " + err.Error())
	}

	fmt.Printf("解密完成：共 %d 个文件，成功 %d，失败 %d\n", res.Total, res.Success, len(res.Failed))
	for _, f := range res.Failed {
		fmt.Printf("  失败 %s: %v\n", f.Source, f.Err)
	}

	bad, err := compare(*plain, out)
	if err != nil {
		fatal("比对出错: " + err.Error())
	}
	if bad > 0 || len(res.Failed) > 0 {
		fmt.Printf("\n对拍失败：%d 个文件内容不一致\n", bad)
		os.Exit(1)
	}
	fmt.Println("\n对拍通过：所有文件逐字节一致")
}

// compare 递归比较两个目录，返回内容不一致的文件数。
func compare(wantDir, gotDir string) (int, error) {
	bad := 0
	checked := 0

	err := filepath.WalkDir(wantDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(wantDir, path)
		if err != nil {
			return err
		}
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(gotDir, rel))
		if err != nil {
			fmt.Printf("  缺失: %s\n", filepath.ToSlash(rel))
			bad++
			return nil
		}
		if !bytes.Equal(want, got) {
			fmt.Printf("  内容不一致: %s（期望 %d 字节，实际 %d 字节）\n",
				filepath.ToSlash(rel), len(want), len(got))
			bad++
		}
		checked++
		return nil
	})
	if err != nil {
		return bad, err
	}
	fmt.Printf("已比对 %d 个文件\n", checked)
	return bad, nil
}



func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "错误: "+msg)
	os.Exit(1)
}
