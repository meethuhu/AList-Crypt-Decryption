// Command crypt 是命令行版加解密工具。
//
// 它有两个用途：一是给对拍脚本调用，验证与 rclone 的兼容性；
// 二是在不想开图形界面时直接用。
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"path/filepath"

	"github.com/meethuhu/alist-crypt-decryption/internal/cryptjob"
	"github.com/meethuhu/alist-crypt-decryption/internal/rcrypt"
)

func main() {
	var (
		modeStr  = flag.String("mode", "decrypt", "decrypt 或 encrypt")
		src      = flag.String("src", "", "源目录")
		files    = flag.String("files", "", "要处理的文件，用逗号分隔；设置后忽略 -src")
		dst      = flag.String("dst", "", "目标目录")
		password = flag.String("password", "", "Crypt 密码")
		salt     = flag.String("salt", "", "Crypt 盐值")
		nameEnc  = flag.String("name-encryption", "standard", "文件名加密：off / standard / obfuscate")
		encoding = flag.String("encoding", "base64", "文件名编码：base64 / base32 / base32768")
		suffix   = flag.String("suffix", ".bin", "加密后缀，仅 off 模式使用")
		dirEnc   = flag.Bool("dir-encryption", true, "目录名是否也加密")
		compare  = flag.String("compare", "", "解密完成后与此目录逐字节比对")
		quiet    = flag.Bool("quiet", false, "不打印逐文件日志")
	)
	flag.Parse()

	var fileList []string
	for _, f := range strings.Split(*files, ",") {
		if f = strings.TrimSpace(f); f != "" {
			fileList = append(fileList, f)
		}
	}
	if len(fileList) == 0 && *src == "" {
		fatal("必须指定 -src 或 -files")
	}
	if *dst == "" {
		fatal("必须指定 -dst")
	}

	mode := cryptjob.Decrypt
	if *modeStr == "encrypt" {
		mode = cryptjob.Encrypt
	} else if *modeStr != "decrypt" {
		fatal("未知模式 " + *modeStr + "，可选 decrypt 或 encrypt")
	}

	ne, err := rcrypt.ParseNameEncryption(*nameEnc)
	if err != nil {
		fatal(err.Error())
	}
	c, err := rcrypt.New(rcrypt.Options{
		Password:          *password,
		Salt:              *salt,
		NameEncryption:    ne,
		DirNameEncryption: *dirEnc,
		EncryptedSuffix:   *suffix,
		NameEncoding:      *encoding,
	})
	if err != nil {
		fatal(err.Error())
	}

	res, err := cryptjob.Run(context.Background(), *src, *dst, c, cryptjob.Options{
		Mode:      mode,
		Files:     fileList,
		Overwrite: true,
		OnFileDone: func(fr cryptjob.FileResult) {
			if fr.Err != nil && !*quiet {
				fmt.Printf("  失败 %s: %v\n", fr.Source, fr.Err)
			}
		},
	})
	if err != nil {
		fatal(fmt.Sprintf("%s失败: %v", mode, err))
	}

	fmt.Printf("%s完成：共 %d 个文件，成功 %d，失败 %d\n", mode, res.Total, res.Success, len(res.Failed))

	if *compare != "" {
		bad, err := compareDirs(*compare, *dst)
		if err != nil {
			fatal("比对出错: " + err.Error())
		}
		if bad > 0 || len(res.Failed) > 0 {
			fmt.Printf("比对失败：%d 个文件内容不一致\n", bad)
			os.Exit(1)
		}
		fmt.Println("比对通过：所有文件逐字节一致")
	}
}

// compareDirs 递归比较两个目录，返回内容不一致的文件数。
func compareDirs(wantDir, gotDir string) (int, error) {
	bad, checked := 0, 0

	err := filepath.WalkDir(wantDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
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
