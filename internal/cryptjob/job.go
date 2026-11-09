// Package cryptjob 负责遍历目录、逐个文件加密或解密，并把结果写到目标目录。
package cryptjob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meethuhu/alist-crypt-decryption/internal/rcrypt"
)

// Mode 决定这批任务是把明文变成密文，还是反过来。
type Mode int

const (
	Decrypt Mode = iota
	Encrypt
)

func (m Mode) String() string {
	if m == Encrypt {
		return "加密"
	}
	return "解密"
}

// Options 控制任务行为。
type Options struct {
	Mode Mode
	// Files 非空时只处理这些文件（绝对路径），忽略 Src 目录。
	// 它们会被平铺到目标目录，同名时自动加序号。
	Files       []string
	Concurrency int
	Overwrite   bool
	OnProgress  func(Progress)
	OnFileDone  func(FileResult)
}

// Progress 是某一时刻的整体进度快照。字节数一律按"明文大小"计。
type Progress struct {
	TotalFiles  int
	DoneFiles   int
	FailedFiles int
	TotalBytes  int64
	DoneBytes   int64
	CurrentFile string
	BytesPerSec float64
}

// Percent 返回 0~100 的完成百分比。
func (p Progress) Percent() float64 {
	if p.TotalBytes <= 0 {
		if p.TotalFiles == 0 {
			return 0
		}
		return float64(p.DoneFiles) / float64(p.TotalFiles) * 100
	}
	return float64(p.DoneBytes) / float64(p.TotalBytes) * 100
}

// FileResult 是单个文件的处理结果。
type FileResult struct {
	Source string
	Target string
	Size   int64
	Err    error
}

// Result 是整批任务的汇总。
type Result struct {
	Total   int
	Success int
	// Skipped 是手动选中的文件里，明显不该处理而被跳过的数量，
	// 比如解密模式下选了一个普通文件。
	Skipped int
	Failed  []FileResult
	Bytes   int64
}

type task struct {
	srcRel  string
	dstRel  string
	srcPath string
	dstPath string
	size    int64
}

type progressState struct {
	totalFiles  int64
	doneFiles   int64
	failedFiles int64
	totalBytes  int64
	doneBytes   int64
	curMu       sync.Mutex
	currentFile string
}

// Run 遍历 src 下的文件，加密或解密后写入 dst。
//
// 如果 opts.Files 非空，就只处理这些文件，不看 src 目录。
// 单个文件失败不会中断整体流程，失败项收集在 Result.Failed 里。
func Run(ctx context.Context, src, dst string, c *rcrypt.Cipher, opts Options) (*Result, error) {
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return nil, err
	}

	result := &Result{}
	var tasks []task

	if len(opts.Files) > 0 {
		var skipped int
		tasks, skipped, err = collectFiles(opts.Files, dstAbs, c, opts.Mode)
		if err != nil {
			return nil, err
		}
		result.Skipped = skipped
	} else {
		srcAbs, absErr := filepath.Abs(src)
		if absErr != nil {
			return nil, absErr
		}
		if srcAbs == dstAbs {
			return nil, errors.New("输出目录不能和源目录相同")
		}
		tasks, err = collectDir(srcAbs, dstAbs, c, opts.Mode)
		if err != nil {
			return nil, err
		}
	}

	if len(tasks) == 0 {
		return result, nil
	}

	result.Total = len(tasks)

	workers := opts.Concurrency
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(tasks) {
		workers = len(tasks)
	}

	var (
		state  progressState
		resMu  sync.Mutex
		start  = time.Now()
	)
	for _, t := range tasks {
		state.totalBytes += t.size
	}
	state.totalFiles = int64(len(tasks))

	stopProgress := make(chan struct{})
	if opts.OnProgress != nil {
		go func() {
			ticker := time.NewTicker(120 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					opts.OnProgress(state.snapshot(start))
				}
			}
		}()
	}

	ch := make(chan task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				if ctx.Err() != nil {
					return
				}
				state.setCurrent(t.srcRel)
				written, err := transformFile(t.srcPath, t.dstPath, c, opts.Mode, opts.Overwrite)

				fr := FileResult{Source: t.srcRel, Target: t.dstRel, Size: written, Err: err}
				if err != nil {
					state.fail()
				} else {
					state.done(written)
				}
				if opts.OnFileDone != nil {
					opts.OnFileDone(fr)
				}
				resMu.Lock()
				if err != nil {
					result.Failed = append(result.Failed, fr)
				} else {
					result.Success++
					result.Bytes += written
				}
				resMu.Unlock()
			}
		}()
	}

	for _, t := range tasks {
		select {
		case <-ctx.Done():
		case ch <- t:
		}
	}
	close(ch)
	wg.Wait()
	close(stopProgress)

	if opts.OnProgress != nil {
		opts.OnProgress(state.snapshot(start))
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

// collectDir 遍历源目录，把每个文件映射成目标路径。
func collectDir(srcAbs, dstAbs string, c *rcrypt.Cipher, mode Mode) ([]task, error) {
	var tasks []task

	err := filepath.WalkDir(srcAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// 输出目录可能就在源目录里，必须跳过，否则会重复处理自己
			if path == dstAbs || ShouldSkip(d.Name(), true) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || ShouldSkip(d.Name(), false) {
			return nil
		}

		rel, err := filepath.Rel(srcAbs, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)

		var mapped string
		if mode == Decrypt {
			mapped, err = c.DecryptFileName(relSlash)
			if err != nil {
				// 不符合加密规则的文件直接忽略，比如 .DS_Store
				if errors.Is(err, rcrypt.ErrNotEncrypted) {
					return nil
				}
				return fmt.Errorf("解密文件名 %q 失败: %w", relSlash, err)
			}
		} else {
			mapped, err = c.EncryptFileName(relSlash)
			if err != nil {
				return fmt.Errorf("加密文件名 %q 失败: %w", relSlash, err)
			}
		}

		dstPath, err := safeJoin(dstAbs, mapped)
		if err != nil {
			return fmt.Errorf("文件名 %q 映射后路径非法: %w", relSlash, err)
		}

		var size int64
		if info, err := d.Info(); err == nil {
			size = info.Size()
			// 进度统一按明文大小算，解密时用文件头推算原大小
			if mode == Decrypt {
				if plain, err := rcrypt.DecryptedSize(info.Size()); err == nil {
					size = plain
				}
			}
		}

		tasks = append(tasks, task{
			srcRel:  relSlash,
			dstRel:  filepath.ToSlash(mapped),
			srcPath: path,
			dstPath: dstPath,
			size:    size,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

// collectFiles 处理手动选中的一组文件。它们被打平到目标目录，
// 因为选中的文件可能来自不同目录，保留原路径既没意义也容易越界。
//
// 返回值里的 skipped 是解密模式下明显不是加密文件、被跳过的数量。
func collectFiles(files []string, dstAbs string, c *rcrypt.Cipher, mode Mode) ([]task, int, error) {
	var (
		tasks   []task
		skipped int
		used    = make(map[string]int)
	)

	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}

		rel := filepath.Base(path)

		var mapped string
		if mode == Decrypt {
			mapped, err = c.DecryptFileName(rel)
			if err != nil {
				// 手选的普通文件在解密模式下没意义，跳过
				skipped++
				continue
			}
		} else {
			mapped, err = c.EncryptFileName(rel)
			if err != nil {
				skipped++
				continue
			}
		}

		mapped = uniqueName(mapped, used)

		dstPath, err := safeJoin(dstAbs, mapped)
		if err != nil {
			return nil, skipped, fmt.Errorf("文件名 %q 映射后路径非法: %w", rel, err)
		}

		tasks = append(tasks, task{
			srcRel:  rel,
			dstRel:  mapped,
			srcPath: path,
			dstPath: dstPath,
			size:    info.Size(),
		})
	}
	return tasks, skipped, nil
}

// uniqueName 避免选中的不同目录里存在同名文件时互相覆盖。
func uniqueName(name string, used map[string]int) string {
	n, seen := used[name]
	if !seen {
		used[name] = 1
		return name
	}
	used[name] = n + 1

	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s (%d)%s", base, n+1, ext)
}

// safeJoin 把映射出来的相对路径拼到目标目录下，并确保不会逃逸出去。
// 解密结果是攻击者可控的输入，必须防住 ../ 穿越。
func safeJoin(base, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("路径试图逃出目标目录")
	}
	target := filepath.Join(base, clean)
	if r, err := filepath.Rel(base, target); err != nil || strings.HasPrefix(r, "..") {
		return "", errors.New("路径试图逃出目标目录")
	}
	return target, nil
}

// transformFile 处理单个文件。先写 .part 临时文件，成功后改名，
// 这样中途失败不会在目标目录留下半截文件。
func transformFile(srcPath, dstPath string, c *rcrypt.Cipher, mode Mode, overwrite bool) (int64, error) {
	if !overwrite {
		if _, err := os.Stat(dstPath); err == nil {
			return 0, errors.New("目标文件已存在")
		}
	}

	in, err := os.Open(srcPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return 0, err
	}

	tmpPath := dstPath + ".part"
	out, err := os.Create(tmpPath)
	if err != nil {
		return 0, err
	}

	var written int64
	switch mode {
	case Encrypt:
		written, err = c.EncryptStream(out, in)
	default:
		var d *rcrypt.Decrypter
		d, err = c.NewDecrypter(in)
		if err == nil {
			written, err = io.Copy(out, d)
		}
	}

	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return written, err
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		os.Remove(tmpPath)
		return written, err
	}
	return written, nil
}

func (s *progressState) setCurrent(name string) {
	s.curMu.Lock()
	s.currentFile = name
	s.curMu.Unlock()
}

func (s *progressState) done(n int64) {
	atomic.AddInt64(&s.doneFiles, 1)
	atomic.AddInt64(&s.doneBytes, n)
}

func (s *progressState) fail() {
	atomic.AddInt64(&s.failedFiles, 1)
	atomic.AddInt64(&s.doneFiles, 1)
}

func (s *progressState) snapshot(start time.Time) Progress {
	s.curMu.Lock()
	cur := s.currentFile
	s.curMu.Unlock()

	doneBytes := atomic.LoadInt64(&s.doneBytes)
	p := Progress{
		TotalFiles:  int(atomic.LoadInt64(&s.totalFiles)),
		DoneFiles:   int(atomic.LoadInt64(&s.doneFiles)),
		FailedFiles: int(atomic.LoadInt64(&s.failedFiles)),
		TotalBytes:  atomic.LoadInt64(&s.totalBytes),
		DoneBytes:   doneBytes,
		CurrentFile: cur,
	}
	if elapsed := time.Since(start).Seconds(); elapsed > 0.2 {
		p.BytesPerSec = float64(doneBytes) / elapsed
	}
	return p
}
