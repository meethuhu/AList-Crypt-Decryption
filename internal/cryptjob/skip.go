package cryptjob

// 加解密目录时默认跳过的东西。卷进这些内容既没意义，
// 又会让预览和进度被大量噪音淹没。
var (
	skipDirs = map[string]struct{}{
		".git":         {},
		".svn":         {},
		".hg":          {},
		"node_modules": {},
		"__pycache__":  {},
		".venv":        {},
		"venv":         {},
		".idea":        {},
		".vscode":      {},
	}

	skipFiles = map[string]struct{}{
		".DS_Store":   {},
		"Thumbs.db":   {},
		"desktop.ini": {},
	}
)

// ShouldSkip 报告某个条目是否应该跳过。
func ShouldSkip(name string, isDir bool) bool {
	if isDir {
		_, skip := skipDirs[name]
		return skip
	}
	_, skip := skipFiles[name]
	return skip
}
