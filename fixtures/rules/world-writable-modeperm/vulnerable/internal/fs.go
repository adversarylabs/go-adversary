package internal

import (
	"io/fs"
	"os"
)

func createWithFS(path string) error {
	return os.Mkdir(path, fs.ModePerm)
}
