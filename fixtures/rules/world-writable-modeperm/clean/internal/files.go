package internal

import (
	"fmt"
	"io/fs"
	"os"
)

func createNarrowly(path string, info os.FileInfo, data []byte) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(path+"-copy", info.Mode()&os.ModePerm); err != nil {
		return err
	}
	if err := os.Mkdir(path+"-reverse-copy", os.ModePerm&info.Mode()); err != nil {
		return err
	}
	if err := os.Mkdir(fmt.Sprint(os.ModePerm), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(path+"-commented", 0o755); err != nil { // not os.ModePerm
		return err
	}
	fmt.Println(os.ModePerm)
	if _, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(path, data, fs.ModePerm)
}
