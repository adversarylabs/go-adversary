package internal

import "os"

func createWrapped(path string) error {
	return os.MkdirAll(path, os.FileMode(os.ModeDir|os.ModePerm))
}
