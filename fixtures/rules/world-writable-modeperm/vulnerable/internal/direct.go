package internal

import "os"

func createDirect(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}
