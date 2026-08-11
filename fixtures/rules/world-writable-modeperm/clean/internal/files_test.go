package internal

import "os"

func createTestDirectory(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}
