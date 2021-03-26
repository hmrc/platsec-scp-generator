package scp

import (
	"os"
)

// directoryCheck checks a directory for files to
// process
func directoryCheck(directory string) (bool, error) {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return false, err
	}

	return true, nil
}

//getFileUsage returns the files to process from a directory
func getFileUsage(directory string) ([]string, error) {
	var filesList []string

	f, err := os.Open(directory)

	if err != nil {
		return filesList, err
	}

	defer f.Close()

	fileInfo, err := f.ReadDir(-1)
	if err != nil {
		return filesList, err
	}

	for _, file := range fileInfo {
		filesList = append(filesList, file.Name())
	}

	return filesList, nil
}
