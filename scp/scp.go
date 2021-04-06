package scp

import (
	"encoding/json"
	"os"
)


type Report struct {
	Results struct{
		RoleUsage []struct{
			EventSource string `json:"event_source"`
			EventName string `json:"event_name"`
			Count int64 `json:"count"`
		} `json:"role_usage"`
	} `json:"results"`
}


// directoryCheck checks a directory for files to
// process
func directoryCheck(directory string) (bool, error) {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return false, err
	}

	return true, nil
}

//getFileUsage returns the files to process from a directory
func GetFileUsage(directory string) ([]string, error) {
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

//generateReport will marshall the incoming json data
func GenerateReport(jsonData []byte) (*Report, error) {
	var v Report
	err := json.Unmarshal(jsonData, &v)

	if err != nil {
		return nil, err
	} else {
		return &v, nil
	}
}
