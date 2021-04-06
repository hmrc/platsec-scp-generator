package scp

import (
	"encoding/json"
	"os"
	"errors"
)


type Report struct {
	Results struct{
		RoleUsage []struct{
			EventName string `json:"event_name"`
			Count int64 `json:"count"`
		} `json:"role_usage"`
	} `json:"results"`
}

var ErrInvalidParameters = errors.New("input parameters missing")

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

//Generates an allow list of all the api calls
//That are above and equal to the threshold
func GenerateAllowList (threshold int64, reportData *Report)(map[string]int64, error) {
	if threshold > 0 {
		allowList :=map[string]int64{}
		for _, v:=range reportData.Results.RoleUsage {
			if v.Count >= threshold {
               allowList[v.EventName] = v.Count
			}
		}
		return allowList, nil
	}else {
	   return nil,ErrInvalidParameters
	}
}
