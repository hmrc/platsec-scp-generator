package scp

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

//Report represents a structure for a scp
type Report struct {
		Account struct {
			Identifier string `json:"identifier"`
			AccountName string `json:"name"`
		} `json:"account"`
		Description string `json:"description"`
		Partition struct {
			Year string `json:"year"`
			Month string `json:"month"`
		}
		Results struct{
			Service string `json:"event_source"`
			ServiceUsage []struct{
				EventName string `json:"event_name"`
				Count int64 `json:"count"`
			} `json:"service_usage"`
		} `json:"results"`
}

//SCP is a struct representing a AWS SCP document
type SCP struct {
	Version string `json:"Version"`
	Statement struct {
       Effect string `json:"Effect"`
       Action []string
	} `json:"Statement"`
	Resource string `json:"Resource"`
}

var ErrInvalidParameters = errors.New("input parameters missing")

// getServiceName returns a formatted service name
// from event_source data
func GetServiceName(eventSource string) string {
    s := strings.Split(eventSource,".")
    return s[0]
}

//LoadScannerFile loads the scanner json report
func LoadScannerFile(scannerFileName string)([]byte, error) {
	scannerData, err := ioutil.ReadFile(scannerFileName)
	if err != nil {
		return nil, ErrInvalidParameters
	}
	return scannerData, nil
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

//GenerateReport will marshall the incoming json data
//from the scanner program into a struct.
func GenerateReport(jsonData []byte) (*[]Report, error) {
	var v []Report
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
		for _, v:=range reportData.Results.ServiceUsage {
			if v.Count >= threshold {
               allowList[v.EventName] = v.Count
			}
		}
		return allowList, nil
	}else {
	   return nil,ErrInvalidParameters
	}
}

//Generates a deny list of all the api calls
//That are above and equal to the threshold
func GenerateDenyList (threshold int64, reportData *Report)(map[string]int64, error) {
	if threshold > 0 {
		allowList :=map[string]int64{}
		for _, v:=range reportData.Results.ServiceUsage {
			if v.Count <= threshold {
				allowList[v.EventName] = v.Count
			}
		}
		return allowList, nil
	}else {
		return nil,ErrInvalidParameters
	}
}

//GenerateSCP generates an SCP
func GenerateSCP(scpType string, awsService string, permissionData map[string]int64) SCP{
	scp  := SCP{}
	scp.Version = "2012-10-17"
	for k, _ := range permissionData {
	   p := awsService + ":" + k
	   scp.Statement.Action = append(scp.Statement.Action, p)
	   scp.Statement.Effect = scpType
	}
	scp.Resource = "*"
	return scp
}

//SaveSCP saves the scp file
func SaveSCP(scp SCP)(bool, error) {
    jsonData, _ := json.MarshalIndent(scp,""," ")
    _ = ioutil.WriteFile("testSCP.json", jsonData, 0644)
    return true, nil
}