package scp

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"os"
	"strings"
)

//SCPConfig is a struct that will hold the
//flag values
type SCPConfig struct {
	SCPType     string
	ScannerFile string
	Threshold   int64
}

//Setup defines script parameters
func (s *SCPConfig) Setup() {
	flag.StringVar(&s.SCPType, "type", "Allow", "can be either Allow or Deny")
	flag.StringVar(&s.ScannerFile, "fileloc", "./s3_usage.json", "file location of scanner usage report")
	flag.Int64Var(&s.Threshold, "threshold", 10, "decision threshold")
}

//ServiceType returns the SCP Type parameter
func (s *SCPConfig) ServiceType() *string {
	return &s.SCPType
}

//ScannerFilename returns the File
func (s *SCPConfig) ScannerFilename() *string {
	return &s.ScannerFile
}

func (s *SCPConfig) ThresholdLimit() *int64 {
	return &s.Threshold
}

//Report represents a structure for a scp
type Report struct {
	Account struct {
		Identifier  string `json:"identifier"`
		AccountName string `json:"name"`
	} `json:"account"`
	Description string `json:"description"`
	Partition   struct {
		Year  string `json:"year"`
		Month string `json:"month"`
	}
	Results struct {
		Service      string `json:"event_source"`
		ServiceUsage []struct {
			EventName string `json:"event_name"`
			Count     int64  `json:"count"`
		} `json:"service_usage"`
	} `json:"results"`
}

//SCP is a struct representing a AWS SCP document
type SCP struct {
	Version   string `json:"Version"`
	Statement struct {
		Effect string `json:"Effect"`
		Action []string
	} `json:"Statement"`
	Resource string `json:"Resource"`
}

var ErrInvalidParameters = errors.New("input parameters missing")
var ErrInvalidThreshold = errors.New("threshold limit must be greater than zero")
var ErrInvalidSCPType = errors.New("scp type must be Allow or Deny")

// ServiceName returns a formatted service name
// from event_source data
func ServiceName(eventSource string) string {
	s := strings.Split(eventSource, ".")
	return s[0]
}

//LoadScannerFile loads the scanner json report
func LoadScannerFile(scannerFileName string) ([]byte, error) {
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

//GenerateReport will marshall the incoming json data
//from the scanner program into a struct.
func GenerateReport(jsonData []byte) (*[]Report, error) {
	var v []Report
	err := json.Unmarshal(jsonData, &v)

	if err != nil {
		return nil, err
	}

	return &v, nil

}

//GenerateList a list of all the api calls
//That are above and equal to the threshold
func GenerateList(threshold int64, reportData *Report, apiEval func(int64, int64) bool) (map[string]int64, error) {

	if threshold <= 0 {
		return nil, ErrInvalidThreshold
	}

	allowList := map[string]int64{}
	for _, v := range reportData.Results.ServiceUsage {
		if apiEval(v.Count, threshold) {
			allowList[v.EventName] = v.Count
		}
	}
	return allowList, nil
}

//GreaterThan evaluates the value
func GreaterThan(value int64, threshold int64) bool {
	isGreaterThan := false
	if value >= threshold {
		isGreaterThan = true
	}
	return isGreaterThan
}

//LessThan evaluates the value
func LessThan(value int64, threshold int64) bool {
	isLessThan := false
	if value < threshold {
		isLessThan = true
	}
	return isLessThan
}

//GenerateSCP generates an SCP
func GenerateSCP(scpType string, awsService string, permissionData map[string]int64) (scp SCP) {
	scp = SCP{}
	scp.Version = "2012-10-17"
	for k := range permissionData {
		p := awsService + ":" + k
		scp.Statement.Action = append(scp.Statement.Action, p)
		scp.Statement.Effect = scpType
	}
	scp.Resource = "*"
	return scp
}

//SaveSCP saves the scp file
func SaveSCP(scp SCP) error {
	jsonData, _ := json.MarshalIndent(scp, "", " ")
	err := ioutil.WriteFile("testSCP.json", jsonData, 0644)
	return err
}

//CheckSCPParameter checks that SCP parameter was
//Entered with correct value
func CheckSCPParameter(scpType string) bool{
	scpCheck := false

	s := strings.ToLower(scpType)
	if s == "allow" || s == "deny" {
		scpCheck = true
	}

	return scpCheck
}