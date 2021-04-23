package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strings"
)

const (
	exitFail = 1
)

//Package level vars to allow patch testing.
type fileLoader func(filename string) ([]byte, error)
type writeSCP func(filename string, data []byte, perm fs.FileMode) error

var loadFile fileLoader = ioutil.ReadFile
var saveSCPFile writeSCP = ioutil.WriteFile
var ErrInvalidParameters = errors.New("input parameters missing")
var ErrInvalidThreshold = errors.New("threshold limit must be greater than zero")
var ErrInvalidSCPType = errors.New("scp type must be Allow or Deny")

type SCPRun struct {
	scannerFilename string
	serviceType     string
	serviceName     string
	thresholdLimit  int64
	usageData       []byte
	reports         *[]Report
	permissionSet   map[string]int64
	scp             SCP
}

// validateService checks that the correct apply or
// deny value was supplied.
func (s *SCPRun) validateService() (bool, error) {
	if !checkSCPParameter(s.serviceType) {
		return false, ErrInvalidSCPType
	}
	return true, nil
}

func (s *SCPRun) getUsageData() error {
	usageData, err := loadScannerFile(s.scannerFilename)
	if err != nil {
		return err
	}
	s.usageData = usageData
	return nil
}

func (s *SCPRun) getReport() error {
	r, err := generateReport(s.usageData)
	if err != nil {
		return err
	}
	s.reports = r
	return nil
}

func (s *SCPRun) createPermissions() error {
	type fnEval = func(int64, int64) bool
	var apiFn fnEval

	switch s.serviceType {
	case "Allow":
		apiFn = greaterThan
	case "Deny":
		apiFn = lessThan
	}

	r := *s.reports
	permissionSet, err := generateList(s.thresholdLimit, &r[0], apiFn)
	if err != nil {
		return err
	}
	s.permissionSet = permissionSet
	return nil
}

func (s *SCPRun) formatServiceName() error {
	r := *s.reports
	u := &r[0].Results.Service

	s.serviceName = serviceName(*u)
	return nil
}

func (s *SCPRun) createSCP() error {
	s.scp = generateSCP(s.serviceType, s.serviceName, s.permissionSet)
	return nil
}

func (s *SCPRun) saveSCP() error {
	err := saveSCP(s.scp)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	conf, output, err := parseFlags(os.Args[0], os.Args[1:])
	if err == flag.ErrHelp {
		fmt.Fprintln(os.Stderr, exitFail)
	}

	r := new(conf)
	if err := run(r); err != nil {
		fmt.Fprintln(os.Stderr, exitFail)
	}

	fmt.Println(output)
}

func new(c *SCPConfig) *SCPRun {
	scpRun := SCPRun{scannerFilename: *c.scannerFilename(),
		serviceType:    *c.serviceType(),
		thresholdLimit: *c.thresholdLimit()}

	return &scpRun
}

// run is an abstraction function that allows
// us to test codebase.
func run(executionRun *SCPRun) error {
	_, err := executionRun.validateService()
	if err != nil {
		return err
	}

	err = executionRun.getUsageData()

	if err != nil {
		return err
	}

	err = executionRun.getReport()
	if err != nil {
		return err
	}

	err = executionRun.createPermissions()

	if err != nil {
		return err
	}

	err = executionRun.formatServiceName()

	if err != nil {
		return err
	}

	err = executionRun.createSCP()

	if err != nil {
		return err
	}

	err = executionRun.saveSCP()

	if err != nil {
		return err
	}
	return nil
}

// SCPConfig is a struct that will hold the
// flag values
type SCPConfig struct {
	SCPType     string
	ScannerFile string
	Threshold   int64
	args        []string
}

func parseFlags(progname string, args []string) (config *SCPConfig,
	output string, err error) {
	flags := flag.NewFlagSet(progname, flag.ContinueOnError)

	var buf bytes.Buffer
	var c SCPConfig

	flags.SetOutput(&buf)
	flag.StringVar(&c.SCPType, "type", "Allow", "can be either Allow or Deny")
	flag.StringVar(&c.ScannerFile, "fileloc", "./s3_usage.json", "file location of scanner usage report")
	flag.Int64Var(&c.Threshold, "threshold", 10, "decision threshold")

	err = flags.Parse(args)

	if err != nil {
		return nil, buf.String(), err
	}

	c.args = flags.Args()
	return &c, buf.String(), nil
}

// ServiceType returns the SCP Type parameter
func (s *SCPConfig) serviceType() *string {
	return &s.SCPType
}

//ScannerFilename returns the File.
func (s *SCPConfig) scannerFilename() *string {
	return &s.ScannerFile
}

func (s *SCPConfig) thresholdLimit() *int64 {
	return &s.Threshold
}

//Report represents a structure for a scp.
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

//SCP is a struct representing a AWS SCP document.
type SCP struct {
	Version   string `json:"Version"`
	Statement struct {
		Effect string `json:"Effect"`
		Action []string
	} `json:"Statement"`
	Resource string `json:"Resource"`
}

// ServiceName returns a formatted service name
// from event_source data.
func serviceName(eventSource string) string {
	s := strings.Split(eventSource, ".")
	return s[0]
}

//LoadScannerFile loads the scanner json report.
func loadScannerFile(scannerFileName string) ([]byte, error) {
	scannerData, err := loadFile(scannerFileName)
	if err != nil {
		return nil, ErrInvalidParameters
	}
	return scannerData, nil
}

// directoryCheck checks a directory for files to
// process.
func directoryCheck(directory string) (bool, error) {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return false, err
	}

	return true, nil
}

// GenerateReport will marshall the incoming json data
// from the scanner program into a struct.
func generateReport(jsonData []byte) (*[]Report, error) {
	var v []Report
	err := json.Unmarshal(jsonData, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// generateList a list of all the api calls
// That are above and equal to the threshold
func generateList(threshold int64, reportData *Report, apiEval func(int64, int64) bool) (map[string]int64, error) {
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

//greaterThan evaluates the value.
func greaterThan(value int64, threshold int64) bool {
	isGreaterThan := false
	if value >= threshold {
		isGreaterThan = true
	}
	return isGreaterThan
}

//lessThan evaluates the value.
func lessThan(value int64, threshold int64) bool {
	isLessThan := false
	if value < threshold {
		isLessThan = true
	}
	return isLessThan
}

//generateSCP generates an SCP.
func generateSCP(scpType string, awsService string, permissionData map[string]int64) (scp SCP) {
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

//saveSCP saves the scp file.
func saveSCP(scp SCP) error {
	jsonData, _ := json.MarshalIndent(scp, "", " ")
	err := saveSCPFile("testSCP.json", jsonData, 0644)
	return err
}

// checkSCPParameter checks that SCP parameter was
// Entered with correct value
func checkSCPParameter(scpType string) bool {
	s := strings.ToLower(scpType)
	if s == "allow" || s == "deny" {
		return true
	}
	return false
}
