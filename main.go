package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

const (
	exitFail = 1
)

// Package level vars to allow patch testing.
type (
	fileLoader func(filename string) ([]byte, error)
	writeSCP   func(filename string, data []byte, perm fs.FileMode) error
)

var (
	loadFile             fileLoader = ioutil.ReadFile
	saveSCPFile          writeSCP   = ioutil.WriteFile
	ErrInvalidParameters            = errors.New("input parameters missing")
	ErrInvalidThreshold             = errors.New("threshold limit must be greater than zero")
	ErrInvalidSCPType               = errors.New("scp type must be Allow or Deny")
)

type SCPRun struct {
	scannerFilename string
	serviceType     string
	serviceName     string
	thresholdLimit  int
	usageData       []byte
	reports         *[]Report
	permissionSet   map[string]int
	scp             SCP
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
	type fnEval = func(int, int) bool
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
	if err := run(os.Args, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitFail)
	}
}

func new(c *SCPConfig) *SCPRun {
	scpRun := SCPRun{
		scannerFilename: c.ScannerFile,
		serviceType:     c.SCPType,
		thresholdLimit:  c.Threshold,
	}

	return &scpRun
}

// run is an abstraction function that allows
// us to test codebase.
func run(args []string, errOutput io.Writer) error {
	conf, err := parseFlags(args, errOutput)
	if err != nil {
		return err
	}

	executionRun := new(conf)
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
// flag values.
type SCPConfig struct {
	SCPType     string
	ScannerFile string
	Threshold   int
	args        []string
}

func parseFlags(args []string, output io.Writer) (config *SCPConfig, err error) {
	var (
		policyType string
		file       string
		threshold  int
	)

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(output)

	flags.Func("file", "path to Platsec AWS Scanner output JSON", func(s string) error {
		file = s
		if _, err := os.Stat(file); err != nil {
			return err
		}

		return nil
	})

	flags.Func("type", "Allow or Deny", func(s string) error {
		policyType = s
		if !(policyType == "Allow" || policyType == "Deny") {
			return fmt.Errorf("policy type can be either 'Allow' or 'Deny'")
		}

		return nil
	})

	flags.Func("threshold", "Integer value which determines Action inclusion/exclusion", func(s string) error {
		threshold, err = strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("cannot convert threshold to an integer")
		}

		if threshold <= 0 {
			return fmt.Errorf("threshold has to be greater than zero")
		}

		return nil
	})

	if err = flags.Parse(args[1:]); err != nil {
		return nil, err
	}

	defaultsOutput := &bytes.Buffer{}

	flags.SetOutput(defaultsOutput)
	flags.PrintDefaults()

	if policyType == "" {
		return nil, fmt.Errorf("-type is a mandatory argument\n\nUsage of %s:\n%s", args[0], defaultsOutput.String())
	}

	if file == "" {
		return nil, fmt.Errorf("-file is a mandatory argument\n\nUsage of %s:\n%s", args[0], defaultsOutput.String())
	}

	if threshold == 0 {
		return nil, fmt.Errorf("-threshold is a mandatory argument\n\nUsage of %s:\n%s", args[0], defaultsOutput.String())
	}

	return &SCPConfig{SCPType: policyType, ScannerFile: file, Threshold: threshold}, nil
}

// Report represents a structure for a scp.
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
			Count     int    `json:"count"`
		} `json:"service_usage"`
	} `json:"results"`
}

// SCP is a struct representing a AWS SCP document.
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

// LoadScannerFile loads the scanner json report.
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
// That are above and equal to the threshold.
func generateList(threshold int, reportData *Report, apiEval func(int, int) bool) (map[string]int, error) {
	if threshold <= 0 {
		return nil, ErrInvalidThreshold
	}

	allowList := map[string]int{}
	for _, v := range reportData.Results.ServiceUsage {
		if apiEval(v.Count, threshold) {
			allowList[v.EventName] = v.Count
		}
	}
	return allowList, nil
}

// greaterThan evaluates the value.
func greaterThan(value int, threshold int) bool {
	isGreaterThan := false
	if value >= threshold {
		isGreaterThan = true
	}
	return isGreaterThan
}

// lessThan evaluates the value.
func lessThan(value int, threshold int) bool {
	isLessThan := false
	if value < threshold {
		isLessThan = true
	}
	return isLessThan
}

// generateSCP generates an SCP.
func generateSCP(scpType string, awsService string, permissionData map[string]int) (scp SCP) {
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

// saveSCP saves the scp file.
func saveSCP(scp SCP) error {
	jsonData, _ := json.MarshalIndent(scp, "", " ")
	err := saveSCPFile("testSCP.json", jsonData, 0644)
	return err
}
