package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	rc := m.Run()
	if rc == 0 && testing.CoverMode() != "" {
		c := testing.Coverage()
		if c < .99 {
			fmt.Println("Tests passed but coverage failed at ", c)
			rc = -1
		}
	}
	os.Exit(rc)
}

// TestGenerateServiceName tests a service name can be
// created from the incoming scanner event_source.
func TestGenerateServiceName(t *testing.T) {
	eventSource := "s3.amazonaws.com"
	serviceName := serviceName(eventSource)
	assert.Equal(t, "s3", serviceName)
}

// TestLoadScannerReport tests that a scanner report can
// be loaded.
func TestLoadScannerValidReport(t *testing.T) {
	scannerFileName := "./testdata/s3_scanner_report.json"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte("It Worked"), nil
	}
	scannerFileData, _ := loadScannerFile(scannerFileName)

	loadFile = loadFileMock
	assert.True(t, len(scannerFileData) > 0)
}

// TestLoadScannerInValidReport tests that a scanner report can
// be loaded.
func TestLoadScannerInValidReport(t *testing.T) {
	scannerFileName := "./testdata/s3_scanner_report.json"
	loadFileMock := func(filename string) ([]byte, error) {
		return nil, ErrInvalidParameters
	}
	loadFile = loadFileMock
	_, err := loadScannerFile(scannerFileName)

	assert.NotNil(t, err)
}

// TestDirectorCheckTrue tests directoryCheck returns true for
// existing directory.
func TestDirectoryCheckTrue(t *testing.T) {
	directory := "../scp/"
	actual, _ := directoryCheck(directory)

	assert.True(t, true, actual)
}

// TestDirectoryCheckFalse test directoryCheck returns false for
// a non existent directory.
func TestDirectoryCheckFalse(t *testing.T) {
	directory := "../scpfalse/"
	expected := false

	actual, _ := directoryCheck(directory)

	assert.False(t, expected, actual)
}

// TestDecodeFile decodes the file to a map.
func TestDecodeFile(t *testing.T) {
	jsonData := getScannerMessage()
	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	reports, _ := generateReport(testData)
	report := *reports

	assert.NotNil(t, report)
	assert.Equal(t, 10, len(report[0].Results.ServiceUsage))
}

// TestDecodeFileError returns an error.
func TestDecodeFileError(t *testing.T) {
	jsonData := getCorruptedScannerMessage()
	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	_, err := generateReport(testData)
	assert.Error(t, err)
}

// TestGenerateAllowListData tests that
// API actions above a threshold are mapped to
// A new data structure.
func TestGenerateAllowListData(t *testing.T) {
	testData := getTestReport()
	r := *testData
	apiFn := greaterThan

	cases := []struct {
		threshold int
		report    Report
		expected  int
	}{
		{
			threshold: 10,
			report:    r[0],
			expected:  8,
		},
		{
			threshold: 100,
			report:    r[0],
			expected:  3,
		},
		{
			threshold: 3000,
			report:    r[0],
			expected:  0,
		},
	}

	for _, c := range cases {
		allowList, _ := generateList(c.threshold, &c.report, apiFn)
		assert.NotNil(t, allowList)
		assert.Equal(t, c.expected, int(len(allowList)))
	}
}

// TestGenerateDenyListData tests that
// API actions above a threshold are mapped to
// A new data structure.
func TestGenerateDenyListData(t *testing.T) {
	testData := getTestReport()
	r := *testData
	apiFn := lessThan

	cases := []struct {
		threshold int
		report    Report
		expected  int
	}{
		{
			threshold: 10,
			report:    r[0],
			expected:  2,
		},
		{
			threshold: 100,
			report:    r[0],
			expected:  7,
		},
		{
			threshold: 3000,
			report:    r[0],
			expected:  10,
		},
	}

	for _, c := range cases {
		denyList, _ := generateList(c.threshold, &c.report, apiFn)
		assert.NotNil(t, denyList)
		assert.Equal(t, c.expected, int(len(denyList)))
	}
}

// TestGenerateAllowListGeneratesError tests for
// An error being returned for zero and negative
// Thresholds.
func TestGenerateAllowListGeneratesError(t *testing.T) {
	testReports := getTestReport()
	testReport := *testReports
	apiFn := greaterThan

	cases := []struct {
		threshold int
		report    Report
		expected  error
	}{
		{
			threshold: 0,
			report:    testReport[0],
			expected:  ErrInvalidParameters,
		},
		{
			threshold: -1,
			report:    testReport[0],
			expected:  ErrInvalidParameters,
		},
	}

	for _, c := range cases {
		_, err := generateList(c.threshold, &c.report, apiFn)
		assert.Error(t, err)
	}
}

// TestGenerateAllowSCP test that we can
// generate an SCP from an Allow List.
func TestGenerateAllowSCP(t *testing.T) {
	allowList := getTestAllowListFilteredData()
	scpType := "Allow"
	awsService := "s3"
	generated := generateSCP(scpType, awsService, allowList)

	assert.Equal(t, "2012-10-17", generated.Version)
}

// TestSaveSCP tests that we can save an SCP report.
func TestSaveSCP(t *testing.T) {
	testSCP := getTestSCP("Allow", "S3")

	SCPSaved := saveSCP(testSCP)

	assert.Nil(t, SCPSaved)
}

// TestLoadScannerFileReturnsError test that an error is
// returned.
func TestLoadScannerFileReturnsError(t *testing.T) {
	testFile := "testFile"
	fileData, err := loadScannerFile(testFile)

	assert.NotNil(t, err)
	assert.Nil(t, fileData)
}

// TestSCPTypeParameterPass tests that we do not
// fail when we pass the correct parameter types.
func TestSCPTypeParameterPass(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{
			value:    "Allow",
			expected: true,
		},
		{
			value:    "Deny",
			expected: true,
		},
		{
			value:    "deny",
			expected: true,
		},
		{
			value:    "allow",
			expected: true,
		},
	}

	for _, c := range cases {
		actual := checkSCPParameter(c.value)
		assert.Equal(t, c.expected, actual)
	}
}

// TestSCPTypeParameterReturnsFalse tests that we do not
// fail when we pass the correct parameter types.
func TestSCPTypeParameterReturnsFalse(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{
			value:    "Allowime",
			expected: false,
		},
		{
			value:    "Denyme",
			expected: false,
		},
		{
			value:    "denyme",
			expected: false,
		},
		{
			value:    "allowme",
			expected: false,
		},
	}

	for _, c := range cases {
		actual := checkSCPParameter(c.value)
		assert.Equal(t, c.expected, actual)
	}
}

///TestValidateService test that validation returns true
//When the Service Type is valid.
func TestValidateServiceValidServiceType(t *testing.T) {
	testSCPRun := getTestSCPRun()
	actual, err := testSCPRun.validateService()
	if err != nil {
		t.Fatalf("TestValidateServiceValidServiceType failed")
	}

	assert.True(t, actual)
}

///TestValidateServiceFails test that validation returns an error
//When the Service Type is valid.
func TestValidateServiceInValidServiceType(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "InvalidType"
	actual, err := testSCPRun.validateService()

	assert.NotNil(t, err)
	assert.False(t, actual)
}

// TestGetUsageDataValidPath tests that the SCP Run
// can load a usage file.
func TestGetUsageDataValidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte("It Worked"), nil
	}
	loadFile = loadFileMock
	err := testSCPRun.getUsageData()
	assert.Nil(t, err)
}

// TestGetUsageDataInvalidPath tests that the SCP Run
// can load a usage file.
func TestGetUsageDataInvalidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	loadFileMock := func(filename string) ([]byte, error) {
		return nil, ErrInvalidParameters
	}
	loadFile = loadFileMock
	err := testSCPRun.getUsageData()
	assert.NotNil(t, err)
}

// TestGetReportValidPath test that the json data can be serialised.
func TestGetReportValidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	testSCPRun.getUsageData()

	err := testSCPRun.getReport()
	assert.Nil(t, err)
}

// TestGetReportInvalidPath test that the json data can be serialised.
func TestGetReportInvalidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	loadFileMock := func(filename string) ([]byte, error) {
		return nil, ErrInvalidParameters
	}
	loadFile = loadFileMock
	err := testSCPRun.getReport()
	assert.NotNil(t, err)
}

// TestCreatePermissionsValidPath tests that the permissions can be
// Created.
func TestCreatePermissionValidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	err := testSCPRun.createPermissions()
	assert.Nil(t, err)
}

// TestCreatePermissionsAlternateValidPath tests that the permissions can be
// Created.
func TestCreatePermissionAlternateValidPath(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "Deny"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	err := testSCPRun.createPermissions()
	assert.Nil(t, err)
}

// TestCreatePermissionsGeneratesErrorInvalidThresholds.
func TestCreatePermissionsGeneratesErrorInvalidThresholds(t *testing.T) {
	cases := []struct {
		threshold int
		expected  error
	}{
		{
			threshold: 0,
			expected:  ErrInvalidThreshold,
		},
		{
			threshold: -1,
			expected:  ErrInvalidThreshold,
		},
	}

	for _, c := range cases {
		testSCPRun := getTestSCPRun()
		testSCPRun.thresholdLimit = c.threshold
		testSCPRun.serviceType = "Deny"
		loadFileMock := func(filename string) ([]byte, error) {
			return []byte(getScannerMessage()), nil
		}
		loadFile = loadFileMock
		usageErr := testSCPRun.getUsageData()

		if usageErr != nil {
			t.Fatalf("Could not get usage information")
		}

		reportErr := testSCPRun.getReport()

		if reportErr != nil {
			t.Fatalf("Could not serialize data")
		}

		err := testSCPRun.createPermissions()
		assert.Equal(t, c.expected, err)
	}
}

// Returns a test SCP Run object.
func getTestSCPRun() SCPRun {
	testSCPRun := SCPRun{
		thresholdLimit:  10,
		scannerFilename: "testFile",
		serviceType:     "Allow",
	}
	return testSCPRun
}

// JSONFileDataStub.
type jsonFileStub struct {
	inputData string
}

// TestFormatServiceName tests that a service name was correctly
// Formatted.
func TestFormatServiceName(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "Deny"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	permErr := testSCPRun.createPermissions()

	if permErr != nil {
		t.Fatalf("Could Not Create Permissions")
	}

	err := testSCPRun.formatServiceName()

	assert.Nil(t, err)
}

// TestCreateSCP tests that an SCP can be created.
func TestCreateSCP_IntegrationTest(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "Deny"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	permErr := testSCPRun.createPermissions()

	if permErr != nil {
		t.Fatalf("Could Not Create Permissions")
	}

	fmtErr := testSCPRun.formatServiceName()

	if fmtErr != nil {
		t.Fatalf("Could Not Format Service Name")
	}

	err := testSCPRun.createSCP()

	assert.Nil(t, err)
}

// TestSaveSCPFile test saving a scp file.
func TestSaveSCPFile_IntegrationTest(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "Deny"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	saveFileMock := func(filename string, data []byte, perm fs.FileMode) error {
		return nil
	}
	saveSCPFile = saveFileMock

	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	permErr := testSCPRun.createPermissions()

	if permErr != nil {
		t.Fatalf("Could Not Create Permissions")
	}

	fmtErr := testSCPRun.formatServiceName()

	if fmtErr != nil {
		t.Fatalf("Could Not Format Service Name")
	}

	SCPerr := testSCPRun.createSCP()

	if SCPerr != nil {
		t.Fatalf("Could Not create SCP")
	}

	err := testSCPRun.saveSCP()

	assert.Nil(t, err)
}

// TestSaveSCPFileGeneratesError tests an error is
// Created.
func TestSaveSCPFileError_IntegrationTest(t *testing.T) {
	testSCPRun := getTestSCPRun()
	testSCPRun.serviceType = "Deny"
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	saveFileMock := func(filename string, data []byte, perm fs.FileMode) error {
		return errors.New("file could not be saved")
	}
	saveSCPFile = saveFileMock

	usageErr := testSCPRun.getUsageData()

	if usageErr != nil {
		t.Fatalf("Could not get usage information")
	}

	reportErr := testSCPRun.getReport()

	if reportErr != nil {
		t.Fatalf("Could not serialize data")
	}

	permErr := testSCPRun.createPermissions()

	if permErr != nil {
		t.Fatalf("Could Not Create Permissions")
	}

	fmtErr := testSCPRun.formatServiceName()

	if fmtErr != nil {
		t.Fatalf("Could Not Format Service Name")
	}

	SCPerr := testSCPRun.createSCP()

	if SCPerr != nil {
		t.Fatalf("Could Not create SCP")
	}

	err := testSCPRun.saveSCP()

	assert.NotNil(t, err)
}

// TestCreateRun creation of a scp run.
func TestCreateRun(t *testing.T) {
	conf := getTestConf()
	testRun := new(conf)
	assert.NotNil(t, testRun)
}

// TestRunEndToEnd_IntegrationTest tests complete run.
func TestRunEndToEnd_IntegrationTest(t *testing.T) {
	progName := "scpgenerator"
	configArg := []string{"testFile", "Deny", "10"}
	conf, _, _ := parseFlags(progName, configArg)
	testRun := new(conf)
	loadFileMock := func(filename string) ([]byte, error) {
		return []byte(getScannerMessage()), nil
	}
	loadFile = loadFileMock
	saveFileMock := func(filename string, data []byte, perm fs.FileMode) error {
		return nil
	}
	saveSCPFile = saveFileMock
	err := run(testRun)
	assert.Nil(t, err)
}

func (j jsonFileStub) getData() []byte {
	return []byte(j.inputData)
}

// getScannerMessage returns a full scanner message.
func getCorruptedScannerMessage() string {
	scannerMessage := `
[
   "rresults": {
      "event_source": "s3.amazon.com",
      "service_usage": [
        {
          "event_name": "ListObjectVersions",
          "count": 15
        },
        {
          "event_name": "ListObjects",
          "count": 224
        },
        {
          "event_name": "GetBucketEncryption",
          "count": 11
        },
        {
          "event_name": "CreateMultipartUpload",
          "count": 6
        },
        {
          "event_name": "GetObject",
          "count": 205
        },
        {
          "event_name": "GetBucketLifecycle",
          "count": 1
        },
        {
          "event_name": "ListBuckets",
          "count": 125
        },
        {
          "event_name": "GetBucketPolicy",
          "count": 19
        },
        {
          "event_name": "GetBucketVersioning",
          "count": 52
        },
        {
          "event_name": "PutObject",
          "count": 31
        }
      ]
    }
  }
]
`
	return scannerMessage
}

// getScannerMessage returns a full scanner message.
func getScannerMessage() string {
	scannerMessage := `
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some account"
    },
    "description": "AWS s3 service usage scan",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "event_source": "s3.amazon.com",
      "service_usage": [
        {
          "event_name": "ListObjectVersions",
          "count": 15
        },
        {
          "event_name": "ListObjects",
          "count": 224
        },
        {
          "event_name": "GetBucketEncryption",
          "count": 11
        },
        {
          "event_name": "CreateMultipartUpload",
          "count": 6
        },
        {
          "event_name": "GetObject",
          "count": 205
        },
        {
          "event_name": "tLifecycle",
          "count": 1
        },
        {
          "event_name": "ListBuckets",
          "count": 125
        },
        {
          "event_name": "GetBucketPolicy",
          "count": 19
        },
        {
          "event_name": "GetBucketVersioning",
          "count": 52
        },
        {
          "event_name": "PutObject",
          "count": 31
        }
      ]
    }
  }
]
`
	return scannerMessage
}

// getTestAllowListFilteredData returns a filtered data set.
func getTestAllowListFilteredData() map[string]int {
	filteredData := map[string]int{
		"LookupEvents":                     10,
		"ListTags":                         1656,
		"GetEventSelectors":                12,
		"BatchGetBuilds":                   223,
		"GetLambdaFunctionRecommendations": 2343,
		"DescribeSecurityGroups":           543,
		"DescribeVpcs":                     48,
		"ListStacks":                       348,
	}

	return filteredData
}

// getTestReport returns a report in the
// form of a serialised json document.
func getTestReport() *[]Report {
	jsonData := getScannerMessage()
	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	report, _ := generateReport(testData)
	return report
}

func getTestSCP(scpType string, awsService string) SCP {
	allowList := getTestAllowListFilteredData()
	testSCP := generateSCP(scpType, awsService, allowList)
	return testSCP
}

func getTestConf() *SCPConfig {
	scpConf := SCPConfig{SCPType: "Deny", ScannerFile: "TestFile", Threshold: 10}
	return &scpConf
}

func Test_parseFlags2(t *testing.T) {
	tests := []struct {
		name                string
		args                []string
		wantConfig          *SCPConfig
		wantOutputErrorLine string
		wantErr             bool
	}{
		{
			"valid arguments Allow",
			[]string{"program_name", "-file", "main_test.go", "-type", "Allow", "-threshold", "10"},
			&SCPConfig{SCPType: "Allow", ScannerFile: "main_test.go", Threshold: 10},
			"",
			false,
		},
		{
			"valid arguments Deny",
			[]string{"program_name", "-file", "main_test.go", "-type", "Deny", "-threshold", "10"},
			&SCPConfig{SCPType: "Deny", ScannerFile: "main_test.go", Threshold: 10},
			"",
			false,
		},
		{
			"invalid file",
			[]string{"program_name", "-file", "not-really-a-file", "-type", "Allow", "-threshold", "10"},
			nil,
			"invalid value \"not-really-a-file\" for flag -file: stat not-really-a-file: no such file or directory",
			true,
		},
		{
			"invalid type",
			[]string{"program_name", "-file", "main_test.go", "-type", "permit", "-threshold", "10"},
			nil,
			"invalid value \"permit\" for flag -type: policy type can be either 'Allow' or 'Deny'",
			true,
		},
		{
			"negative treshold",
			[]string{"program_name", "-file", "main_test.go", "-type", "Allow", "-threshold", "-99"},
			nil,
			"invalid value \"-99\" for flag -threshold: threshold has to be greater than zero",
			true,
		},
		{
			"treshold is not integer",
			[]string{"program_name", "-file", "main_test.go", "-type", "Allow", "-threshold", "ten"},
			nil,
			"invalid value \"ten\" for flag -threshold: cannot convert threshold to an integer",
			true,
		},
		{
			"invalid args",
			[]string{"program_name", "-Files", "main_test.go", "-type", "Allow", "-threshold", "10"},
			nil,
			"flag provided but not defined: -Files",
			true,
		},
		{
			"missing file arg",
			[]string{"program_name", "-type", "Allow", "-threshold", "10"},
			nil,
			"",
			true,
		},
		{
			"missing type arg",
			[]string{"program_name", "-file", "main_test.go", "-threshold", "10"},
			nil,
			"",
			true,
		},
		{
			"missing threshold arg",
			[]string{"program_name", "-file", "main_test.go", "-type", "Deny"},
			nil,
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			gotConfig, err := parseFlags2(tt.args, output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlags2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				t.Errorf("parseFlags2() = %+v, want %+v", gotConfig, tt.wantConfig)
			}
			if gotOutputErrorLine := strings.Split(output.String(), "\n")[0]; gotOutputErrorLine != tt.wantOutputErrorLine {
				t.Errorf("parseFlags2() = %v, want %v", gotOutputErrorLine, tt.wantOutputErrorLine)
			}
		})
	}
}
