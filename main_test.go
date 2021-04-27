package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	minimumCoverage := 90.0 // %

	if m.Run() == 0 && testing.CoverMode() != "" {
		realCoverage := testing.Coverage()
		if realCoverage < minimumCoverage/100 {
			fmt.Fprintf(os.Stderr, "Tests passed but coverage is below required %.1f%%\n", minimumCoverage)
			os.Exit(exitFail)
		}
	}
}

func Test_parseFlags(t *testing.T) {
	tests := []struct {
		name                string
		args                []string
		wantConfig          *Config
		wantOutputErrorLine string
		wantErr             bool
	}{
		{
			"valid arguments Allow",
			[]string{"program_name", "-file", "main_test.go", "-type", "Allow", "-threshold", "10"},
			&Config{policyType: "Allow", scannerFile: "main_test.go", threshold: 10},
			"",
			false,
		},
		{
			"valid arguments Deny",
			[]string{"program_name", "-file", "main_test.go", "-type", "Deny", "-threshold", "10"},
			&Config{policyType: "Deny", scannerFile: "main_test.go", threshold: 10},
			"",
			false,
		},
		{
			"invalid file",
			[]string{"program_name", "-file", "not-really-a-file", "-type", "Allow", "-threshold", "10"},
			nil,
			"invalid value \"not-really-a-file\" for flag -file: failed to find scanner output file: " +
				"stat not-really-a-file: no such file or directory",
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
			gotConfig, err := parseFlags(tt.args, output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlags() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				t.Errorf("parseFlags() = %+v, want %+v", gotConfig, tt.wantConfig)
			}
			if gotOutputErrorLine := strings.Split(output.String(), "\n")[0]; gotOutputErrorLine != tt.wantOutputErrorLine {
				t.Errorf("parseFlags() = %v, want %v", gotOutputErrorLine, tt.wantOutputErrorLine)
			}
		})
	}
}

func Test_loadServiceUsageReport(t *testing.T) {
	type args struct {
		file string
	}

	tests := []struct {
		name        string
		args        args
		wantService string
		wantUsage   []ServiceUsage
		wantErr     bool
	}{
		{
			"load valid file",
			args{"testdata/s3_usage.input.json"},
			"s3",
			[]ServiceUsage{{"ListBuckets", 145}, {"GetObject", 231}, {"GetBucketNotification", 1}},
			false,
		},
		{
			"fail to load not exiting file",
			args{"testdata/does-not-exist.json"},
			"",
			nil,
			true,
		},
		{
			"fail to load invalid JSON",
			args{"testdata/invalid.input.json"},
			"",
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotService, gotUsage, err := loadServiceUsageReport(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadServiceUsageReport() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if gotService != tt.wantService {
				t.Errorf("loadServiceUsageReport() gotService = %v, want %v", gotService, tt.wantService)
			}
			if !reflect.DeepEqual(gotUsage, tt.wantUsage) {
				t.Errorf("loadServiceUsageReport() gotUsage = %v, want %v", gotUsage, tt.wantUsage)
			}
		})
	}
}

func Test_generatePolicy(t *testing.T) {
	type args struct {
		config  *Config
		service string
		usage   []ServiceUsage
	}

	tests := []struct {
		name string
		args args
		want *SCP
	}{
		{
			"success for Allow over treshold 10 included",
			args{
				&Config{policyType: "Allow", threshold: 10},
				"s3",
				[]ServiceUsage{{"ListBuckets", 145}, {"GetObject", 10}, {"GetBucketNotification", 1}},
			},
			&SCP{
				Version: "2012-10-17",
				Statement: Statement{
					Effect:   "Allow",
					Resource: "*",
					Action:   []string{"s3:ListBuckets", "s3:GetObject"},
				},
			},
		},
		{
			"success for Deny over treshold 10 included",
			args{
				&Config{policyType: "Deny", threshold: 10},
				"s3",
				[]ServiceUsage{{"ListBuckets", 145}, {"GetObject", 10}, {"GetBucketNotification", 1}},
			},
			&SCP{
				Version: "2012-10-17",
				Statement: Statement{
					Effect:   "Deny",
					Resource: "*",
					Action:   []string{"s3:GetBucketNotification"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generatePolicy(tt.args.config, tt.args.service, tt.args.usage)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generatePolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSCP_String(t *testing.T) {
	type fields struct {
		Version   string
		Statement Statement
	}

	tests := []struct {
		name     string
		fields   fields
		wantFile string
	}{
		{
			"print policy as an indented JSON",
			fields{
				Version: "2012-10-17",
				Statement: Statement{
					Effect:   "Deny",
					Resource: "*",
					Action:   []string{"s3:GetBucketNotification"},
				},
			},
			"testdata/s3_usage_deny_10.golden.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := SCP{
				Version:   tt.fields.Version,
				Statement: tt.fields.Statement,
			}
			want, err := ioutil.ReadFile(tt.wantFile)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}
			if got := p.String(); got != string(want) {
				t.Errorf("SCP.String() = %v, want %v", got, string(want))
			}
		})
	}
}

func Test_run(t *testing.T) {
	type args struct {
		args []string
	}

	tests := []struct {
		name              string
		args              args
		wantStdOutputFile string
		wantErrOutputFile string
		wantErr           bool
	}{
		{
			"create Allow policy from valid input",
			args{[]string{"program_name", "-file", "testdata/s3_usage.input.json", "-type", "Allow", "-threshold", "10"}},
			"testdata/s3_usage_allow_10.golden.json",
			"",
			false,
		},
		{
			"create Deny policy from valid input",
			args{[]string{"program_name", "-file", "testdata/s3_usage.input.json", "-type", "Deny", "-threshold", "10"}},
			"testdata/s3_usage_deny_10.golden.json",
			"",
			false,
		},
		{
			"fail to load non-exiting file",
			args{[]string{"program_name", "-file", "testdata/does_not_exist.input.json", "-type", "Deny", "-threshold", "10"}},
			"",
			"testdata/does_not_exist.golden.txt",
			true,
		},
		{
			"fail to load invalid JSON",
			args{[]string{"program_name", "-file", "testdata/invalid.input.json", "-type", "Deny", "-threshold", "10"}},
			"",
			"", // error will be printed in main as it is post parsing
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdOutput := &bytes.Buffer{}
			errOutput := &bytes.Buffer{}
			wantStdOutput := ""
			wantErrOutput := ""
			if err := run(tt.args.args, stdOutput, errOutput); (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if tt.wantStdOutputFile != "" {
				content, err := ioutil.ReadFile(tt.wantStdOutputFile)
				if err != nil {
					t.Fatalf("failed to read fixture: %v", err)
				}
				wantStdOutput = string(content)
			}
			if gotStdOutput := stdOutput.String(); gotStdOutput != wantStdOutput {
				t.Errorf("run() = %v, want %v", gotStdOutput, wantStdOutput)
			}
			if tt.wantErrOutputFile != "" {
				content, err := ioutil.ReadFile(tt.wantErrOutputFile)
				if err != nil {
					t.Fatalf("failed to read fixture: %v", err)
				}
				wantErrOutput = string(content)
			}
			if gotErrOutput := errOutput.String(); gotErrOutput != wantErrOutput {
				t.Errorf("run() = %v, want %v", gotErrOutput, wantErrOutput)
			}
		})
	}
}
