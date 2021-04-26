package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

const (
	exitFail = 1
	allow    = "Allow"
	deny     = "Deny"
)

func main() {
	if err := run(os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitFail)
	}
}

func run(args []string, stdOutput, errOutput io.Writer) error {
	config, err := parseFlags(args, errOutput)
	if err != nil {
		return err
	}

	service, usage, err := loadServiceUsageReport(config.scannerFile)
	if err != nil {
		return err
	}

	fmt.Fprint(stdOutput, generatePolicy(config, service, usage))

	return nil
}

// Config is a struct that will hold the
// flag values.
type Config struct {
	policyType  string
	scannerFile string
	threshold   int
}

func generatePolicy(config *Config, service string, usage []ServiceUsage) *SCP {
	actions := []string{}

	for _, record := range usage {
		if config.policyType == allow && record.Count >= config.threshold {
			actions = append(actions, fmt.Sprintf("%s:%s", service, record.EventName))
		}

		if config.policyType == deny && record.Count < config.threshold {
			actions = append(actions, fmt.Sprintf("%s:%s", service, record.EventName))
		}
	}

	return &SCP{
		Version: "2012-10-17",
		Statement: Statement{
			Effect:   config.policyType,
			Resource: "*",
			Action:   actions,
		},
	}
}

func loadServiceUsageReport(file string) (service string, usage []ServiceUsage, err error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read content of %s, got: %w", file, err)
	}

	var report []Report
	if err := json.Unmarshal(content, &report); err != nil {
		return "", nil, fmt.Errorf("failed to parse content of %s, got: %w", file, err)
	}

	return strings.Split(report[0].Results.Service, ".")[0], report[0].Results.ServiceUsage, nil
}

func parseFlags(args []string, output io.Writer) (config *Config, err error) {
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
		if !(policyType == allow || policyType == deny) {
			return fmt.Errorf("policy type can be either 'Allow' or 'Deny'")
		}

		return nil
	})

	flags.Func("threshold", "integer value which determines Action inclusion/exclusion", func(s string) error {
		threshold, err = strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("cannot convert threshold to an integer")
		}

		if threshold <= 0 {
			return fmt.Errorf("threshold has to be greater than zero")
		}

		return nil
	})

	if err := flags.Parse(args[1:]); err != nil {
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

	return &Config{policyType: policyType, scannerFile: file, threshold: threshold}, nil
}

type ServiceUsage struct {
	EventName string `json:"event_name"`
	Count     int    `json:"count"`
}

// Report represents a structure for a scp.
type Report struct {
	Results struct {
		Service      string         `json:"event_source"`
		ServiceUsage []ServiceUsage `json:"service_usage"`
	} `json:"results"`
}

type Statement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// SCP is a struct representing a AWS SCP document.
type SCP struct {
	Version   string    `json:"Version"`
	Statement Statement `json:"Statement"`
}

func (p SCP) String() string {
	jsonData, _ := json.MarshalIndent(p, "", "  ")

	return fmt.Sprintln(string(jsonData))
}
