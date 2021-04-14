package main

import (
	"flag"
	"fmt"
	platsec "github.com/platsec-scp-generator/scp"
	"os"
)

const (
	exitFail = 1
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, exitFail)
	}
}

//run is an abstraction function that allows
//us to test codebase.
func run() error {
	//Get Config
	c := platsec.SCPConfig{}
	c.Setup()
	flag.Parse()

	f := c.ScannerFilename()
	t := c.ServiceType()
	d := c.ThresholdLimit()

	if !platsec.CheckSCPParameter(*t) {
		return platsec.ErrInvalidSCPType
	}
	//Load the raw json data
	scannerData, err := platsec.LoadScannerFile(*f)

	if err != nil {
		return err
	}

	scannerReport, err := platsec.GenerateReport(scannerData)
	if err != nil {
		return err
	}
    type fnEval = func(int64, int64) bool

	var apiFn fnEval

	r := *scannerReport
	n := &r[0].Results.Service
	s := platsec.ServiceName(*n)

	switch *t {
	case "Allow":
		apiFn = platsec.GreaterThan
	case "Deny":
		apiFn = platsec.LessThan
	}

	listResults, err := platsec.GenerateList(*d,&r[0],apiFn)

	if err != nil {
		return err
	}

	SCPfile := platsec.GenerateSCP(*t, s, listResults)
	err = platsec.SaveSCP(SCPfile)

	if err != nil {
		return err
	}

	return nil
}
