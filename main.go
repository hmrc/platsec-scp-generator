package main

import (
	"fmt"
	"os"
	"flag"
	"github.com/platsec-scp-generator/utilities"
	platsec "github.com/platsec-scp-generator/scp"
)

func main() {

	//Get Config
	c := utilities.SCPConfig{}
	c.Setup()
	flag.Parse()

    f := c.GetScannerFilename()
    t := c.GetSCPType()
    d := c.GetThreshold()

    //Load the raw json data
	scannerData, err := platsec.LoadScannerFile(*f)

	if err != nil {
		os.Exit(1)
	}

	scannerReport, err :=platsec.GenerateReport(scannerData)
	if err != nil {
		os.Exit(1)
	}

	if *t == "Allow" {
		r := *scannerReport
		n := &r[0].Results.Service
		f := platsec.GetServiceName(*n)
        testAccount := &r[0].Account.AccountName
		fmt.Printf("***Debug Account Name: %s \n", *testAccount)
		allowList, err :=platsec.GenerateAllowList(*d, &r[0])
		if err != nil {
			os.Exit(1)
		}

		for k,v := range allowList{
			fmt.Printf("***Debug Key: %s Value: %v \n",k,v)
		}

		allowSCP :=platsec.GenerateSCP(*t,f,allowList)
		result, err :=platsec.SaveSCP(allowSCP)

		if err!=nil {
			os.Exit(1)
		}else{
			fmt.Printf("Report saved %v \n", result)
		}
	} else {
		r := *scannerReport
		n := &r[0].Results.Service
		f := platsec.GetServiceName(*n)
		testAccount := &r[0].Account.AccountName
		fmt.Printf("***Debug Account Name: %s \n", *testAccount)
		denyList, err :=platsec.GenerateDenyList(*d, &r[0])
		if err != nil {
			os.Exit(1)
		}

		for k,v := range denyList{
			fmt.Printf("***Debug Key: %s Value: %v \n",k,v)
		}

		allowSCP :=platsec.GenerateSCP(*t,f,denyList)
		result, err :=platsec.SaveSCP(allowSCP)

		if err!=nil {
			os.Exit(1)
		}else{
			fmt.Printf("Report saved %v \n", result)
		}

	}


}
