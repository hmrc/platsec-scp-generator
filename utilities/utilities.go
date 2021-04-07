package utilities

import (
	"flag"
)

//SCPConfig is a struct that will hold the
//flag values
type SCPConfig struct {
	SCPType string
	ScannerFile string
	Threshold int64
}

func (s *SCPConfig) Setup(){
	flag.StringVar(&s.SCPType, "type","Allow", "can be either Allow or Deny")
	flag.StringVar(&s.ScannerFile, "fileloc", "./s3_usage.json", "file location of scanner usage report")
	flag.Int64Var(&s.Threshold,"threshold", 10,"decision threshold")
}

func (s *SCPConfig) GetSCPType() *string {
	return &s.SCPType
}

func (s *SCPConfig) GetScannerFilename() *string {
	return &s.ScannerFile
}

func (s *SCPConfig) GetThreshold() * int64 {
	return &s.Threshold
}