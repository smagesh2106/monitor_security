package util

import (
	"log"
	"os"
)

var Log *log.Logger

func init() {
	Log = log.New(os.Stdout, "security-gaurd : ", log.LstdFlags)
}
