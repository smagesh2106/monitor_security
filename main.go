package main

import (
	"fmt"
	"time"

	mdb "github.com/monitor_security/db"
	util "github.com/monitor_security/util"
)

func main() {

	fmt.Println("initialize....monitor...")
	label := false
	//Initialize mongodb and start.
	for {
		if label {
			break
		}
		err := mdb.Init_Mongo()
		if err != nil {
			util.Log.Printf("Error setting up mongoDB :%v", err)
			time.Sleep(5 * time.Second)
		} else {
			label = true
		}
	}
	mdb.Close_Mongo()
	fmt.Println("initialize....monitor...")
}
