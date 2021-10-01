package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	api "github.com/monitor_security/api"
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
	router := api.NewRouter()
	router.PathPrefix("/html").Handler(http.FileServer(http.Dir("./html/")))

	fs := http.FileServer(http.Dir("./media/"))
	router.PathPrefix("/media/").Handler(http.StripPrefix("/media/", fs))

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"})
	origins := handlers.AllowedOrigins([]string{"*"})

	log.Println("Running HTTP Server")

	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(origins, headers, methods)(router)))

	mdb.Close_Mongo()
}
