package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	api "github.com/monitor_security/api"
	mdb "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	util "github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/bson"
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
	defer mdb.Close_Mongo()

	go func() {
		for {
			CheckSubscription()
			time.Sleep(24 * time.Hour)
			//time.Sleep(10 * time.Second)
		}
	}()

	router := api.NewRouter()
	router.PathPrefix("/html").Handler(http.FileServer(http.Dir("./html/")))

	fs := http.FileServer(http.Dir("./media/"))
	router.PathPrefix("/media/").Handler(http.StripPrefix("/media/", fs))

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"})
	origins := handlers.AllowedOrigins([]string{"*"})

	log.Println("Running HTTP Server")
	serverPort := os.Getenv("SERVER_PORT")
	httpOnly := os.Getenv("HTTP_ONLY")
	httpEnabled, err := strconv.ParseBool(httpOnly)
	if err != nil {
		httpEnabled = false
	}
	log.Printf("HTTP only :%v", httpOnly)

	//log.Fatal(http.ListenAndServe(":8080", handlers.CORS(origins, headers, methods)(router)))
	if httpEnabled {
		log.Printf("Running in HTTP mode")
		log.Fatal(http.ListenAndServe(":"+serverPort, handlers.CORS(origins, headers, methods)(router)))
	} else {
		serverSSLPort := os.Getenv("SERVER_SSL_PORT")
		serverCrtFile := os.Getenv("SERVER_SSL_CERT")
		serverKeyFile := os.Getenv("SERVER_SSL_KEY")

		if _, err := os.Stat(serverKeyFile); os.IsNotExist(err) {
			log.Panic(err)
		}

		if _, err := os.Stat(serverCrtFile); os.IsNotExist(err) {
			log.Panic(err)
		}

		log.Printf("Running in HTTPS mode")
		log.Fatal(http.ListenAndServeTLS(":"+serverSSLPort, serverCrtFile, serverKeyFile, handlers.CORS(origins, headers, methods)(router)))
	}
}

/*
 *
 */
func CheckSubscription() {
	defer func() {
		if r := recover(); r != nil {
			util.Log.Println("Recovered in CheckSubscription :", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"active": true}
	cursor, err := mdb.ProprietorDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Check Subscription : Unable to find Business Groups: %v", err.Error())
		return
	}

	for cursor.Next(ctx) {
		tmp := mod.Proprietor{}
		cursor.Decode(&tmp)
		if tmp.Active == true && time.Now().Before(tmp.Subscription.Expiry) {
			util.Log.Println("Subscription Check -- Not expried yet  :" + tmp.Group)
		} else {
			util.Log.Println("Subscription Check -- CLEANUP  :" + tmp.Group)

			ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()

			filter := bson.M{"_id": tmp.Id}
			update := bson.M{"$set": bson.M{"active": false}}
			result := mdb.ProprietorDB.FindOneAndUpdate(ctx, filter, update)

			if result.Err() != nil {
				util.Log.Printf("Unable to deactivate group :" + result.Err().Error())
			}
		}
	}

}
