package driver

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client
var ctx context.Context

var AdminDB *mongo.Collection
var ProprietorDB *mongo.Collection
var GuardDB *mongo.Collection
var CompanyDB *mongo.Collection

var IncidentDB *mongo.Collection
var PatrolDB *mongo.Collection

func Init_Mongo() error {

	//read mongo connection info from env.
	mongoHost := os.Getenv("MONGO_HOST")
	mongoPort := os.Getenv("MONGO_PORT")
	mongoAddr := strings.Join([]string{mongoHost, mongoPort}, ":")
	mongoUsername := os.Getenv("MONGO_USERNAME")
	mongoPassword := os.Getenv("MONGO_PASSWORD")
	database := os.Getenv("DB_NAME")
	mongoAuthSource := os.Getenv("MONGO_AUTHSOURCE")

	mongourl := "mongodb://" + mongoAddr + "/" + database + "?ssl=false"
	clientOptions := options.Client().ApplyURI(mongourl).
		SetAuth(options.Credential{
			AuthSource: mongoAuthSource, Username: mongoUsername, Password: mongoPassword,
		}) //.SetTLSConfig(tlsConfig) //.SetReplicaSet("rs0")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	Client, _ = mongo.Connect(ctx, clientOptions)
	err := Client.Ping(ctx, nil)
	if err != nil {
		util.Log.Printf("mongo connection error %v", err)
		return err
	}
	AdminDB = Client.Database("testdb").Collection("admins")
	ProprietorDB = Client.Database("testdb").Collection("proprietors")
	GuardDB = Client.Database("testdb").Collection("guards")
	CompanyDB = Client.Database("testdb").Collection("companies")
	IncidentDB = Client.Database("testdb").Collection("incidents")
	PatrolDB = Client.Database("testdb").Collection("patrols")

	util.Log.Println("done mongodb init ....")
	return nil
}

func Close_Mongo() {
	if ctx != nil {
		Client.Disconnect(ctx)
	}
}
