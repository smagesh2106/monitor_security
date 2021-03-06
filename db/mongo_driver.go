package driver

import (
	"context"
	"time"

	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client
var ctx context.Context

var UserDB *mongo.Collection //<FIXME: Delete>

var ProprietorDB *mongo.Collection
var GuardDB *mongo.Collection
var CompanyDB *mongo.Collection

var IncidentDB *mongo.Collection
var PatrolDB *mongo.Collection

func Init_Mongo() error {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017/?ssl=false").
		SetAuth(options.Credential{
			AuthSource: "testdb", Username: "user1", Password: "passw0rd",
		})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	Client, _ = mongo.Connect(ctx, clientOptions)
	err := Client.Ping(ctx, nil)
	if err != nil {
		util.Log.Printf("mongo connection error %v", err)
		return err
	}

	UserDB = Client.Database("testdb").Collection("users") // <FIXME :Delete>

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
