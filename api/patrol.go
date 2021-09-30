package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	db "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/validator.v2"
)

func AddPatrolData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	//fetch company id
	params := mux.Vars(r)
	id := params["Id"]
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// validate post data
	patrol := mod.Patrol{}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	err = json.NewDecoder(r.Body).Decode(&patrol)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validator.NewValidator().Validate(patrol); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Validate the company and fetch company name
	var company mod.Company
	filter := bson.M{"_id": objID, "tenent": claims["tenent"].(string)}

	err = db.CompanyDB.FindOne(ctx, filter).Decode(&company)
	if err != nil {
		util.Log.Printf("Unable to find company: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: fmt.Errorf("Company not found: %v", id).Error()})
		return
	}
	patrol.Tenent = claims["tenent"].(string)
	patrol.Phone = claims["phone"].(string)
	patrol.CompanyId = id
	patrol.CompanyName = company.Name

	//Add Patrol Data
	index := mongo.IndexModel{
		Keys:    bson.D{{"_id", 1}, {"tenent", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = db.PatrolDB.Indexes().CreateOne(ctx, index)
	if err != nil {
		util.Log.Printf("Unable to create unique index for company : %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: fmt.Errorf("Unable to create unique index: %v", err.Error()).Error()})
		return
	}
	_, err = db.PatrolDB.InsertOne(ctx, patrol)
	if err != nil {
		util.Log.Printf("Unable to insert Company document : %v", err)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: fmt.Errorf("Unable to add patrol data: %v", err.Error()).Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func GetAllPatrolsByCompanyId(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	params := mux.Vars(r)
	id := params["Id"]
	_, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": claims["tenent"].(string), "companyid": id}
	cursor, err := db.PatrolDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find patrol data: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Patrol{}
	for cursor.Next(ctx) {
		tmp := mod.Patrol{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var patrols mod.Patrols
	patrols.Patrols = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(patrols)
}
