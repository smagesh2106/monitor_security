package api

import (
	"context"
	"encoding/json"
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

//Add a guard ( by Proprietor )
func AddGuard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	if dat == nil {
		util.Log.Println("user-claim context is nil")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims := dat.(jwt.MapClaims)

	var guard mod.RegisterGuard
	err := json.NewDecoder(r.Body).Decode(&guard)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validator.NewValidator().Validate(guard); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Create a user type Guard
	var user mod.Guard
	user.Phone = guard.Phone
	user.UserType = mod.GUARD
	user.Active = true // registered=false, guard yet to register.

	if tenent, ok := claims["tenent"]; !ok {
		util.Log.Printf("Unable to find tenent id : %v", tenent.(string))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user.Tenent = claims["tenent"].(string)
	user.Group = claims["group"].(string)
	user.Password = "123456789"
	index := mongo.IndexModel{
		Keys:    bson.D{{"phone", 1}, {"tenent", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = db.GuardDB.Indexes().CreateOne(ctx, index)
	if err != nil {
		util.Log.Printf("Unable to create unique index : %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = db.GuardDB.InsertOne(ctx, user)
	if err != nil {
		util.Log.Printf("Unable to insert document : %v", err)
		w.WriteHeader(http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

/*
 * Pull Valid Tenents for a Guard to register.
 */
func GetValidTenentsToRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	params := mux.Vars(r)
	phone := params["Phone"]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"phone": phone, "active": true, "registered": false}
	cursor, err := db.GuardDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find user : %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "User NOT found, check phone, password, usertype, tenet"})
		return
	}

	var c []mod.TenentGroup
	for cursor.Next(ctx) {
		tmp := mod.Guard{}
		cursor.Decode(&tmp)
		c = append(c, mod.TenentGroup{Group: tmp.Group, Tenent: tmp.Tenent})
	}

	json.NewEncoder(w).Encode(mod.TenentsToRegister{Tenents: c})
	w.WriteHeader(http.StatusOK)
}

func GetAllGuardsByOwner(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": claims["tenent"].(string)}
	cursor, err := db.GuardDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find guards: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Guard{}
	for cursor.Next(ctx) {
		tmp := mod.Guard{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var guards mod.Guards
	guards.Guards = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(guards)
}

func GetGuardById(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	params := mux.Vars(r)
	id := params["Id"]
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	var guard mod.Guard
	filter := bson.M{"_id": objID, "tenent": claims["tenent"].(string)}

	err = db.GuardDB.FindOne(ctx, filter).Decode(&guard)
	if err != nil {
		util.Log.Printf("Unable to find guard: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(guard)
}

func DeleteGuardById(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	params := mux.Vars(r)
	id := params["Id"]
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	filter := bson.M{"_id": objID, "tenent": claims["tenent"].(string)}

	result, err := db.GuardDB.DeleteOne(ctx, filter)
	if err != nil {
		util.Log.Printf("Unable to find guard: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

//------------------------------------------------------------------
