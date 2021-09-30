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

func AddCompany(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	company := mod.Company{}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	err := json.NewDecoder(r.Body).Decode(&company)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validator.NewValidator().Validate(company); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	company.Tenent = claims["tenent"].(string)
	index := mongo.IndexModel{
		Keys:    bson.D{{"name", 1}, {"tenent", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = db.CompanyDB.Indexes().CreateOne(ctx, index)
	if err != nil {
		util.Log.Printf("Unable to create unique index for company : %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = db.CompanyDB.InsertOne(ctx, company)
	if err != nil {
		util.Log.Printf("Unable to insert Company document : %v", err)
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func DeleteCompanyById(w http.ResponseWriter, r *http.Request) {
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

	result, err := db.CompanyDB.DeleteOne(ctx, filter)
	if err != nil {
		util.Log.Printf("Unable to find company: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func DeleteAllCompanies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": claims["tenent"].(string)}
	result, err := db.CompanyDB.DeleteMany(ctx, filter)

	if err != nil {
		util.Log.Printf("Unable to delete companies: %v", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(result)

}

func GetCompanyById(w http.ResponseWriter, r *http.Request) {
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

	var company mod.Company
	filter := bson.M{"_id": objID, "tenent": claims["tenent"].(string)}

	err = db.CompanyDB.FindOne(ctx, filter).Decode(&company)
	if err != nil {
		util.Log.Printf("Unable to find company: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(company)
}

func GetAllCompanies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": claims["tenent"].(string)}
	cursor, err := db.CompanyDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find companies: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Company{}
	for cursor.Next(ctx) {
		tmp := mod.Company{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var companies mod.Companies
	companies.Companies = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(companies)

}
