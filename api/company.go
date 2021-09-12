package api

import (
	"context"
	"encoding/json"
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"
	db "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/validator.v2"
)

func CreateCompany(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	company := mod.Company{}

	dat := r.Context().Value("user-claim")
	if dat == nil {
		util.Log.Println("user-claim context is nil")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
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

	if tenent, ok := claims["tenent"]; ok {

		company.Tenent = tenent.(string)
		index := mongo.IndexModel{
			Keys:    bson.D{{"phone", 1}},
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
	} else {
		util.Log.Printf("Could not fetch Claims['tenet'] %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func DeleteCompanyById(w http.ResponseWriter, r *http.Request) {

}

func DeleteAllCompanies(w http.ResponseWriter, r *http.Request) {

}

func GetCompanyById(w http.ResponseWriter, r *http.Request) {

}

func GetCompanies(w http.ResponseWriter, r *http.Request) {

}
