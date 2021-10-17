package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	db "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/validator.v2"
)

/*
 * Token Refresh
 */
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	tokenStr, err := util.GenerateJWT(auth)
	if err != nil {
		fmt.Printf("Err : %v\n", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Token Refreshed."})
}

/*
 * Proprietor Registration
 */
func RegisterProprietor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var user mod.Proprietor
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(user); err != nil {
		util.Log.Printf("Error input validation %v\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	util.Log.Println("Register : Proprietor")
	id, err := uuid.NewUUID()
	if err != nil {
		util.Log.Println("Error Generating uuid " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	user.Tenent = id.String()
	user.Active = true
	user.Plan = mod.PLAN_FREE

	subscription := mod.SubscriptionMap[mod.PLAN_FREE]
	mod.UpdateSubscription(&subscription)
	user.Subscription = subscription

	index := mongo.IndexModel{
		Keys:    bson.D{{"phone", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = db.ProprietorDB.Indexes().CreateOne(ctx, index)
	if err != nil {
		util.Log.Printf("Unable to create unique index : %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	_, err = db.ProprietorDB.InsertOne(ctx, user)
	if err != nil {
		util.Log.Printf("Unable to insert document : %v", err.Error())
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "User Registered, Pls login."})
}

/*
 * Proprietor Password Login
 */
func ProprietorPasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var login mod.ProprietorPasswordLogin

	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(login); err != nil {
		util.Log.Printf("Error input validation %v\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user mod.Proprietor
	err = db.ProprietorDB.FindOne(ctx, bson.M{"phone": login.Phone}).Decode(&user)
	if err != nil {
		util.Log.Printf("Unable to find user : %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "User NOT found, check phone, password, usertype"})
		return
	}

	//validate Password
	if login.Password != user.Password {
		util.Log.Printf("Password did not match : %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Password did not match."})
		return
	}

	tData := &mod.OwnerTokenData{
		UserType: user.UserType,
		Tenent:   user.Tenent,
		Phone:    user.Phone,
		Group:    user.Group,
	}
	tokenStr, err := util.GenerateJWT(tData)
	if err != nil {
		fmt.Printf("Err : %v\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Login Successful, token cookie returned."})
}

/*
 * Register a Guard
 */
func RegisterGuard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var user mod.Guard
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Validation Error " + err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(user); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Validation Error " + err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//User  = Guard ( make sure the user is created by Proprietor)
	util.Log.Println("Register : Guard")
	filter := bson.M{"phone": user.Phone, "tenent": user.Tenent, "active": true, "registered": false}
	update := bson.M{"$set": bson.M{"name": user.Name, "registered": true, "password": user.Password}}
	result := db.GuardDB.FindOneAndUpdate(ctx, filter, update)

	if result.Err() != nil {
		util.Log.Printf("Unable to register Gurard User, Guard user must be added by Proprietor to complete registration: %v", result.Err().Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "DB Error " + result.Err().Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Guard Successfully registered."})
}

/*
 * Guard Password Login
 */
func GuardPasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var login mod.GuardPasswordLogin

	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(login); err != nil {
		util.Log.Printf("Error input validation %v\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user mod.Guard
	//guard must be registered(true), and active( true )
	err = db.GuardDB.FindOne(ctx, bson.M{"phone": login.Phone, "tenent": login.Tenent, "registered": true, "active": true}).Decode(&user)
	if err != nil {
		util.Log.Printf("Unable to find user : %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "User NOT found, check phone, password, usertype, tenet"})
		return
	}

	//validate Password
	if login.Password != user.Password {
		util.Log.Printf("Password did not match : %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Password did not match."})
		return
	}

	tData := &mod.GuardTokenData{
		UserType: user.UserType,
		Tenent:   user.Tenent,
		Phone:    user.Phone,
		Name:     user.Name,
		Group:    user.Group,
	}
	tokenStr, err := util.GenerateJWT(tData)
	if err != nil {
		fmt.Printf("Err : %v\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Login Successful, token cookie returned."})
}

/*
 * Guard Logout
 */
func GuardLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	if dat == nil {
		util.Log.Println("user-claim context is nil")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Unable to parse token from request obj"})
		return
	}
	claims := dat.(jwt.MapClaims)

	t, ok1 := claims["tenent"]
	p, ok2 := claims["phone"]
	if !ok1 || !ok2 {
		util.Log.Println("Check :Tenent or Phone info, not found in token")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Tenent or phone info not found in token"})
		return
	}
	tenent := t.(string)
	phone := p.(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": tenent, "phone": phone}
	update := bson.M{"$set": bson.M{"registered": false}}

	result := db.GuardDB.FindOneAndUpdate(ctx, filter, update)
	if result.Err() != nil {
		util.Log.Printf("Unable to find user : %v", phone)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "User NOT found, check phone,  tenet"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Logout Successful, token cookie returned."})
}

/*
 * Admin Password Login
 */
func AdminPasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var login mod.AdminPasswordLogin

	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(login); err != nil {
		util.Log.Printf("Error input validation %v\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user mod.Admin
	err = db.AdminDB.FindOne(ctx, bson.M{"phone": login.Phone}).Decode(&user)
	if err != nil {
		util.Log.Printf("Unable to find user : %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "User NOT found, check phone, password, usertype"})
		return
	}

	//validate Password
	if login.Password != user.Password {
		util.Log.Printf("Password did not match : %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Password did not match."})
		return
	}

	tData := &mod.AdminTokenData{
		UserType: user.UserType,
		Phone:    user.Phone,
		Name:     user.Name,
	}
	tokenStr, err := util.GenerateJWT(tData)
	if err != nil {
		fmt.Printf("Err : %v\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Login Successful, token cookie returned."})
}
