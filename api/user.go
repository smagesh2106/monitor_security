package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"github.com/google/uuid"
	db "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	"github.com/monitor_security/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/validator.v2"
)

//Create a new user( Proprietor or Guard )
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var user mod.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validator.NewValidator().Validate(user); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Handle diff user types differntly
	if user.UserType == mod.PROPRIETOR {
		//User  = Proprietor
		id, err := uuid.NewUUID()
		if err != nil {
			util.Log.Println("Error Generating uuid")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user.Tenent = id.String()
		user.Active = true

		index := mongo.IndexModel{
			Keys:    bson.D{{"phone", 1}},
			Options: options.Index().SetUnique(true),
		}
		_, err = db.UserDB.Indexes().CreateOne(ctx, index)
		if err != nil {
			util.Log.Printf("Unable to create unique index : %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, err = db.UserDB.InsertOne(ctx, user)
		if err != nil {
			util.Log.Printf("Unable to insert document : %v", err)
			w.WriteHeader(http.StatusConflict)
			return
		}
	} else if user.UserType == mod.GUARD {
		//User  = Guard ( make sure the user is created by Proprietor)
		/*
			u := mod.User{}
			err = db.UserDB.FindOne(ctx, bson.M{"phone": user.Phone}).Decode(&u)
			if err != nil {
				util.Log.Printf("Unable to find the user : %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if u.Active == false {
		*/
		err := db.UserDB.FindOneAndUpdate(ctx, bson.M{"phone": user.Phone, "active": false}, user)
		if err != nil {
			util.Log.Printf("Unable to register Gurard User: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		/*
			} else {
				util.Log.Printf("Gurard User is already registered : %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		*/
	} else {
		//User  = Unknown User
		util.Log.Printf("Unknown user type : %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	/*
		tData := &mod.TokenData{
			UserType: user.UserType,
			Tenent:   user.Tenent,
			Phone:    user.Phone,
		}

		tokenStr, err := util.GenerateJWT(tData)
		if err != nil {
			fmt.Printf("Err : %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: tokenStr,
		})
	*/
	w.WriteHeader(http.StatusCreated)
}

/*
 * Password Login
 */
func PasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil
	var login mod.PasswordLogin

	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := validator.NewValidator().Validate(login); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user mod.User
	err = db.UserDB.FindOne(ctx, bson.M{"phone": login.Phone}).Decode(&user)
	if err != nil {
		util.Log.Printf("Unable to find user : %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if user.UserType == mod.GUARD && user.Active != true {
		util.Log.Printf("Gurard is not registered yet ")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//validate Password
	if login.Password != user.Password {
		util.Log.Printf("Password did not match : %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tData := &mod.TokenData{
		UserType: user.UserType,
		Tenent:   user.Tenent,
		Phone:    user.Phone,
	}
	tokenStr, err := util.GenerateJWT(tData)
	if err != nil {
		fmt.Printf("Err : %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})
	w.WriteHeader(http.StatusCreated)
}
