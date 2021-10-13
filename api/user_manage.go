package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"strconv"
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

/*
 * Add a guard ( by Proprietor )
 */
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
	user.UserType = mod.USER_GUARD
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
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.TenentsToRegister{Tenents: c})
}

/*
 * Get All Guards ( by Proprietor )
 */
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

/*
 * Get a guard by ID ( by Proprietor )
 */
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

/*
 * Delete a Guard by ID ( by Proprietor )
 */
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

	result := db.GuardDB.FindOneAndDelete(ctx, filter)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(result)
}

//------------------------------------------------------------------
/*
 * Get all Business Groups ( by Admin )
 */
func GetAllGroups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{}
	cursor, err := db.ProprietorDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find Business Groups: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Proprietor{}
	for cursor.Next(ctx) {
		tmp := mod.Proprietor{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var proprietors mod.Proprietors
	proprietors.Proprietors = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(proprietors)
}

/*
 * Get all Business Groups by Status (active:true/false) ( by Admin )
 */
func GetAllGroupsByStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	qVals := r.URL.Query()

	status, err := strconv.ParseBool(qVals["status"][0])

	if err != nil {
		status = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"active": status}
	cursor, err := db.ProprietorDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find Business Groups: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Proprietor{}
	for cursor.Next(ctx) {
		tmp := mod.Proprietor{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var proprietors mod.Proprietors
	proprietors.Proprietors = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(proprietors)
}

/*
 * Get Business Group by ID ( by Admin )
 */
func GetGroupById(w http.ResponseWriter, r *http.Request) {
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

	proprietor := mod.Proprietor{}
	filter := bson.M{"_id": objID}
	err = db.ProprietorDB.FindOne(ctx, filter).Decode(&proprietor)

	if err != nil {
		util.Log.Printf("Unable to find Business Group: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(proprietor)
}

/*
 * Delete Business Group by ID ( by Admin )
 */
func DeleteGroupById(w http.ResponseWriter, r *http.Request) {
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

	//---------
	go func() {
		//find the group
		util.Log.Println("DELETE Group : Find the Group")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		proprietor := mod.Proprietor{}
		filter := bson.M{"_id": objID}
		err = db.ProprietorDB.FindOne(ctx, filter).Decode(&proprietor)
		if err != nil {
			util.Log.Println("Unable to find the Business Group  :" + proprietor.Group)
			return
		}

		//delete guards
		util.Log.Println("DELETE Gurards")
		ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		filter1 := bson.M{"tenent": proprietor.Tenent}
		_, err := db.GuardDB.DeleteMany(ctx, filter1)
		if err != nil {
			util.Log.Println("Error deleting guards under Business Group  :" + proprietor.Group)
		}

		//delete patrols
		util.Log.Println("DELETE Patrol data")
		ctx, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel3()
		filter2 := bson.M{"tenent": proprietor.Tenent}
		_, err = db.PatrolDB.DeleteMany(ctx, filter2)
		if err != nil {
			util.Log.Println("Error deleting patrol data under Business Group  :" + proprietor.Group)
		}

		//delete incidents
		util.Log.Println("DELETE Incident data")
		ctx, cancel4 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel4()
		filter4 := bson.M{"tenent": proprietor.Tenent}
		_, err = db.IncidentDB.DeleteMany(ctx, filter4)
		if err != nil {
			util.Log.Println("Error deleting incident data under Business Group  :" + proprietor.Group)
		}

		//delete incident media.
		pwd, _ := os.Getwd()
		dir := path.Join(pwd, "media", proprietor.Tenent)
		err = os.RemoveAll(dir)
		if err != nil {
			util.Log.Printf("Error deleting incident media under Business Group %v, Err :%v :", proprietor.Group, err.Error())
		}
	}()
	//---------

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": objID}
	result := db.ProprietorDB.FindOneAndDelete(ctx, filter)

	if err != nil {
		util.Log.Printf("Unable to find Business Group: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(result)
}

/*
 * Update Subscription ( by Admin )
 */
func UpdateSubscriptionById(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	params := mux.Vars(r)
	groupid := params["Id"]
	plan := params["Plan"]
	objID, err := primitive.ObjectIDFromHex(groupid)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	subscription, ok := mod.SubscriptionMap[plan]
	if !ok {
		util.Log.Printf("Wrong plan in query: %v", plan)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	util.UpdateSubscription(&subscription)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": objID}
	update := bson.M{"$set": bson.M{"subscription": subscription}}
	result := db.ProprietorDB.FindOneAndUpdate(ctx, filter, update)

	if result.Err() != nil {
		util.Log.Printf("Unable to Update Business Group: %v", result.Err().Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Subscription successfully updated."})
}
