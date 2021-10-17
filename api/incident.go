package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

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

const UPLOAD_LIMIT int64 = 16777216

func CreateIncident(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	//fetch company id
	params := mux.Vars(r)
	id := params["Id"]
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Invalid ID " + err.Error()})
		return
	}
	// validate post data
	incident := mod.Incident{}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	err = json.NewDecoder(r.Body).Decode(&incident)
	if err != nil {
		util.Log.Printf("Invalid body :%v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Error " + err.Error()})
		return
	}
	if err := validator.NewValidator().Validate(incident); err != nil {
		util.Log.Printf("Error input validation %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: " Error " + err.Error()})
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
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "DB Error " + err.Error()})
		return
	}
	if name, ok := claims["name"]; ok {
		incident.Name = name.(string)
	} else {
		incident.Name = "Proprietor"
	}

	incident.Tenent = claims["tenent"].(string)
	incident.Phone = claims["phone"].(string)
	t := time.Now()
	incident.Date = t
	incident.Date_HR = t.Format(time.RFC1123)
	incident.CompanyId = id
	incident.CompanyName = company.Name
	incident.Media = []string{}

	//Add Patrol Data
	index := mongo.IndexModel{
		Keys:    bson.D{{"_id", 1}, {"tenent", 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err = db.IncidentDB.Indexes().CreateOne(ctx, index)
	if err != nil {
		util.Log.Printf("Unable to create unique index for company : %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "DB Error " + err.Error()})
		return
	}
	_, err = db.IncidentDB.InsertOne(ctx, incident)
	if err != nil {
		util.Log.Printf("Unable to insert Incident document : %v", err)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "DB Error " + err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Incident Successfully Created"})
}

func UpdateIncident(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	//fetch company id
	params := mux.Vars(r)
	id := params["Id"]
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		util.Log.Printf("Wrong Incident id: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "ID Error " + err.Error()})
		return
	}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)
	tenent := claims["tenent"].(string)

	//save files.
	err = r.ParseMultipartForm(UPLOAD_LIMIT) // 16MB grab the multipart form
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	data := []string{}
	formdata := r.MultipartForm // ok, no problem so far, read the Form data

	//get the *fileheaders
	files := formdata.File["files"] // grab the filenames

	for i, _ := range files { // loop through the files one by one
		file, err := files[i].Open()
		defer file.Close()
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}
		pwd, _ := os.Getwd()
		//<FIXME: Store under tenent dir>
		//dir := path.Join(pwd, "media", id) //orig
		dir := path.Join(pwd, "media", tenent, id)
		util.Log.Println("dir is , ", dir)
		err = os.MkdirAll(dir, os.ModePerm)

		if err == nil {
			//fileName := dir + "/" + files[i].Filename
			fileName := path.Join(dir, files[i].Filename)
			util.Log.Println("fileName is , ", fileName)
			out, err := os.Create(fileName)
			defer out.Close()
			if err != nil {
				util.Log.Printf("Error creating file :%v", err.Error())
			} else {
				_, err = io.Copy(out, file) // file not files[i] !

				if err != nil {
					util.Log.Printf("Error Copying file :%v", err.Error())
				} else {
					data = append(data, path.Join("media", tenent, id, files[i].Filename))
					//				data = append(data, fileName)
				}
			}

		} else {
			util.Log.Printf("Error Creating directory :%v", err.Error())
		}
	}
	if len(data) > 0 {
		//update the incident with image files.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{"_id": objID, "tenent": tenent}
		update := bson.M{"$addToSet": bson.M{"media": bson.M{"$each": data}}}
		result := db.IncidentDB.FindOneAndUpdate(ctx, filter, update)
		if result.Err() != nil {
			util.Log.Printf("Unable to update the list of image files to incident: %v", result.Err().Error())
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "DB Error " + result.Err().Error()})
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Files uploaded successfully."})
}

func GetAllIncidents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header()["Date"] = nil

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"tenent": claims["tenent"].(string)}
	cursor, err := db.IncidentDB.Find(ctx, filter)
	defer cursor.Close(ctx)

	if err != nil {
		util.Log.Printf("Unable to find incidents: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c := []mod.Incident{}
	for cursor.Next(ctx) {
		tmp := mod.Incident{}
		cursor.Decode(&tmp)
		c = append(c, tmp)
	}
	var incidents mod.Incidents
	incidents.Incidents = c

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(incidents)
}

func DeleteIncidentById(w http.ResponseWriter, r *http.Request) {
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
	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)
	t, ok := claims["tenent"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Unable to find group"})
		return
	}
	tenent := t.(string)

	filter := bson.M{"_id": objID, "tenent": tenent}

	//-------Delete Media files from filesystem first.------------
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	incident := mod.Incident{}
	err = db.IncidentDB.FindOne(ctx, filter).Decode(&incident)
	if err != nil {
		util.Log.Printf("Unable to find Incident: %v", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Unable to find Incident: " + id})
		return
	}

	pwd, _ := os.Getwd()
	f := path.Join(pwd, "media", tenent, id)
	util.Log.Printf("Deleting folder :%v\n", f)
	err = os.RemoveAll(f)
	if err != nil {
		util.Log.Printf("Unable to remove folder :" + err.Error())
	}
	//---------End----------

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	result := db.IncidentDB.FindOneAndDelete(ctx, filter)
	if result.Err() != nil {
		util.Log.Printf("Unable to find Incident: %v", result.Err().Error())
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Unable to find Incident: " + id})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mod.SuccessResponse{Status: "Successfully Incident Deleted"})
}
