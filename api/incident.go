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
		return
	}
	if err := validator.NewValidator().Validate(incident); err != nil {
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
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: fmt.Errorf("Unable to create unique index: %v", err.Error()).Error()})
		return
	}
	result, err := db.IncidentDB.InsertOne(ctx, incident)
	if err != nil {
		util.Log.Printf("Unable to insert Incident document : %v", err)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(mod.ErrorResponse{Error: fmt.Errorf("Unable to add incident data: %v", err.Error()).Error()})
		return
	}
	json.NewEncoder(w).Encode(result)
	w.WriteHeader(http.StatusCreated)
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
		return
	}

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)
	tenent := claims["tenent"].(string)

	//save files.
	err = r.ParseMultipartForm(16777216) // 16MB grab the multipart form
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
		dir := path.Join(pwd, "media", id)
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
					data = append(data, path.Join("media", id, files[i].Filename))
				}
			}

		} else {
			util.Log.Printf("Error Creating directory :%v", err.Error())
		}

		//update the incident with image files.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		filter := bson.M{"_id": objID, "tenent": tenent}
		update := bson.M{"$addToSet": bson.M{"media": bson.M{"$each": data}}}
		result := db.IncidentDB.FindOneAndUpdate(ctx, filter, update)
		if result.Err() != nil {
			util.Log.Printf("Unable to update the list of image files to incident: %v", result.Err().Error())
			w.WriteHeader(http.StatusBadRequest)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dat := r.Context().Value("user-claim")
	claims := dat.(jwt.MapClaims)

	filter := bson.M{"_id": objID, "tenent": claims["tenent"].(string)}

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
