package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	db "github.com/monitor_security/db"
	mod "github.com/monitor_security/model"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/monitor_security/util"
)

func TokenValidator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		valid, errMsg := util.ValidateToken(auth)

		if valid {
			cPtr, err := util.GetUserClaims(auth)
			if err != nil {
				util.Log.Printf("Unable to get user type : %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: err.Error()})
				return
			} else {
				r = r.WithContext(context.WithValue(r.Context(), "user-claim", cPtr))
				next.ServeHTTP(w, r)
			}
		} else {
			util.Log.Println("Invalid Token")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: errMsg})
			return

		}
	})
}

func IsAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user-claim").(jwt.MapClaims)
		utype, ok := claims["usertype"]
		p, ok1 := claims["phone"]
		if !ok || !ok1 {
			util.Log.Println("Check :Phone info, not found in token")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "phone info not found in token"})
			return
		}
		phone := p.(string)
		filter := bson.M{"phone": phone}

		if ok && utype == mod.USER_ADMIN {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var admin mod.Admin

			err := db.AdminDB.FindOne(ctx, filter).Decode(&admin)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Admin not found"})
				return
			}
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.USER_ADMIN)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
			return
		}
	})
}

func IsProprietor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user-claim").(jwt.MapClaims)
		utype, ok := claims["usertype"]
		t, ok1 := claims["tenent"]
		p, ok2 := claims["phone"]
		if !ok || !ok1 || !ok2 {
			util.Log.Println("Check :Tenent or Phone info, not found in token")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Tenent or phone info not found in token"})
			return
		}
		tenent := t.(string)
		phone := p.(string)
		filter := bson.M{"tenent": tenent, "active": true, "phone": phone}

		if utype == mod.USER_PROPRIETOR {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var propreitor mod.Proprietor
			err := db.ProprietorDB.FindOne(ctx, filter).Decode(&propreitor)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Group not found"})
				return
			}
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.USER_PROPRIETOR)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
			return
		}
	})
}

func IsGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user-claim").(jwt.MapClaims)
		utype, ok := claims["usertype"]
		t, ok1 := claims["tenent"]
		p, ok2 := claims["phone"]
		if !ok || !ok1 || !ok2 {
			util.Log.Println("Check :Tenent or Phone info, not found in token")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Tenent or phone info not found in token"})
			return
		}
		//Check if User is active
		tenent := t.(string)
		phone := p.(string)
		filter := bson.M{"phone": phone, "tenent": tenent, "active": true}

		if utype == mod.USER_GUARD {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var guard mod.Guard
			err := db.GuardDB.FindOne(ctx, filter).Decode(&guard)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
				return
			}
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.USER_GUARD)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
			return
		}
	})
}

func IsProprietorOrGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user-claim").(jwt.MapClaims)
		utype, ok := claims["usertype"]
		t, ok1 := claims["tenent"]
		p, ok2 := claims["phone"]
		if !ok || !ok1 || !ok2 {
			util.Log.Println("Check :Tenent or Phone info, not found in token")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Tenent or phone info not found in token"})
			return
		}
		tenent := t.(string)
		phone := p.(string)
		filter := bson.M{"phone": phone, "tenent": tenent, "active": true}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if utype == mod.USER_PROPRIETOR {
			var propreitor mod.Proprietor
			err := db.ProprietorDB.FindOne(ctx, filter).Decode(&propreitor)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Group not found"})
				return
			}
			next.ServeHTTP(w, r)
		} else if utype == mod.USER_GUARD {
			var guard mod.Guard
			err := db.GuardDB.FindOne(ctx, filter).Decode(&guard)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
				return
			}
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.USER_GUARD)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Insufficient Permission"})
			return
		}
	})
}

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		util.Log.Printf(
			"%s %s %s",
			r.Method,
			r.RequestURI,
			name,
		)
		inner.ServeHTTP(w, r)
	})
}

func IsSubscriptionValid(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		claims := r.Context().Value("user-claim").(jwt.MapClaims)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		t, ok := claims["tenent"]
		if !ok {
			util.Log.Println("Tenent info not found")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Tenent not found"})
			return
		}
		tenent := t.(string)
		filter := bson.M{"tenent": tenent, "active": true}
		var propreitor mod.Proprietor
		err := db.ProprietorDB.FindOne(ctx, filter).Decode(&propreitor)

		if err != nil {
			util.Log.Println("Subscription check failed :" + err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(mod.ErrorResponse{Error: "Subscription check, " + err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}
