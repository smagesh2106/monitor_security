package api

import (
	"context"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	mod "github.com/monitor_security/model"
	"github.com/monitor_security/util"
)

func TokenValidator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if util.ValidateToken(auth) {
			cPtr, err := util.GetUserClaims(auth)
			if err != nil {
				util.Log.Printf("Unable to get user type : %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else {
				r = r.WithContext(context.WithValue(r.Context(), "user-claim", cPtr))
				util.Log.Printf("User type from context : %s", r.Context().Value("user-claim")) //r.Context().Value("user-type")
				next.ServeHTTP(w, r)
			}
		} else {
			util.Log.Println("Invalid Token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	})
}

func IsAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("user-claim").(jwt.MapClaims)

		//		u := r.Context().Value("user-type")
		utype, ok := claims["usertype"]
		if ok && utype == mod.ADMIN {
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.ADMIN)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	})
}

func IsProprietor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//dat := r.Context().Value("user-claim").(jwt.MapClaims)
		dat := r.Context().Value("user-claim")
		if dat == nil {
			util.Log.Println("user-claim context is nil")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims := dat.(jwt.MapClaims)
		utype, ok := claims["usertype"]
		if ok && utype == mod.PROPRIETOR {
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.PROPRIETOR)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	})
}

func IsGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("user-claim").(jwt.MapClaims)

		utype, ok := claims["usertype"]
		if ok && utype == mod.GUARD {
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.GUARD)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	})
}

func IsProprietorOrGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("user-claim").(jwt.MapClaims)

		utype, ok := claims["usertype"]
		if ok && (utype == mod.GUARD || utype == mod.PROPRIETOR) {
			next.ServeHTTP(w, r)
		} else {
			util.Log.Printf("Wrong user type Actual: %v, expected: %v", utype, mod.GUARD)
			w.WriteHeader(http.StatusUnauthorized)
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
