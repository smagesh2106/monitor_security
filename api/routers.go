package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/monitor_security/util"
)

type Route struct {
	Name       string
	Method     string
	Pattern    string
	HandleFunc http.HandlerFunc
	Action     string
}

type Routes []Route

func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandleFunc
		if strings.Contains(route.Action, "RoleAdminValidation") {
			handler = IsAdmin(handler)
		}
		if strings.Contains(route.Action, "RoleProprietorValidation") {
			handler = IsProprietor(handler)
		}
		if strings.Contains(route.Action, "RoleGuardValidation") {
			handler = IsGuard(handler)
		}

		if strings.Contains(route.Action, "TokenValidation") {
			handler = TokenValidator(handler)
		}

		handler = Logger(handler, route.Name)
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}
	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello world!")
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	tokenStr, err := util.GenerateJWT(tokenStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: tokenStr,
	})
}

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/v1/",
		Index,
		"SkipValidation",
	},
	Route{
		"RegisterUser",
		"POST",
		"/v1/auth/register",
		RegisterUser,
		"SkipValidation",
	},
	Route{
		"PasswordLogin",
		"POST",
		"/v1/auth/loginpassword",
		PasswordLogin,
		"SkipValidation",
	},

	Route{
		"CreateCompany",
		"POST",
		"/v1/company",
		CreateCompany,
		"TokenValidation RoleProprietorValidation",
	},
}
