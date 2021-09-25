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
		if strings.Contains(route.Action, "RoleProprietorOrGuardValidation") {
			handler = IsProprietorOrGuard(handler)
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
		"RegisterProprietor",
		"POST",
		"/v1/auth/register-proprietor",
		RegisterProprietor,
		"SkipValidation",
	},
	Route{
		"ProprietorPasswordLogin",
		"POST",
		"/v1/auth/login-proprietor-password",
		ProprietorPasswordLogin,
		"SkipValidation",
	},
	Route{
		"AddGuard",
		"POST",
		"/v1/guard",
		AddGuard,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"GetTenentsToRegisterForGuard",
		"GET",
		"/v1/auth/fetch-tenents/{Phone}",
		GetValidTenentsToRegister,
		"SkipValidation",
	},
	Route{
		"RegisterGuard",
		"POST",
		"/v1/auth/register-guard",
		RegisterGuard,
		"SkipValidation",
	},
	Route{
		"GuardPasswordLogin",
		"POST",
		"/v1/auth/login-guard-password",
		GuardPasswordLogin,
		"SkipValidation",
	},
	Route{
		"GetAllGuardsByOwner",
		"GET",
		"/v1/guards",
		GetAllGuardsByOwner,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"GetGuardById",
		"GET",
		"/v1/guard/{Id}",
		GetGuardById,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"DeleteGuardById",
		"DELETE",
		"/v1/guard/{Id}",
		DeleteGuardById,
		"TokenValidation RoleProprietorValidation",
	},

	Route{
		"AddCompany",
		"POST",
		"/v1/company",
		AddCompany,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"GetAllCompaniesByOwner",
		"GET",
		"/v1/companies/byproprietor",
		GetAllCompaniesByOwner,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"GetCompanyById",
		"GET",
		"/v1/company/{Id}",
		GetCompanyById,
		"TokenValidation RoleProprietorOrGuardValidation",
	},
	Route{
		"DeleteAllCompanies",
		"DELETE",
		"/v1/company",
		DeleteAllCompanies,
		"TokenValidation RoleProprietorValidation",
	},
	Route{
		"DeleteCompanyById",
		"DELETE",
		"/v1/company/{Id}",
		DeleteCompanyById,
		"TokenValidation RoleProprietorValidation",
	},
}
