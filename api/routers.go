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
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK!")
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
	// Health check
	Route{
		"Index",
		"GET",
		"/v1/health",
		Index,
		"SkipValidation",
	},
	//------------------- Proprietor Register/Logins -----------------------
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
	//----------------- Guard Register/Login -------------------------------
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
	//----------------- Owner Operations w.r.t Guard -----------------------
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
	//----------------- Refresh token Owner or Guard -----------------------
	Route{
		"RefreshToken",
		"GET",
		"/v1/auth/token-refresh",
		RefreshToken,
		"SkipValidation",
	},
	//----------------- Owner operation w.r.t Company ----------------------
	Route{
		"AddCompany",
		"POST",
		"/v1/company",
		AddCompany,
		"TokenValidation RoleProprietorValidation",
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
	//--------------- Owner or Guard operations w.r.t Company --------------
	Route{
		"GetAllCompanies",
		"GET",
		"/v1/companies",
		GetAllCompanies,
		"TokenValidation RoleProprietorOrGuardValidation",
	},
	Route{
		"GetCompanyById",
		"GET",
		"/v1/company/{Id}",
		GetCompanyById,
		"TokenValidation RoleProprietorOrGuardValidation",
	},
	//------------ Patrol ( owner or guard ) ------------------------------
	Route{
		"AddPatrolData",
		"POST",
		"/v1/patrol/company/{Id}",
		AddPatrolData,
		"TokenValidation RoleProprietorOrGuardValidation",
	},
	Route{
		"GetAllPatrolDataByCompanyID",
		"GET",
		"/v1/patrol/company/{Id}",
		GetAllPatrolsByCompanyId,
		"TokenValidation RoleProprietorOrGuardValidation",
	},
}
