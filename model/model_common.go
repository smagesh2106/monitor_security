package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	//User Types
	USER_ADMIN      string = "admin"
	USER_PROPRIETOR string = "proprietor"
	USER_GUARD      string = "guard"

	//Plan Types
	PLAN_FREE string = "FREE"
	PLAN_GOLD string = "GOLD"
)

var SubscriptionMap = make(map[string]SubscriptionInfo)

type SubscriptionInfo struct {
	CompaniesLimit int
	GuardsLimit    int
	ValidityMonths int
	Expiry         time.Time
	Expiry_HR      string
	IsValid        bool
}

func init() {
	SubscriptionMap["FREE"] = SubscriptionInfo{
		CompaniesLimit: 2,
		GuardsLimit:    4,
		ValidityMonths: 1,
		IsValid:        false,
	}
	SubscriptionMap["BRONZE"] = SubscriptionInfo{
		CompaniesLimit: 5,
		GuardsLimit:    20,
		ValidityMonths: 12,
		IsValid:        false,
	}
	SubscriptionMap["SILVER"] = SubscriptionInfo{
		CompaniesLimit: 10,
		GuardsLimit:    50,
		ValidityMonths: 12,
		IsValid:        false,
	}
	SubscriptionMap["GOLD"] = SubscriptionInfo{
		CompaniesLimit: 25,
		GuardsLimit:    150,
		ValidityMonths: 12,
		IsValid:        false,
	}
	SubscriptionMap["PLATINUM"] = SubscriptionInfo{
		CompaniesLimit: -1,
		GuardsLimit:    -1,
		ValidityMonths: 12,
		IsValid:        false,
	}

}

type Admin struct {
	Id       string `json:"id,omitempty" bson:"_id,omitempty"`
	Name     string `json:"name,omitempty" bson:"name,omitempty"`
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"`
	UserType string `validate:"regexp=^admin$ json:"usertype" bson:"usertype"`
}

type Proprietor struct {
	Id           primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent       string             `json:"tenent,omitempty" bson:"tenent"` //uuid
	Group        string             `validate:"min=3,max=25" json:"group" bson:"group"`
	Phone        string             `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password     string             `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	UserType     string             `validate:"regexp=^proprietor$" json:"usertype" bson:"usertype"`                //only proprietor
	Image        string             `json:"image,omitempty" bson:"image,omitempty"`
	Active       bool               `json:"active,omitempty" bson:"active"`
	Plan         string             `json:"plan,omitempty" bson:"plan"`
	Subscription SubscriptionInfo   `json:"subscription,omitempty" bson:"subscription"`
}

type Guard struct {
	Id         primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent     string             `validate:"nonzero,nonnil" json:"tenent" bson:"tenent"` //uuid
	Group      string             `json:"group" bson:"group"`
	Name       string             `validate:"min=3,max=25" json:"name" bson:"name"`
	Phone      string             `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password   string             `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	UserType   string             `validate:"regexp=^guard$" json:"usertype" bson:"usertype"`                     //only gurard are allowed
	Image      string             `json:"image,omitempty" bson:"image,omitempty"`
	Active     bool               `json:"active,omitempty" bson:"active"`
	Registered bool               `json:"registered,omitempty" bson:"registered"`
}

type AdminPasswordLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password"`
	UserType string `validate:"regexp=^admin$" json:"usertype"`
}

type ProprietorPasswordLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password"`
	UserType string `validate:"regexp=^proprietor$" json:"usertype"`
}

type GuardPasswordLogin struct {
	Tenent   string `validate:"nonzero,nonnil" json:"tenent"` //uuid
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password"`
	UserType string `validate:"regexp=^guard$" json:"usertype"`
}

type RegisterGuard struct {
	Phone string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
}

//-------
type TenentsToRegister struct {
	Tenents []TenentGroup `json:"tenents"`
}

type TenentGroup struct {
	Tenent string
	Group  string
}

type Company struct {
	Id      primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent  string             `json:"tenent,omitempty" bson:"tenent"` //uuid
	Name    string             `validate:"nonzero,nonnil" json:"name" bson:"name"`
	Address string             `validate:"nonzero,nonnil" json:"address" bson:"address"`
	Phone   string             `validate:"min=8,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Image   string             `json:"image,omitempty" bson:"image,omitempty"`
	//Add Patrol frequency
}

type Proprietors struct {
	Proprietors []Proprietor `json:"proprietors"`
}

type Companies struct {
	Companies []Company `json:"companies"`
}

type Guards struct {
	Guards []Guard `json:"guards"`
}

type Patrols struct {
	Patrols []Patrol `json:"patrols"`
}

type Incidents struct {
	Incidents []Incident `json:"incidents"`
}

type PasswordLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password"`
	UserType string `validate:"regexp=^(admin|proprietor|guard)$" json:"usertype"`
}

type AdminTokenData struct {
	Name     string
	Phone    string
	UserType string
}

type OwnerTokenData struct {
	Group    string
	Tenent   string
	Phone    string
	UserType string
}

type GuardTokenData struct {
	Group    string
	Tenent   string
	Name     string
	Phone    string
	UserType string
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Status string `json:"status"`
}

type Patrol struct {
	Id          string    `json:"id,omitempty" bson:"_id,omitempty"`
	Phone       string    `json:"phone" bson:"phone"`
	Name        string    `json:"name" bson:"name"`
	Tenent      string    `json:"tenent,omitempty" bson:"tenent"` //uuid
	CompanyId   string    `json:"companyid" bson:"companyid"`
	CompanyName string    `json:"companyname" bson:"companyname"`
	Date        time.Time `json:"-" bson:"date"`
	Date_HR     string    `json:"date_hr" bson:"date_hr"`
	Description string    `json:"description" bson:"description"`
	GPS         string    `validate:"nonzero,nonnil" json:"gps" bson:"gps"`
	RFData      string    `validate:"nonzero,nonnil" json:"rfdata" bson:"rfdata"`
}

type Incident struct {
	Id          string    `json:"id,omitempty" bson:"_id,omitempty"`
	Phone       string    `json:"phone" bson:"phone"`
	Name        string    `json:"name" bson:"name"`
	Tenent      string    `json:"tenent,omitempty" bson:"tenent"` //uuid
	CompanyId   string    `json:"companyid" bson:"companyid"`
	CompanyName string    `json:"companyname" bson:"companyname"`
	Date        time.Time `json:"-" bson:"date"`
	Date_HR     string    `json:"date_hr" bson:"date_hr"`
	Description string    `json:"description" bson:"description"`
	Media       []string  `json:"media" bson:"media"`
}

//-------------------------------------------------------------------------------------------------
type OtpLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Otp      string `validate:"min=6,max=6,regexp=^[0-9]+$" json:"otp"`
	UserType string `validate:"nonzero,nonnil" json:"usertype"`
}
