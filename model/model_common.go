package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	ADMIN      string = "admin"
	PROPRIETOR string = "proprietor"
	GUARD      string = "guard"
	VIDEO      string = "video"
	IMAGE      string = "image"
)

type Proprietor struct {
	Id       primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent   string             `json:"tenent,omitempty" bson:"tenent"` //uuid
	Group    string             `validate:"min=3,max=25" json:"group" bson:"group"`
	Phone    string             `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password string             `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	UserType string             `validate:"regexp=^proprietor$" json:"usertype" bson:"usertype"`                //only proprietor and gurard are allowed
	Image    string             `json:"image,omitempty" bson:"image,omitempty"`
	Active   bool               `json:"active,omitempty" bson:"active"`
}

type Guard struct {
	Id         primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent     string             `validate:"nonzero,nonnil" json:"tenent" bson:"tenent"` //uuid
	Group      string             `json:"group" bson:"group"`
	Name       string             `validate:"min=3,max=25" json:"name" bson:"name"`
	Phone      string             `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password   string             `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	UserType   string             `validate:"regexp=^guard$" json:"usertype" bson:"usertype"`                     //only proprietor and gurard are allowed
	Image      string             `json:"image,omitempty" bson:"image,omitempty"`
	Active     bool               `json:"active,omitempty" bson:"active"`
	Registered bool               `json:"registered,omitempty" bson:"registered"`
}

type Admin struct {
	Id       string `json:"id,omitempty" bson:"_id,omitempty"`
	Name     string `validate:"min=3,max=25" json:"name" bson:"name"`
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"`
	UserType string `validate:"regexp=^admin$ json:"usertype" bson:"usertype"`
	Image    string `json:"image,omitempty" bson:"image,omitempty"`
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
	Tenent      string    `json:"tenent,omitempty" bson:"tenent"` //uuid
	CompanyId   string    `json:"companyid" bson:"companyid"`
	CompanyName string    `json:"companyname" bson:"companyname"`
	Date        time.Time `json:"date" bson:"date"`
	Date_HR     string    `json:"date_hr" bson:"date_hr"`
	Description string    `json:"description" bson:"description"`
	GPS         string    `validate:"nonzero,nonnil" json:"gps" bson:"gps"`
	RFData      string    `validate:"nonzero,nonnil" json:"rfdata" bson:"rfdata"`
}

//-------------------------------------------------------------------------------------------------

type Incident struct {
	Id          string    `json:"id,omitempty" bson:"_id,omitempty"`
	Phone       string    `json:"phone" bson:"phone"`
	Tenent      string    `json:"tenent,omitempty" bson:"tenent"` //uuid
	CompanyId   string    `json:"companyid" bson:"companyid"`
	CompanyName string    `json:"companyname" bson:"companyname"`
	Date        time.Time `json:"date" bson:"date"`
	Date_HR     string    `json:"date_hr" bson:"date_hr"`
	Description string    `json:"description" bson:"description"`
	Media       []string  `json:"media" bson:"media"`
}

type OtpLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Otp      string `validate:"min=6,max=6,regexp=^[0-9]+$" json:"otp"`
	UserType string `validate:"nonzero,nonnil" json:"usertype"`
}
