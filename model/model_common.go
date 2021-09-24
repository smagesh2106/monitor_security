package model

const (
	ADMIN      string = "admin"
	PROPRIETOR string = "proprietor"
	GUARD      string = "guard"
	VIDEO      string = "video"
	IMAGE      string = "image"
)

type User struct {
	Id        string `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent    string `json:"tenent,omitempty" bson:"tenent"` //uuid
	FirstName string `validate:"nonzero,nonnil" json:"firstname" bson:"firstname"`
	LastName  string `json:"lastname,omitempty" bson:"lastname,omitempty"`
	Phone     string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Password  string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	UserType  string `validate:"regexp=^(admin|proprietor|guard)$" json:"usertype" bson:"usertype"`  //only proprietor and gurard are allowed
	Image     string `json:"image,omitempty" bson:"image,omitempty"`
	Active    bool   `json:"active,omitempty" bson:"active"`
}

type Guard struct {
	Phone string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone" bson:"phone"`
}

/*
type Admin struct {
	Id        string `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent    string `json:"tenent,omitempty" bson:"tenent"` //uuid
	FirstName string `validate:"nonzero,nonnil" json:"firstName" bson:"firstname"`
	LastName  string `json:"lastName,omitempty" bson:"lastname,omitempty"`
	Phone     string `validate:"min=8,regexp=^\\+[0-9]+$" json:"phone" bson:"phone"`
	Password  string `validate:"min=8" json:"password" bson:"password"`
	UserType  string `json:"usertype,omitempty" bson:"usertype"`
	Image     string `json:"image,omitempty" bson:"image,omitempty"`
}

type Proprietor struct {
	Id        string   `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent    string   `json:"tenent,omitempty" bson:"tenent"` //uuid
	FirstName string   `validate:"nonzero,nonnil" json:"firstName" bson:"firstname"`
	LastName  string   `json:"lastName,omitempty" bson:"lastname,omitempty"`
	Phone     string   `validate:"min=8,max=15,regexp=^\\+[0-9]+$" json:"phone" bson:"phone"`
	Password  string   `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password" bson:"password"` //<FIXME> password chars
	Companies []string `json:"companies,omitempty" bson:"companies,omitempty"`
	UserType  string   `json:"usertype,omitempty" bson:"usertype"`
	Image     string   `json:"image,omitempty" bson:"image,omitempty"`
}

*/
type Company struct {
	Id      string `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent  string `json:"tenent,omitempty" bson:"tenent"` //uuid
	Name    string `validate:"nonzero,nonnil" json:"name" bson:"name"`
	Address string `validate:"nonzero,nonnil" json:"address" bson:"address"`
	Phone   string `validate:"min=8,regexp=^[0-9]+$" json:"phone" bson:"phone"`
	Image   string `json:"image,omitempty" bson:"image,omitempty"`
}

type Companies struct {
	Companies []Company `json:"companies"`
}

type Company_User struct {
	Id        string `json:"id,omitempty" bson:"_id,omitempty"`
	Tenent    string `json:"tenent,omitempty" bson:"tenent"` //uuid
	CompanyId string `validate:"nonzero,nonnil" json:"companyid" bson:"companyid"`
	UserId    string `validate:"nonzero,nonnil" json:"userid" bson:"userid"`
}

type Patrol struct {
	Id          string `json:"id,omitempty" bson:"_id,omitempty"`
	Phone       string `validate:"min=8,regex=^[0-9]+$" json:"phone" bson:"phone"`
	Tenent      string `validate:"nonzero,nonnil" json:"tenent" bson:"tenent"` //uuid
	CompanyId   string `validate:"nonzero,nonnil" json:"companyid" bson:"companyid"`
	Date        string `json:"date,omitempty" bson:"date,omitempty"`
	Description string `validate:"nonzero,nonnil" json:"description" bson:"description"`
	GPS         string `validate:"nonzero,nonnil" json:"gps" bson:"gps"`
	RFData      string `validate:"nonzero,nonnil" json:"rfdata" bson:"rfdata"`
}

type Incident struct {
	Id          string `json:"id,omitempty" bson:"_id,omitempty"`
	Phone       string `validate:"min=8,regex=^[0-9]+$" json:"phone" bson:"phone"`
	Tenent      string `validate:"nonzero,nonnil" json:"tenent" bson:"tenent"`       //uuid
	CompanyId   string `validate:"nonzero,nonnil" json:"companyid" bson:"companyid"` //uuid
	Date        string `json:"date,omitempty" bson:"date,omitempty"`
	Description string `validate:"nonzero,nonnil" json:"description" bson:"description"`
}

type Media struct {
	Id         string `json:"id,omitempty" bson:"_id,omitempty"`
	IncidentId string `validate:"nonzero,nonnil" json:"incidentid" json:"incidentid"`
	Type       string `json:"type,omitempty" bson:"type,omitempty"`
	URL        string `json:"url,omitempty" bson:"url,omitempty"`
}

type TokenData struct {
	Tenent   string
	Phone    string
	UserType string
}

type PasswordLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Password string `validate:"min=8,max=15,regexp=^[a-zA-Z0-9]+$" json:"password"`
	UserType string `validate:"regexp=^(admin|proprietor|guard)$" json:"usertype"`
}

type OtpLogin struct {
	Phone    string `validate:"min=8,max=15,regexp=^[0-9]+$" json:"phone"`
	Otp      string `validate:"min=6,max=6,regexp=^[0-9]+$" json:"otp"`
	UserType string `validate:"nonzero,nonnil" json:"usertype"`
}
