package util

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	mod "github.com/monitor_security/model"
)

var jwtKey = []byte("e0b1a2bc-1dfd-11ec-87f3-38baf832d723")

/*
 * Generate a fresh token or refresh existing token.
 */
func GenerateJWT(t interface{}) (string, error) {
	var token *jwt.Token

	if c, ok := t.(*mod.OwnerTokenData); ok {
		tok := jwt.New(jwt.SigningMethodHS256)
		claims := tok.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
		claims["tenent"] = c.Tenent
		claims["phone"] = c.Phone
		claims["usertype"] = c.UserType
		claims["group"] = c.Group

		token = tok
	} else if c, ok := t.(*mod.GuardTokenData); ok {
		tok := jwt.New(jwt.SigningMethodHS256)
		claims := tok.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
		claims["tenent"] = c.Tenent
		claims["phone"] = c.Phone
		claims["name"] = c.Name
		claims["usertype"] = c.UserType
		claims["group"] = c.Group

		token = tok
	} else if c, ok := t.(*mod.AdminTokenData); ok {
		tok := jwt.New(jwt.SigningMethodHS256)
		claims := tok.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
		claims["phone"] = c.Phone
		claims["name"] = c.Name
		claims["usertype"] = c.UserType
		token = tok
	} else if c, ok := t.(string); ok {
		tok, err := jwt.Parse(c, func(tk *jwt.Token) (interface{}, error) {
			if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
				return "", fmt.Errorf("Wrong Singing algorithm")
			}
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				return "", fmt.Errorf("Invalid Signature")
			}
			if v, ok := err.(*jwt.ValidationError); ok {
				if v.Errors == jwt.ValidationErrorExpired {
					Log.Println("Token has expired, hence refresh....")
				} else if !token.Valid {
					return "", fmt.Errorf("Malformed token.")
				}
			}
		}
		claims := tok.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
		token = tok
	} else {
		return "", fmt.Errorf("Unknown token")
	}

	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		Log.Println("Could not create a signed token")
		return "", err
	}
	return tokenStr, nil
}

func ValidateToken(t string) (bool, string) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Wrong Singing algorithm")
		}
		return jwtKey, nil
	})
	if err != nil {
		Log.Printf("Token validation error :%v", err.Error())
		return false, err.Error()
	} else if !token.Valid {
		Log.Printf("Tokken Validation Error")
		return false, "Invalid Token"
	} else {
		Log.Println("Token is valid")
		return true, "Token is valid"
	}
}

func GetUserClaims(t string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(t, func(tk *jwt.Token) (interface{}, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("Wrong Singing algorithm")
		}
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, fmt.Errorf("Invalid Signature")
		}
		if v, ok := err.(*jwt.ValidationError); ok {
			if v.Errors == jwt.ValidationErrorExpired {
				Log.Println("Token Expired")
				return nil, fmt.Errorf("Token is expired")
			} else if !tok.Valid {
				Log.Println("Malformed token")
				return nil, fmt.Errorf("Malformed token")
			}
		}
	}
	claims := tok.Claims.(jwt.MapClaims)
	if _, ok := claims["usertype"]; !ok {
		return nil, fmt.Errorf("Claims : Unknown user type")
	}
	if _, ok := claims["phone"]; !ok {
		return nil, fmt.Errorf("Claims : Unknown phone")
	}

	return claims, nil
}
