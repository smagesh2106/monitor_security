package util

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	mod "github.com/monitor_security/model"
)

var jwtKey = []byte("secret_key")

/*
 * Generate a fresh token or refresh existing token.
 */
func GenerateJWT(t interface{}) (string, error) {
	var token *jwt.Token

	if c, ok := t.(*mod.TokenData); ok {
		tok := jwt.New(jwt.SigningMethodHS256)
		claims := tok.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
		claims["tenent"] = c.Tenent
		claims["phone"] = c.Phone
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
				//w.WriteHeader(http.StatusUnauthorized)
				return "", fmt.Errorf("Invalid Signature")
			}
			if v, ok := err.(*jwt.ValidationError); ok {
				if v.Errors == jwt.ValidationErrorExpired {
					Log.Println("Token has expired, hence refresh....")
				} else if !token.Valid {
					//w.WriteHeader(http.StatusBadRequest)
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

func ValidateToken(t string) bool {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Wrong Singing algorithm")
		}
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		Log.Printf("Invalid token :%v", err)
		return false
	} else {
		Log.Println("Token is valid")
		return true
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
				Log.Println("Token has expired, hence refresh....")
			} else if !tok.Valid {
				return nil, fmt.Errorf("Malformed token.")
			}
		}
	}
	claims := tok.Claims.(jwt.MapClaims)
	if _, ok := claims["usertype"]; !ok {
		return nil, fmt.Errorf("Claims : Unknown user type")
	}
	if _, ok := claims["tenent"]; !ok {
		return nil, fmt.Errorf("Claims : Unknown tenent")
	}
	if _, ok := claims["phone"]; !ok {
		return nil, fmt.Errorf("Claims : Unknown phone")
	}

	return claims, nil
}
