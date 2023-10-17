package auth

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

var accessTokenSignature = []byte("secretAccess")
var refreshTokenSignature = []byte("secretRefresh")

func GenerateJWT(login string) (string, string) {

	claimsAccess := &jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": login,
	}

	claimsRefresh := &jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 2).Unix(),
		"iss": login,
	}

	tokenAccess := jwt.NewWithClaims(jwt.SigningMethodHS512, claimsAccess)
	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS512, claimsRefresh)

	accessToken, err := tokenAccess.SignedString([]byte(accessTokenSignature))
	if err != nil {
		panic(err)
	}

	refreshToken, err := tokenRefresh.SignedString([]byte(refreshTokenSignature))
	if err != nil {
		panic(err)
	}

	return accessToken, refreshToken
}

func GetJWT(login, password string) string {
	var ans string

	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/app")
	if err != nil {
		panic(err)
	}

	rows, err := db.Query("SELECT login, password, jwt FROM users WHERE login = ? and password = ?", login, password)
	if err != nil {
		ans = "Такого пользователя нет"
		panic(err)
	} else {
		defer db.Close()
		if !rows.Next() {
			ans = "Такого пользователя нет"
		} else {
			var user User
			err = rows.Scan(&user.Login, &user.Password, &user.JWT)
			if err != nil {
				panic(err)
			}

			ans = user.JWT
		}
	}
	return ans
}

func ValidateJWT(token string) bool {
	//secretKey := []byte("secretAccess")
	// parse the token and validate it
	tokenv, err := jwt.Parse(token, func(tokenv *jwt.Token) (interface{}, error) {
		// validate the signing algorithm
		if _, ok := tokenv.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tokenv.Header["alg"])
		}
		// return the secret key
		return accessTokenSignature, nil
	})
	// check if there was an error parsing or validating the token
	if err != nil {
		fmt.Println("Error parsing or validating token:", err)
		return false
	}
	// check if the token is valid
	if !tokenv.Valid {
		fmt.Println("Invalid token")
		return false
	} else {
		return true
	}
}
