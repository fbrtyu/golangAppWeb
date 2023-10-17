package auth

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

// Ключи для токенов
var accessTokenSignature = []byte("secretAccess")
var refreshTokenSignature = []byte("secretRefresh")

// Генерация токенов с определенными данными (время жизни и кому принадлежит)
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
	//Подпись токенов
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

func ValidateJWT(token string) bool {
	//Парсинг токена
	tokenv, err := jwt.Parse(token, func(tokenv *jwt.Token) (interface{}, error) {
		//Проверка алгоритма шифрования
		if _, ok := tokenv.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tokenv.Header["alg"])
		}
		//Тут секретный ключ для проверки токена
		return accessTokenSignature, nil
	})
	if err != nil {
		fmt.Println("Error parsing or validating token:", err)
		return false
	}
	if !tokenv.Valid {
		fmt.Println("Invalid token")
		return false
	} else {
		return true
	}
}
