package auth

import (
	"database/sql"
	"fmt"
	"net/http"

	//"golang.org/x/crypto/bcrypt"
	//"github.com/dgrijalva/jwt-go"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	Id       string `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	JWT      string `json:"jwt"`
}

func Reg(w http.ResponseWriter, r *http.Request) {
	fmt.Println("reg")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:3000")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization") //withCredentials: true Set-Cookie
	r.ParseForm()

	User := User{
		Login:    r.FormValue("login"),
		Password: r.FormValue("password1"),
		JWT:      r.FormValue("jwt"),
	}

	if r.FormValue("password1") == r.FormValue("password2") {

		db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/app")
		if err != nil {
			panic(err)
		}

		rows, err := db.Query("SELECT id FROM users WHERE login = ?", r.FormValue("login"))
		if err != nil {
			panic(err)
		} else if !rows.Next() {

			accessToken, refreshToken := GenerateJWT(r.FormValue("login"))

			res, err := db.Exec("INSERT INTO users (login, password, jwt) VALUES (?, ?, ?)", User.Login, User.Password, refreshToken)
			if err != nil {
				fmt.Println(res)
				panic(err)
			}

			w.Header().Set("Authorization", accessToken)
			w.Write([]byte("RegOk"))
			defer db.Close()

		} else {
			w.WriteHeader(404)
			w.Write([]byte("FailReg"))
			defer db.Close()
		}
	} else {
		w.WriteHeader(404)
		w.Write([]byte("FailReg"))
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("login")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	//Access-Control-Expose-Headers:Content-Type, Allow, Authorization, X-Response-Time
	r.ParseForm()

	User := User{
		Login:    r.FormValue("login"),
		Password: r.FormValue("password"),
		JWT:      r.FormValue("jwt"),
	}

	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/app")
	if err != nil {
		panic(err)
	}

	rows, err := db.Query("SELECT login, password, jwt FROM users WHERE login = ? and password = ?", r.FormValue("login"), r.FormValue("password"))
	if err != nil {
		panic(err)
	} else {
		if !rows.Next() {
			w.WriteHeader(404)
			w.Write([]byte("FailLogin"))
			defer db.Close()
		} else {
			err = rows.Scan(&User.Login, &User.Password, &User.JWT)
			if err != nil {
				panic(err)
			}

			accessToken, refreshToken := GenerateJWT(r.FormValue("login"))

			res, err := db.Exec("UPDATE users set jwt = ? WHERE login = ?", refreshToken, User.Login)
			if err != nil {
				fmt.Println(res)
				panic(err)
			}

			w.Header().Set("Authorization", accessToken)
			w.Write([]byte("LoginOk"))
			defer db.Close()
		}
	}
}

func Profile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("profile")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	r.ParseForm()

	fmt.Println(r.FormValue("accessToken"))

	if ValidateJWT(r.FormValue("accessToken")) {
		w.Write([]byte("True"))
	} else {
		w.Write([]byte("False"))
	}
}
