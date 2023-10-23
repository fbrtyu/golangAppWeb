package auth

import (
	"database/sql"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	Id       string `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	JWT      string `json:"jwt"`
}

// Создание хеша пароля
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

// Проверка пароля и хеша
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Reg(w http.ResponseWriter, r *http.Request) {
	fmt.Println("reg")
	//Настройка хедера для передачи токенов
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
<<<<<<< Updated upstream
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
=======
<<<<<<< HEAD
	w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:3000")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization") //withCredentials: true Set-Cookie
	c := http.Cookie{Name: "some", Value: "cookie"}
	http.SetCookie(w, &c)
=======
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
>>>>>>> e716e26d7b18f174f98f5fcbc411c9ad52a5b832
>>>>>>> Stashed changes
	r.ParseForm()

	hash, _ := HashPassword(r.FormValue("password1"))

	User := User{
		Login:    r.FormValue("login"),
		Password: hash,
		JWT:      r.FormValue("jwt"),
	}

	//Проверка паролей, поиск пользователя, если нет, то запись в БД
	if r.FormValue("password1") == r.FormValue("password2") {

		db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/app")
		if err != nil {
			panic(err)
		}

		rows, err := db.Query("SELECT id FROM users WHERE login = ?", r.FormValue("login"))
		if err != nil {
			panic(err)
		} else if !rows.Next() {
			//Если всё хорошо с БД, то генерация токенов. Логин - полезная нагрузка
			accessToken, refreshToken := GenerateJWT(r.FormValue("login"))
			//Добавление токенов в http, чтобы клиент автоматически установил их в куки
			cookieA := http.Cookie{Name: "accessToken", Value: accessToken, MaxAge: 3600}
			http.SetCookie(w, &cookieA)

			cookieR := http.Cookie{Name: "refreshToken", Value: refreshToken, MaxAge: 3600 * 2}
			http.SetCookie(w, &cookieR)

			res, err := db.Exec("INSERT INTO users (login, password, jwt) VALUES (?, ?, ?)", User.Login, User.Password, refreshToken)
			if err != nil {
				fmt.Println(res)
				panic(err)
			}

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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
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

	rows, err := db.Query("SELECT login, password, jwt FROM users WHERE login = ?", r.FormValue("login"))
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
			if CheckPasswordHash(r.FormValue("password"), User.Password) {
				//При повторном логине все токены обновляются
				accessToken, refreshToken := GenerateJWT(r.FormValue("login"))

				cookieA := http.Cookie{Name: "accessToken", Value: accessToken, MaxAge: 3600}
				http.SetCookie(w, &cookieA)

				cookieR := http.Cookie{Name: "refreshToken", Value: refreshToken, MaxAge: 3600 * 2}
				http.SetCookie(w, &cookieR)

				res, err := db.Exec("UPDATE users set jwt = ? WHERE login = ?", refreshToken, User.Login)
				if err != nil {
					fmt.Println(res)
					panic(err)
				}

				w.Write([]byte("LoginOk"))
				defer db.Close()
			} else {
				w.WriteHeader(404)
				w.Write([]byte("FailLogin"))
				defer db.Close()
			}
		}
	}
}

func Profile(w http.ResponseWriter, r *http.Request) {
	//Вывод страницы "профиля", если есть токены и они валидны
	fmt.Println("profile")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	r.ParseForm()

	fmt.Println(r.FormValue("accessToken"))

	if ValidateJWT(r.FormValue("accessToken")) {
		//Можно распарсить токен и узнать логин, чтобы далее вывести данные конкретного пользователя
		//Ниже в коде есть пример как достать логин из токена
		w.Write([]byte("True"))
	} else {
		w.Write([]byte("False"))
	}
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	fmt.Println("refreshtoken")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	r.ParseForm()

	//Тут валидания аксес токена
	//Парсинг логина из него и генерация новых токенов
	//По логину понимаем, кому в БД их менять и на какой логин делать новые
	if ValidateJWT(r.FormValue("accessToken")) {
		tokenString := r.FormValue("accessToken")
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(accessTokenSignature), nil
		})
		if err != nil {
			panic(err)
		}

		if v, found := claims["iss"]; found {
			fmt.Println(v)
			accessToken, refreshToken := GenerateJWT(v.(string))

			db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/app")
			if err != nil {
				panic(err)
			}

			cookieA := http.Cookie{Name: "accessToken", Value: accessToken, MaxAge: 3600, HttpOnly: true}
			http.SetCookie(w, &cookieA)

			cookieR := http.Cookie{Name: "refreshToken", Value: refreshToken, MaxAge: 3600 * 2, HttpOnly: true}
			http.SetCookie(w, &cookieR)

			res, err := db.Exec("UPDATE users set jwt = ? WHERE login = ?", refreshToken, v.(string))
			if err != nil {
				fmt.Println(res)
				panic(err)
			}

			w.Write([]byte("True"))
			defer db.Close()
		}
	} else {
		w.Write([]byte("False"))
	}
}
