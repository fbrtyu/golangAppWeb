package main

import (
	"log"
	"main/modules/auth"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	http.HandleFunc("/signup", auth.Reg)
	http.HandleFunc("/signin", auth.Login)
	http.HandleFunc("/profile", auth.Profile)

	log.Println("http server started on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
