package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"checks/internal/server"
)

func main() {
	handler := server.NewHandler(5 * time.Minute)

	port := ":8080"
	fmt.Printf("Starting server on %s\n", port)
	fmt.Println("Usage: curl http://localhost:8080/example.com")

	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal(err)
	}
}