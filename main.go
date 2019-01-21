package main

import (
	"encoding/json"
	"errors"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Used by Http server

const (
	PORT   = "1337"
	SECRET = "42isTheAnswer"
)

// Used for JWT authentication

type JWTData struct {
	// Standard claims are the standard jwt claims from the IETF standard
	// https://tools.ietf.org/html/rfc7519
	jwt.StandardClaims
	CustomClaims map[string]string `json:"custom,omitempty"`
}

// Structure to store stats card data

type Stats struct {
	Type       string `json:"type"`
	Icon       string `json:"icon"`
	Title      string `json:"title"`
	Value      string `json:"value"`
	FooterText string `json:"footerText"`
	FooterIcon string `json:"footerIcon"`
}

//Function to generate random number

func random(min uint64, max uint64) uint64 {
	return uint64(rand.Intn(int(max)-int(min)) + int(min))
}

// Main entry point for program

func main() {

	mux := mux.NewRouter() // Create new Gorilla mux router

	// Specify the routes

	mux.HandleFunc("/login", login).Methods("POST")
	mux.Path("/statscards/capacity").Queries("fromDate", "{filter1}", "toDate", "{filter2}").HandlerFunc(GetCapacityData)

	//Setup CORS to enable SPA to talk to Go server

	c := cors.New(cors.Options{
		AllowedHeaders: []string{"X-Requested-With", "Content-Type", "Authorization"},
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "HEAD", "OPTIONS"},
	})

	handler := c.Handler(mux)

	log.Println("Listening for connections on port: ", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
}

// HTTP Handler to process login request
// This function authenticates incoming API request that contains email and password. If login is successful, it sends back JWT token as part of response, which is to be included by every subsequent request from client for that user.

func login(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	// Demo - in real case scenario you'd check this against your database
	if userData["email"] == "john@smith.com" && userData["password"] == "mypassword" {
		claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},

			CustomClaims: map[string]string{
				"userid": "u1",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(SECRET))
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
		}

		json, err := json.Marshal(struct {
			Token string `json:"token"`
		}{
			tokenString,
		})

		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
		}

		w.Write(json)
	} else {
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}
}

// HTTP handler to generate random capacity data. This API request should be accompanied by valid JWT token that hasn't expired.

func GetCapacityData(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("Inside GetCapacityData")
	authToken := r.Header.Get("Authorization")
	authArr := strings.Split(authToken, " ")

	if len(authArr) != 2 {
		log.Println("Authentication header is invalid: " + authToken)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
	}

	jwtToken := authArr[1]

	claims, err := jwt.ParseWithClaims(jwtToken, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodHS256 != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}
		return []byte(SECRET), nil
	})

	if err != nil {
		log.Println(err)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
	}

	data := claims.Claims.(*JWTData)

	userID := data.CustomClaims["userid"]

	// fetch some data based on the userID and then send that data back to the user in JSON format
	vars := mux.Vars(r)

	fromU64, _ := strconv.ParseUint(strings.TrimSpace(vars["filter1"]), 10, 64)
	toU64, _ := strconv.ParseUint(strings.TrimSpace(vars["filter2"]), 10, 64)

	//fmt.Printf("fromu64 is %d/n", fromU64)
	//fmt.Printf("tou64 is %d/n", toU64)

	randomNum := random(fromU64, toU64)

	fmt.Printf("Random Num: %d/n", randomNum)

	randCapacity := strconv.FormatUint(randomNum, 10)
	randCapacity = randCapacity[len(randCapacity)-3:] + "GB"

	jsonData, err := getCapacityData(randCapacity, userID)
	if err != nil {
		log.Println(err)
		http.Error(w, "Request failed!", http.StatusUnauthorized)
	}

	w.Write(jsonData)
}

// Supporting function to format the capacity data to send back as API response

func getCapacityData(randCapacity string, UserID string) ([]byte, error) {
	output := Stats{"warning", "ti-server", "Capacity", randCapacity, "Updated Now", "ti-reload"}
	json, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	return json, nil
}
