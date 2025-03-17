package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var db *mongo.Database

var jwtSecret = []byte("compereTugasAkhir12345")

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Username     string             `bson:"username"`
	Password     string             `bson:"password"`
	Role         string             `bson:"role"`
	FullName     *string            `bson:"full_name,omitempty"`
	Email        *string            `bson:"email,omitempty"`
	PhoneNumber  *string            `bson:"phone_number,omitempty"`
	PhotoProfile *string            `bson:"photo_profile,omitempty"`
	CreatedAt    time.Time          `bson:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at"`
}

type Perbaikan struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	UserID         primitive.ObjectID `bson:"user_id"`
	Description    string             `bson:"description"`
	Component      string             `bson:"component"`
	Status         string             `bson:"status"`
	Result         string             `bson:"result"`
	Status_Predict string             `bson:"status_predict"`
	CreatedAt      time.Time          `bson:"created_at"`
	UpdatedAt      time.Time          `bson:"updated_at"`
}

type TrainingData struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Description string             `bson:"description"`
	Component   string             `bson:"component"`
	CreatedAt   time.Time          `bson:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at"`
}

type PerbaikanKomponen struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`
	PerbaikanID   primitive.ObjectID `bson:"perbaikan_id"`
	KomponenRusak string             `bson:"komponen_rusak"`
	Persentase    float64            `bson:"persentase"`
	CreatedAt     time.Time          `bson:"created_at"`
	UpdatedAt     time.Time          `bson:"updated_at"`
}

type Claims struct {
	ID       primitive.ObjectID `json:"id"`
	Username string             `json:"username"`
	jwt.StandardClaims
}

func initDB() {
	var err error
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	db = client.Database("compere_db")

	// Seed data
	seedTrainingDataFromCSV("training_data.csv")
	seedPerbaikanDataFromCSV("perbaikan_data.csv")
}

func seedTrainingDataFromCSV(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Gagal membuka file CSV: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Gagal membaca file CSV: %v", err)
	}

	for i, record := range records {
		if i == 0 {
			continue
		}

		trainingData := TrainingData{
			Description: record[0],
			Component:   record[1],
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		_, err := db.Collection("training_data").InsertOne(context.TODO(), trainingData)
		if err != nil {
			log.Printf("Gagal memasukkan data ke database: %v", err)
		}
	}

	fmt.Println("Training data dari CSV berhasil dimasukkan ke database.")
}

func seedPerbaikanDataFromCSV(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Gagal membuka file CSV: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Gagal membaca file CSV: %v", err)
	}

	for i, record := range records {
		if i == 0 {
			continue
		}

		userID, _ := primitive.ObjectIDFromHex(record[0])
		statusPredict := record[5]

		perbaikan := Perbaikan{
			UserID:         userID,
			Description:    record[1],
			Component:      record[2],
			Status:         record[3],
			Result:         record[4],
			Status_Predict: statusPredict,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

		_, err := db.Collection("perbaikan").InsertOne(context.TODO(), perbaikan)
		if err != nil {
			log.Printf("Gagal memasukkan data ke database: %v", err)
		}
	}

	fmt.Println("Data dummy Perbaikan berhasil dimasukkan ke database.")
}

func generateToken(user User) (string, error) {
	claims := Claims{
		ID:       user.ID,
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func register(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	var existingUser User
	err := db.Collection("users").FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
		return
	}

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	_, err = db.Collection("users").InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	var user User
	err := db.Collection("users").FindOne(context.TODO(), bson.M{"username": credentials.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if user.Password != credentials.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

func authorize(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		c.Abort()
		return
	}

	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		c.Abort()
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	c.Set("user_id", claims.ID)
	c.Set("username", claims.Username)
	c.Next()
}

func createPerbaikan(c *gin.Context) {
	var perbaikan Perbaikan
	if err := c.ShouldBind(&perbaikan); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if strings.TrimSpace(perbaikan.Description) == "" || strings.TrimSpace(perbaikan.Component) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Description and Component are required"})
		return
	}

	userID, _ := c.Get("user_id")
	perbaikan.UserID = userID.(primitive.ObjectID)
	perbaikan.CreatedAt = time.Now()
	perbaikan.UpdatedAt = time.Now()

	_, err := db.Collection("perbaikan").InsertOne(context.TODO(), perbaikan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Perbaikan created successfully",
		"perbaikan_id": perbaikan.ID,
	})
}

func getPerbaikan(c *gin.Context) {
	var perbaikan []Perbaikan
	cursor, err := db.Collection("perbaikan").Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan", "details": err.Error()})
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var p Perbaikan
		cursor.Decode(&p)
		perbaikan = append(perbaikan, p)
	}

	c.JSON(http.StatusOK, perbaikan)
}

func getPerbaikanById(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))
	var perbaikan Perbaikan

	err := db.Collection("perbaikan").FindOne(context.TODO(), bson.M{"_id": id}).Decode(&perbaikan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, perbaikan)
}

func getPerbaikanByUser(c *gin.Context) {
	userID, _ := primitive.ObjectIDFromHex(c.Param("id"))
	var perbaikan []Perbaikan

	cursor, err := db.Collection("perbaikan").Find(context.TODO(), bson.M{"user_id": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan for user", "details": err.Error()})
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var p Perbaikan
		cursor.Decode(&p)
		perbaikan = append(perbaikan, p)
	}

	if len(perbaikan) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "No perbaikan found for this user"})
		return
	}

	c.JSON(http.StatusOK, perbaikan)
}

func updatePerbaikan(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))
	var perbaikan Perbaikan

	if err := c.ShouldBind(&perbaikan); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	perbaikan.UpdatedAt = time.Now()

	_, err := db.Collection("perbaikan").UpdateOne(context.TODO(), bson.M{"_id": id}, bson.M{"$set": perbaikan})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Perbaikan updated successfully"})
}

func deletePerbaikan(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))

	_, err := db.Collection("perbaikan").DeleteOne(context.TODO(), bson.M{"_id": id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Perbaikan deleted successfully"})
}

func createTrainingData(c *gin.Context) {
	var trainingData TrainingData
	if err := c.ShouldBind(&trainingData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if strings.TrimSpace(trainingData.Description) == "" || strings.TrimSpace(trainingData.Component) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Description and Component are required"})
		return
	}

	trainingData.CreatedAt = time.Now()
	trainingData.UpdatedAt = time.Now()

	_, err := db.Collection("training_data").InsertOne(context.TODO(), trainingData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data created successfully"})
}

func getTrainingData(c *gin.Context) {
	var trainingData []TrainingData
	cursor, err := db.Collection("training_data").Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve training data", "details": err.Error()})
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var t TrainingData
		cursor.Decode(&t)
		trainingData = append(trainingData, t)
	}

	c.JSON(http.StatusOK, trainingData)
}

func updateTrainingData(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))
	var trainingData TrainingData

	if err := c.ShouldBind(&trainingData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	trainingData.UpdatedAt = time.Now()

	_, err := db.Collection("training_data").UpdateOne(context.TODO(), bson.M{"_id": id}, bson.M{"$set": trainingData})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data updated successfully"})
}

func deleteTrainingData(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))

	_, err := db.Collection("training_data").DeleteOne(context.TODO(), bson.M{"_id": id})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data deleted successfully"})
}

func getUser(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var user User

	err := db.Collection("users").FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func getUserById(c *gin.Context) {
	id, _ := primitive.ObjectIDFromHex(c.Param("id"))
	var user User

	err := db.Collection("users").FindOne(context.TODO(), bson.M{"_id": id}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
	userID, _ := primitive.ObjectIDFromHex(c.Param("id"))

	fullName := c.PostForm("full_name")
	email := c.PostForm("email")
	phoneNumber := c.PostForm("phone_number")

	file, _ := c.FormFile("profile_pic")
	var filename *string

	if file != nil {
		savedFilename := fmt.Sprintf("uploads/%s_%s", userID.Hex(), file.Filename)
		if err := c.SaveUploadedFile(file, savedFilename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file", "details": err.Error()})
			return
		}
		filename = &savedFilename
	}

	updates := bson.M{
		"full_name":    fullName,
		"email":        email,
		"phone_number": phoneNumber,
		"updated_at":   time.Now(),
	}

	if filename != nil {
		updates["photo_profile"] = *filename
	}

	_, err := db.Collection("users").UpdateOne(context.TODO(), bson.M{"_id": userID}, bson.M{"$set": updates})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func main() {
	initDB()

	r := gin.Default()

	// Middleware CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Public routes
	r.POST("/register", register)
	r.PUT("/update_user/:id", updateUser)
	r.POST("/login", login)

	// TrainingData CRUD
	r.POST("/training_data", createTrainingData)
	r.GET("/training_data", getTrainingData)
	r.PUT("/training_data/:id", updateTrainingData)
	r.DELETE("/training_data/:id", deleteTrainingData)

	// Protected routes
	r.Use(authorize)
	r.POST("/perbaikan", createPerbaikan)
	r.GET("/perbaikan", getPerbaikan)
	r.GET("/perbaikan_user/:id", getPerbaikanByUser)
	r.GET("/perbaikan/:id", getPerbaikanById)
	r.PUT("/perbaikan/:id", updatePerbaikan)
	r.DELETE("/perbaikan/:id", deletePerbaikan)

	// r.POST("/perbaikan_komponen", createPerbaikanKomponen)

	// User routes
	r.GET("/user", getUser)
	r.GET("/user/:id", getUserById)

	r.Run(":8080")
}
