package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

// compereTugasAkhir12345
var jwtSecret = []byte("compereTugasAkhir12345")

type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"unique"`
	Password     string
	Role         string
	FullName     *string `gorm:"type:varchar(100)"`
	Email        *string `gorm:"type:varchar(100)"`
	PhoneNumber  *string `gorm:"type:varchar(20)"`
	PhotoProfile *string `gorm:"type:varchar(255)"`
}

type Perbaikan struct {
	ID                uint `gorm:"primaryKey"`
	UserID            uint
	Description       string
	Component         string
	Status            string
	Result            string
	Status_Predict    string
	PerbaikanKomponen []PerbaikanKomponen `gorm:"foreignKey:PerbaikanID"`
}

type TrainingData struct {
	ID          uint `gorm:"primaryKey"`
	Description string
	Component   string
}

type PerbaikanKomponen struct {
	ID            uint    `gorm:"primaryKey"`
	PerbaikanID   uint    `gorm:"not null"`
	KomponenRusak string  `gorm:"type:varchar(100);not null"`
	Persentase    float64 `gorm:"not null"`
}

type Claims struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))

	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{}, &Perbaikan{}, &TrainingData{}, &PerbaikanKomponen{})

	// Jalankan seeding data dari CSV
	seedTrainingDataFromCSV(db, "training_data.csv")
	seedPerbaikanDataFromCSV(db, "perbaikan_data.csv")
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

	// Validation for required fields
	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	// Check if username already exists
	var existingUser User
	if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
		return
	}

	if err := db.Create(&user).Error; err != nil {
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

	// Bind JSON input (expecting { "username": "someuser", "password": "somepass" })
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	// Check if the user exists in the database
	var user User
	if err := db.Where("username = ?", credentials.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Check if the password matches (here you would ideally hash the password)
	if user.Password != credentials.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate JWT token
	token, err := generateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

// Middleware to protect routes that require authentication
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

	// Extract claims from the token
	claims, ok := token.Claims.(*Claims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	// Attach user info to context
	c.Set("user_id", claims.ID)
	c.Set("username", claims.Username)
	c.Next()
}

// CREATE for Perbaikan Komponen Persentase
func createPerbaikanKomponen(c *gin.Context) {
	var perbaikanKomponen PerbaikanKomponen
	if err := c.ShouldBindJSON(&perbaikanKomponen); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if err := db.Create(&perbaikanKomponen).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create perbaikan komponen", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Perbaikan komponen created successfully"})
}

// CRUD for Perbaikan
func createPerbaikan(c *gin.Context) {
	var perbaikan Perbaikan
	if err := c.ShouldBind(&perbaikan); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	// Validate required fields
	if strings.TrimSpace(perbaikan.Description) == "" || strings.TrimSpace(perbaikan.Component) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Description and Component are required"})
		return
	}

	userID, _ := c.Get("user_id")

	perbaikan.UserID = userID.(uint)

	if err := db.Create(&perbaikan).Error; err != nil {
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
	if err := db.Preload("PerbaikanKomponen").Find(&perbaikan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, perbaikan)
}

func getPerbaikanById(c *gin.Context) {
	id := c.Param("id")
	var perbaikan []Perbaikan

	if err := db.Preload("PerbaikanKomponen").Where("id = ?", id).Find(&perbaikan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan", "details": err.Error()})
		return
	}
	c.JSON(http.StatusOK, perbaikan)
}

func getPerbaikanByUser(c *gin.Context) {
	userID := c.Param("id")
	var perbaikan []Perbaikan

	if err := db.Preload("PerbaikanKomponen").Where("user_id = ?", userID).Find(&perbaikan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve perbaikan for user", "details": err.Error()})
		return
	}

	if len(perbaikan) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "No perbaikan found for this user"})
		return
	}

	c.JSON(http.StatusOK, perbaikan)
}

func updatePerbaikan(c *gin.Context) {
	var perbaikan Perbaikan
	id := c.Param("id")
	if err := db.First(&perbaikan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Perbaikan not found"})
		return
	}

	if err := c.ShouldBind(&perbaikan); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if err := db.Save(&perbaikan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Perbaikan updated successfully"})
}

func deletePerbaikan(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Perbaikan{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete perbaikan", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Perbaikan deleted successfully"})
}

// CRUD for TrainingData
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

	if err := db.Create(&trainingData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data created successfully"})
}

func getTrainingData(c *gin.Context) {
	var trainingData []TrainingData
	if err := db.Find(&trainingData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, trainingData)
}

func updateTrainingData(c *gin.Context) {
	var trainingData TrainingData
	id := c.Param("id")
	if err := db.First(&trainingData, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Training data not found"})
		return
	}

	if err := c.ShouldBind(&trainingData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input format", "details": err.Error()})
		return
	}

	if err := db.Save(&trainingData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data updated successfully"})
}

func deleteTrainingData(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&TrainingData{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete training data", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Training data deleted successfully"})
}

// Get the current logged-in user based on the JWT token
func getUser(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// Get a user by their ID
func getUserById(c *gin.Context) {
	id := c.Param("id")

	var user User
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
	userID := c.Param("id")

	fullName := c.PostForm("full_name")
	email := c.PostForm("email")
	phoneNumber := c.PostForm("phone_number")

	file, _ := c.FormFile("profile_pic")
	var filename *string

	if file != nil {
		savedFilename := fmt.Sprintf("uploads/%s_%s", userID, file.Filename)
		if err := c.SaveUploadedFile(file, savedFilename); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file", "details": err.Error()})
			return
		}
		filename = &savedFilename
	}

	updates := map[string]interface{}{
		"full_name":    fullName,
		"email":        email,
		"phone_number": phoneNumber,
	}

	if filename != nil {
		updates["photo_profile"] = *filename
	}

	if err := db.Model(&User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// Fungsi untuk membaca CSV dan memasukkan ke database
func seedTrainingDataFromCSV(db *gorm.DB, filename string) {
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

	// Lewati header CSV (baris pertama)
	for i, record := range records {
		if i == 0 {
			continue
		}

		trainingData := TrainingData{
			Description: record[0],
			Component:   record[1],
		}

		if err := db.Create(&trainingData).Error; err != nil {
			log.Printf("Gagal memasukkan data ke database: %v", err)
		}
	}

	fmt.Println("Training data dari CSV berhasil dimasukkan ke database.")
}

func seedPerbaikanDataFromCSV(db *gorm.DB, filename string) {
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

	// Lewati header CSV (baris pertama)
	for i, record := range records {
		if i == 0 {
			continue
		}

		userID, _ := strconv.Atoi(record[0])
		statusPredict, _ := strconv.Atoi(record[5])

		perbaikan := Perbaikan{
			UserID:         uint(userID),
			Description:    record[1],
			Component:      record[2],
			Status:         record[3],
			Result:         record[4],
			Status_Predict: strconv.Itoa(statusPredict),
		}

		if err := db.Create(&perbaikan).Error; err != nil {
			log.Printf("Gagal memasukkan data ke database: %v", err)
		}
	}

	fmt.Println("Data dummy Perbaikan berhasil dimasukkan ke database.")
}

func main() {
	initDB()

	r := gin.Default()

	// Middleware CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"}, // Ganti dengan origin frontend kamu
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

	r.POST("/perbaikan_komponen", createPerbaikanKomponen)

	// User routes
	r.GET("/user", getUser)         // Get the logged-in user's info
	r.GET("/user/:id", getUserById) // Get a user by their ID

	r.Run(":8080")
}
