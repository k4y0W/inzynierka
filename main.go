package main

import (
	"errors"   // Używane w np. errors.Is
	"fmt"      // Używane w np. fmt.Sprintf
	"log"      // Używane do logowania błędów
	"net/http" // Standardowy pakiet HTTP
	"os"       // Używane do odczytu zmiennych środowiskowych
	"strings"  // Używane w np. strings.ToUpper, strings.Contains
	"time"     // Używane do obsługi czasu (CreatedAt, exp w JWT)

	"github.com/gin-contrib/cors"  // Middleware CORS dla Gin
	"github.com/gin-gonic/gin"     // Framework webowy Gin
	"github.com/golang-jwt/jwt/v4" // Biblioteka do obsługi JWT
	"github.com/joho/godotenv"     // Ładowanie zmiennych środowiskowych z pliku .env
	"golang.org/x/crypto/bcrypt"   // Haszowanie haseł
	"gorm.io/driver/postgres"      // Sterownik PostgreSQL dla GORM
	"gorm.io/gorm"                 // ORM dla Go

	"server/models" // Ważne: Ta ścieżka musi odpowiadać nazwie Twojego modułu z go.mod
)

// --- Konfiguracja ---

type Config struct {
	Port              string
	JWTSecret         []byte
	CorsAllowedOrigin string
	DatabaseURL       string
}

// LoadConfig wczytuje konfigurację z pliku .env lub zmiennych środowiskowych.
func LoadConfig() Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, proceeding with OS environment variables")
	}

	port := os.Getenv("GO_SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	corsOrigin := os.Getenv("CORS_ALLOWED_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "http://localhost:3000"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "host=localhost user=postgres password=password dbname=mydatabase port=5432 sslmode=disable TimeZone=Europe/Warsaw"
		log.Printf("DATABASE_URL not set, using default: %s", dbURL)
	}

	return Config{
		Port:              port,
		JWTSecret:         []byte(jwtSecretStr), // Poprawka: konwersja stringa na []byte
		CorsAllowedOrigin: corsOrigin,
		DatabaseURL:       dbURL,
	}
}

// --- Middleware JWT ---
func jwtMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}
		tokenString := ""
		// Sprawdzamy, czy nagłówek zaczyna się od "Bearer " (case-insensitive)
		if len(authHeader) > 7 && strings.ToUpper(authHeader[0:7]) == "BEARER " {
			tokenString = authHeader[7:]
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must start with 'Bearer '"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Sprawdzamy metodę podpisu tokenu
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil // Zwracamy sekret do weryfikacji podpisu
		})
		if err != nil {
			log.Printf("Token parsing error: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Sprawdzamy poprawność tokenu i pobieramy z niego dane
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Sprawdzamy, czy token nie wygasł
			if exp, ok := claims["exp"].(float64); ok {
				if int64(exp) < time.Now().Unix() {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
					c.Abort()
					return
				}
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims (exp missing)"})
				c.Abort()
				return
			}

			// Ustawiamy dane użytkownika w kontekście GIN, aby były dostępne dla kolejnych handlerów
			c.Set("user_id", claims["user_id"])
			c.Set("username", claims["username"])
			c.Next() // Przechodzimy do następnego handlera w łańcuchu
		} else {
			log.Println("Invalid token or claims issue")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
		}
	}
}

// --- Zmienna globalna dla instancji bazy danych ---
var db *gorm.DB

// --- Główna funkcja aplikacji ---
func main() {
	cfg := LoadConfig()

	// Inicjalizacja globalnej zmiennej db
	var errGorm error
	db, errGorm = gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{}) // Połączenie z PostgreSQL
	if errGorm != nil {
		log.Fatalf("Failed to connect to PostgreSQL database: %v", errGorm)
	}

	// AutoMigrate wszystkich modeli z pakietu models
	// UWAGA: Kolejność jest ważna ze względu na relacje kluczy obcych (foreign keys).
	// Modele, które są referencjonowane przez inne (np. User, Process, Step), powinny być na początku.
	errMigrate := db.AutoMigrate(
		&models.User{},
		&models.Process{},
		&models.Step{},
		&models.UserProgress{},
		&models.Log{},
		&models.StepNote{},
	)
	if errMigrate != nil {
		log.Fatalf("Failed to migrate database: %v", errMigrate)
	}

	r := gin.Default()

	// Konfiguracja CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.CorsAllowedOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// --- Publiczne Trasy (rejestracja, logowanie) ---
	r.POST("/register", func(c *gin.Context) {
		var registerInput struct {
			Username string `json:"username" binding:"required,min=3"`
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=6"`
			Name     string `json:"name,omitempty"` // Opcjonalne pola z diagramu
			LastName string `json:"lastName,omitempty"`
			Indeks   int    `json:"indeks,omitempty"`
		}
		if err := c.ShouldBindJSON(&registerInput); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerInput.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
			return
		}

		user := models.User{
			Username:  registerInput.Username,
			Email:     registerInput.Email,
			Password:  string(hashedPassword),
			Name:      registerInput.Name,
			LastName:  registerInput.LastName,
			Indeks:    registerInput.Indeks,
			CreatedAt: time.Now(),
		}

		if err := db.Create(&user).Error; err != nil {
			// Obsługa błędów unikalności dla PostgreSQL
			if strings.Contains(err.Error(), "unique constraint") {
				errorMessage := "Username or email already exists."
				if strings.Contains(err.Error(), "users_username_key") { // Przykład domyślnej nazwy constraintu w PG
					errorMessage = "Username already exists."
				} else if strings.Contains(err.Error(), "users_email_key") { // Przykład domyślnej nazwy constraintu w PG
					errorMessage = "Email already exists."
				}
				c.JSON(http.StatusConflict, gin.H{"error": errorMessage})
				return
			}
			log.Printf("Error creating user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"message": "User added successfully"})
	})

	r.POST("/login", func(c *gin.Context) {
		var loginInput struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&loginInput); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
			return
		}
		var user models.User
		if err := db.Where("email = ?", loginInput.Email).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			} else {
				log.Printf("Error finding user: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing login"})
			}
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginInput.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}
		// Generowanie JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
			"email":    user.Email,
			"exp":      time.Now().Add(time.Hour * 24 * 7).Unix(), // Token ważny przez 7 dni
		})
		tokenString, err := token.SignedString(cfg.JWTSecret)
		if err != nil {
			log.Printf("Error signing token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": tokenString})
	})

	// --- Chronione Trasy (dostępne tylko po zalogowaniu) ---
	protected := r.Group("/")
	protected.Use(jwtMiddleware(cfg.JWTSecret))
	{
		// Przykład chronionej trasy
		protected.GET("/home", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			username, _ := c.Get("username")
			c.JSON(http.StatusOK, gin.H{
				"message":  fmt.Sprintf("Witaj w chronionej strefie, %s!", username),
				"username": username,
				"user_id":  userID,
			})
		})
	}

	log.Printf("Server starting on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
