package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/sfreiberg/gotwilio"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type users struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Application struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	FullName    string `json:"full_name"`
	BirthDate   string `json:"birth_date"`
	Region      string `json:"region"`
	Phone       string `json:"phone"`
	IDCard      string `json:"id_card"`
	MilitaryDoc string `json:"military_doc"`
	Status      string `json:"status"`
}

var db *sql.DB

const accountSID = ""
const authToken = ""
const twilioPhone = ""

func sendSMS(phone string, message string) {
	twilio := gotwilio.NewTwilioClient(accountSID, authToken)
	_, _, err := twilio.SendSMS(twilioPhone, phone, message, "", "")
	if err != nil {
		fmt.Println("Ошибка отправки SMS:", err)
	} else {
		fmt.Println("SMS успешно отправлено на", phone)
	}
}

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbSSLMode := os.Getenv("DB_SSLMODE")

	dbConnStr := "user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " sslmode=" + dbSSLMode

	db, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	server := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		MaxAge: 1 * 60,
	})
	server.Use(sessions.Sessions("mysession", store))

	server.Use(sessionTimeout())

	server.LoadHTMLGlob("templates/*")
	server.GET("/home", authRequired(homePage))

	server.GET("/form", authRequired(formPage))
	server.POST("/submit-form", authRequired(submitForm))

	server.GET("/profile", authRequired(profilePage))

	server.GET("/admin", adminRequired(adminPage))
	server.POST("/set-quota", adminRequired(setQuota))
	server.POST("/set-total-places", adminRequired(setTotalPlaces))
	server.POST("/approve-application", adminRequired(approveApplication))
	server.POST("/delete-application", adminRequired(deleteApplication))
	server.POST("/update-application-id", adminRequired(updateApplicationID))

	server.GET("/signUpPage", signUpPage)
	server.POST("/signup", signUp)
	server.GET("/signInPage", signInPage)
	server.POST("/signin", signIn)
	server.GET("/logout", logout)

	server.Run(":8080")
}

func homePage(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	var user users
	db.QueryRow("SELECT id, username, email FROM users WHERE id = $1", userID).Scan(&user.ID, &user.Username, &user.Email)

	c.HTML(http.StatusOK, "home.html", gin.H{
		"user": user,
	})
}

func signUpPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signUp.html", nil)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signUp(c *gin.Context) {
	userName := c.PostForm("user-name")
	userEmail := c.PostForm("user-email")
	userPass := c.PostForm("user-password")

	if userName == "" || len(userPass) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	var existingUser users
	err := db.QueryRow("SELECT id FROM users WHERE email = $1", userEmail).Scan(&existingUser.ID)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already in use"})
		return
	}

	hashedPassword, err := hashPassword(userPass)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	var newUser users
	err = db.QueryRow("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id", userName, userEmail, hashedPassword).Scan(&newUser.ID)
	if err != nil {
		log.Fatal(err)
	}

	c.Redirect(http.StatusFound, "/home")
}

func signInPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signIn.html", nil)
}

func signIn(c *gin.Context) {
	email := c.PostForm("user-email")
	password := c.PostForm("user-password")

	var storedUser users
	err := db.QueryRow("SELECT id, username, email, password FROM users WHERE email = $1", email).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Email, &storedUser.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !checkPasswordHash(password, storedUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	session := sessions.Default(c)
	session.Set("user_id", storedUser.ID)
	session.Set("user_email", storedUser.Email)
	session.Save()

	c.Redirect(http.StatusFound, "/home")
}
func logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()

	c.Redirect(http.StatusFound, "/signInPage")
}

func authRequired(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			c.Redirect(http.StatusFound, "/signInPage")
			return
		}
		handler(c)
	}
}

func sessionTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		lastActivity := session.Get("last_activity")

		if lastActivity != nil {
			lastActivityTime := lastActivity.(int64)
			if time.Now().Unix()-lastActivityTime > 1*60 {
				session.Clear()
				session.Save()
				c.Redirect(http.StatusFound, "/signInPage")
				c.Abort()
				return
			}
		}

		session.Set("last_activity", time.Now().Unix())
		session.Save()
		c.Next()
	}
}

func formPage(c *gin.Context) {
	c.HTML(http.StatusOK, "form.html", nil)
}

func submitForm(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	fullName := c.PostForm("full_name")
	birthDate := c.PostForm("birth_date")
	region := c.PostForm("region")
	phone := c.PostForm("phone")

	if fullName == "" || birthDate == "" || region == "" || phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "All fields are required"})
		return
	}

	var maxPlaces, currentCount int
	err := db.QueryRow("SELECT max_places FROM quotas WHERE region = $1", region).Scan(&maxPlaces)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Регион не зарегистрирован в системе"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения квоты"})
		return
	}

	err = db.QueryRow("SELECT COUNT(*) FROM applications WHERE region = $1", region).Scan(&currentCount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки текущего количества заявок"})
		return
	}

	if currentCount >= maxPlaces {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Квота на этот регион уже заполнена"})
		return
	}

	idCard, err := c.FormFile("id_card")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID card is required"})
		return
	}
	idCardPath := "uploads/" + idCard.Filename
	c.SaveUploadedFile(idCard, idCardPath)

	militaryDoc, err := c.FormFile("military_doc")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Military document is required"})
		return
	}
	militaryDocPath := "uploads/" + militaryDoc.Filename
	c.SaveUploadedFile(militaryDoc, militaryDocPath)

	_, err = db.Exec("INSERT INTO applications (user_id, full_name, birth_date, region, phone, id_card, military_doc, status) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')",
		userID, fullName, birthDate, region, phone, idCardPath, militaryDocPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save application"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Application submitted successfully"})
}

func profilePage(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	if userID == nil {
		c.Redirect(http.StatusFound, "/signInPage")
		return
	}

	var app Application
	err := db.QueryRow("SELECT id, status FROM applications WHERE user_id = $1 ORDER BY id ASC LIMIT 1", userID).
		Scan(&app.ID, &app.Status)

	if err == sql.ErrNoRows {
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"user":  session.Get("user_email"),
			"error": "Вы еще не подали заявку.",
		})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных"})
		return
	}

	notification := ""
	if app.Status == "approved" {
		notification = "Ваша заявка одобрена! Ожидайте СМС с информацией о путевке."
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"user":         session.Get("user_email"),
		"status":       app.Status,
		"queue_number": app.ID,
		"notification": notification,
	})
}

func adminRequired(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil || userID.(int) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		handler(c)
	}
}

func adminPage(c *gin.Context) {
	rows, err := db.Query("SELECT id, full_name, birth_date, region, phone, status FROM applications ORDER BY id ASC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения заявок"})
		return
	}
	defer rows.Close()

	var applications []Application
	for rows.Next() {
		var app Application
		err := rows.Scan(&app.ID, &app.FullName, &app.BirthDate, &app.Region, &app.Phone, &app.Status)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки заявок"})
			return
		}
		applications = append(applications, app)
	}

	qRows, err := db.Query("SELECT region, max_places FROM quotas")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения квот"})
		return
	}
	defer qRows.Close()

	quotas := make(map[string]int)
	for qRows.Next() {
		var region string
		var maxPlaces int
		qRows.Scan(&region, &maxPlaces)
		quotas[region] = maxPlaces
	}

	var totalPlaces int
	db.QueryRow("SELECT total_places FROM system_settings").Scan(&totalPlaces)

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"applications": applications,
		"quotas":       quotas,
		"total_places": totalPlaces,
	})
}

func setQuota(c *gin.Context) {
	region := c.PostForm("region")
	maxPlaces := c.PostForm("max_places")

	_, err := db.Exec("INSERT INTO quotas (region, max_places) VALUES ($1, $2) ON CONFLICT (region) DO UPDATE SET max_places = EXCLUDED.max_places", region, maxPlaces)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления квоты"})
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

func setTotalPlaces(c *gin.Context) {
	totalPlaces := c.PostForm("total_places")

	_, err := db.Exec("UPDATE system_settings SET total_places = $1", totalPlaces)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления общего лимита"})
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

func approveApplication(c *gin.Context) {
	appID := c.PostForm("application_id")

	var phone string
	err := db.QueryRow("SELECT phone FROM applications WHERE id = $1", appID).Scan(&phone)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Заявка не найдена"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных"})
		return
	}

	_, err = db.Exec("UPDATE applications SET status = 'approved' WHERE id = $1", appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка подтверждения заявки"})
		return
	}

	message := "Ваша заявка на путевку одобрена! Ожидайте дальнейших инструкций."
	sendSMS(phone, message)

	c.Redirect(http.StatusFound, "/admin")
}

func deleteApplication(c *gin.Context) {
	appID := c.PostForm("application_id")

	_, err := db.Exec("DELETE FROM applications WHERE id = $1", appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления заявки"})
		return
	}
	c.Redirect(http.StatusFound, "/admin")
}

func updateApplicationID(c *gin.Context) {
	oldID := c.PostForm("old_id")
	newID := c.PostForm("new_id")

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1)", oldID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Заявка с таким ID не найдена"})
		return
	}

	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM applications WHERE id = $1)", newID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID уже занято другой заявкой"})
		return
	}

	_, err = db.Exec("UPDATE applications SET id = $1 WHERE id = $2", newID, oldID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления ID"})
		return
	}

	c.Redirect(http.StatusFound, "/admin")
}
