package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

const (
	userFilepath = "users.csv"
)

func main() {
	http.HandleFunc("/register", registerUser)
	http.HandleFunc("/login", login)
	http.HandleFunc("/", helloWorld)
	fmt.Println("Server started at localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func helloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello World!"))
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	var user User

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	_ = json.Unmarshal(body, &user)

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Please fill out all form fields", http.StatusBadRequest)
		return
	}

	userData, err := getUserDataWithPassword(user.Username, user.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("Hello " + userData.Username + "!"))
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	var user User

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	_ = json.Unmarshal(body, &user)

	if user.Username == "" || user.Password == "" {
		http.Error(w, "Please fill out all form fields", http.StatusBadRequest)
		return
	}

	if !isValidEmail(user.Email) {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	if isUserExists(user.Username) {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	err = SaveUserData(user, userFilepath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User created successfully"))
}

// jebakan betmen
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)

	if email == "" {
		return false
	}

	return re.MatchString(email)
}

func SaveUserData(user User, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	// ini nanti juga dihapus
	// defer file.Close()

	w := csv.NewWriter(file)

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return err
	}

	header := []string{"Name", "Email", "Password"}
	if err := w.Write(header); err != nil {
		return err
	}

	if err := w.Write([]string{user.Username, user.Email, hashedPassword}); err != nil {
		return err
	}
	w.Flush()

	return nil
}

func hashPassword(password string) (string, error) {
	// 15 itu cost, kegedean costnya bisa bikin server crash
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 15)
	return string(bytes), err
}

func checkPassword(hashedPassword string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func getUserDataWithPassword(username, password string) (User, error) {
	f, err := os.Open(userFilepath)
	if err != nil {
		return User{}, err
	}
	// ini nanti dihapus
	// defer f.Close()

	reader := csv.NewReader(f)

	records, err := reader.ReadAll()
	if err != nil {
		return User{}, err
	}

	var wg sync.WaitGroup
	var user User

	for _, record := range records {
		wg.Add(1)
		go func(record []string) {
			// ini nanti dihapus di soalnya
			// defer wg.Done()

			if record[0] == username {
				err = checkPassword(record[2], password)
				if err == nil {
					user = parseUserData(record)
				}
			}
		}(record)
	}
	if err != nil {
		return User{}, err
	}

	wg.Wait()

	return user, nil
}

// ini ngeloop, csvnya bakal dipopulate banyak data. bakal lambat disini
func isUserExists(username string) bool {
	f, err := os.Open(userFilepath)
	if err != nil {
		return true
	}
	defer f.Close()

	reader := csv.NewReader(f)

	records, err := reader.ReadAll()
	if err != nil {
		return true
	}

	for _, record := range records {
		if record[0] == username {
			return true
		}
	}

	return false
}

func parseUserData(record []string) User {
	return User{
		Username: record[0],
		Email:    record[1],
		Password: record[2],
	}
}
