package pass

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

// CheckPass checks a password
func CheckPass(truePassword, attemptPassword string) bool {
	return comparePasswords(truePassword, []byte(attemptPassword))
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
