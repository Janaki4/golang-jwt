package helper

import (
	"errors"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func CheckUserRole(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	err = nil
	if userType != role {
		err = errors.New("Role didnot match")
		return err
	}
	return err
}

func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil
	if userType == "USER" && uid != userId {
		err = errors.New("UNAUTHORIZED")
		return err
	}

	return CheckUserRole(c, userType)
}

type SignedDetails struct {
	Email    string
	FName    string
	LName    string
	UserType string
	Id       string
	jwt.StandardClaims
}

func GenerateTokens(email *string, fName *string, lName *string, userType *string, id *string) (*string, *string, error) {
	expTime := jwt.NewTime(float64(time.Now().Local().Add(24 * time.Hour).Unix()))
	tokn := &SignedDetails{
		Email:    *email,
		FName:    *fName,
		LName:    *lName,
		UserType: *userType,
		Id:       *id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expTime,
		},
	}
	refreshTokn := SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.NewTime(float64(time.Now().Local().Add(200 * time.Hour).Unix())),
		},
	}
	// parsedJson, _ := json.Marshal(gin.H{"email": email, "fName": fName, "userType": userType})

	// hash, err := bcrypt.GenerateFromPassword(parsedJson, bcrypt.DefaultCost)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// refresh, err := bcrypt.GenerateFromPassword(parsedJson, bcrypt.DefaultCost)
	// if err != nil {
	// 	return nil, nil, err
	// }

	// _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, tokn).SignedString([]byte("janaki"))
	RTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokn).SignedString([]byte("janaki"))
	if err != nil {
		return nil, nil, err
	}

	token := string(Tok)
	refereshToken := string(RTok)
	return &token, &refereshToken, nil
}
func HashPassword(password string) (*string, error) {
	hashedByte, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}

	hashedPassword := string(hashedByte)
	return &hashedPassword, nil
}

func VerifyPassword(password string, hash string) bool {
	log.Println(password, hash, 1111111)
	flag := true
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash))
	if err != nil {
		flag = false
		log.Println(err.Error())
	}
	return flag
}

func ValidateJwt(token *string) (claims *SignedDetails, err error) {
	tokn, err := jwt.ParseWithClaims(*token, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) { return []byte("janaki"), nil })
	if err != nil {
		log.Println(err)
		return nil, err
	}

	claims, ok := tokn.Claims.(*SignedDetails)
	if !ok {
		log.Println(err)
		return nil, errors.New("Error")
	}

	return claims, nil
}
