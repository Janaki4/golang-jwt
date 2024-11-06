package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Janaki4/go_jwt_be/database"
	helper "github.com/Janaki4/go_jwt_be/helpers"
	"github.com/Janaki4/go_jwt_be/models"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User

		// fmt.Println(c, user, c.BindJSON(&user))
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			// defer cancel()
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()

		if err != nil {
			// defer cancel()
			log.Panic(err)
			c.JSON(http.StatusBadRequest, bson.M{"error": "Email is already present"})
			return
		}

		phCount, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, bson.M{"error": "Phone is already present"})
			return
		}

		userData, err := json.Marshal(user)
		if err != nil {
			log.Println("Error marshaling user:", err)
			return
		}

		bodyBytes, err := io.ReadAll(bytes.NewReader(userData))
		if err != nil {
			log.Println("Error reading user data:", err)
			return
		}
		log.Println(string(bodyBytes))

		if count > 0 || phCount > 0 {
			log.Println(count, phCount)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Count is positive"})
			return
		}

		password, err := helper.HashPassword(*user.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password hashing failed"})
			return
		}

		user.Password = password
		user.Created_at, _ = time.Parse(time.RFC1123, time.Now().Format(time.RFC1123))
		user.Updated_at = user.Created_at
		user.ID = primitive.NewObjectID()

		hexID := user.ID.Hex()
		user.User_id = &hexID
		token, refreshToken, err := helper.GenerateTokens(user.Email, user.First_name, user.Last_name, user.User_type, user.User_id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": string(err.Error()) + "Something wrong with hashing"})
			return
		}
		user.Token = token
		user.Refresh_token = refreshToken

		insertRes, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			type e map[string]interface{}
			c.JSON(http.StatusBadRequest, e{"error": insertErr.Error()})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, gin.H{"message": insertRes})
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {

		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			log.Println(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		err := userCollection.FindOne(ctx, gin.H{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		// dumm, _ := json.Marshal(foundUser)
		dummm, _ := json.Marshal(user)
		log.Println(string(dummm), 888888)

		if err != nil {
			log.Println(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user email not present"})
			return
		}

		isPasswordValid := helper.VerifyPassword(*foundUser.Password, *user.Password)
		if !isPasswordValid {
			log.Println("Password is invalid")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password is invalid"})
			return
		}

		token, refreshToken, err := helper.GenerateTokens(foundUser.Email, foundUser.First_name, foundUser.Last_name, foundUser.User_type, foundUser.User_id)
		if err != nil {
			log.Println("Token creation failed")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		updatedRes, err := userCollection.UpdateOne(ctx, gin.H{"email": foundUser.Email}, gin.H{"$set": gin.H{"token": token, "refresh_token": refreshToken}})
		defer cancel()
		if err != nil {
			log.Println(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		log.Printf("%+v", updatedRes)
		fetchErr := userCollection.FindOne(ctx, bson.M{"email": foundUser.Email}).Decode(&foundUser)
		defer cancel()
		if fetchErr != nil {
			log.Println(fetchErr.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": fetchErr.Error()})
			return
		}

		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()

		fmt.Println("OKKkkk", c.GetString("user_type"), c.GetString("uid"), c.GetString("id"))

		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error on fetching user"})
			return
		}
		c.JSON(http.StatusOK, user)
	}
}

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("token")
		if token == "" {
			log.Println("Token should be present")
			c.JSON(http.StatusBadRequest, bson.M{"error": "Token should be present"})
			c.Abort()
			return
		}

		claims, err := helper.ValidateJwt(&token)
		if err != nil {
			log.Println(err.Error(), 1)
			c.JSON(http.StatusBadRequest, bson.M{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("fName", claims.FName)
		c.Set("user_id", claims.ID)
		c.Set("user_type", claims.UserType)
		c.Set("uid", claims.Id)
		c.Next()
	}
}
