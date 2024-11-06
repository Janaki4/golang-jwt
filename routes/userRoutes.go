package routes

import (
	"github.com/Janaki4/go_jwt_be/controllers"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(controllers.Authentication())
	incomingRoutes.GET("/users/get/:user_id", controllers.GetUsers())
}
