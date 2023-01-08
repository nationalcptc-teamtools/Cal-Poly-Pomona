package routes

import (
	"github.com/gin-gonic/gin"

	controllers "AM-UNGoS/controllers"
)

func PublicRoutes(g *gin.RouterGroup) {
	g.GET("/login", controllers.LoginGetHandler())
	g.POST("/login", controllers.LoginPostHandler())
	g.GET("/register", controllers.RegisterGetHandler())
	g.POST("/register", controllers.RegisterPostHandler())
	g.GET("/", controllers.IndexGetHandler())
	g.POST("/api/upload", controllers.UploadPostHandler())
}

func PrivateRoutes(g *gin.RouterGroup) {
	g.GET("/dashboard", controllers.DashboardGetHandler())
	g.GET("/dashboard/boxes", controllers.BoxesGetHandler())
	g.GET("/dashboard/profile", controllers.ProfileGetHandler())
	g.GET("/dashboard/upload", controllers.UploadGetHandler())
	g.GET("/dashboard/credentials", controllers.CredentialsGetHandler())
	g.GET("/logout", controllers.LogoutGetHandler())

	g.POST("/api/update/color", controllers.UpdateColorPostHandler())
	g.POST("/api/update/password", controllers.UpdatePasswordPostHandler())
	g.POST("/api/update/service-details", controllers.UpdateServiceDetailsPostHandler())
	g.POST("/api/update/credentials", controllers.UpdateCredentialsPostHandler())
	g.POST("/dashboard/credentials", controllers.CredentialsPostHandler())
	g.POST("/dashboard/credentials/delete", controllers.DeleteCredentialPostHandler())
	g.POST("/dashboard/boxes/delete", controllers.DeleteBoxPostHandler())
	g.POST("/dashboard/boxes/update-codename", controllers.UpdateCodenamePostHandler())
	g.POST("/dashboard/boxes/update-assignee", controllers.UpdateAssigneePostHandler())
	g.POST("/dashboard/boxes/update-shells", controllers.UpdateShellsPostHandler())
}
