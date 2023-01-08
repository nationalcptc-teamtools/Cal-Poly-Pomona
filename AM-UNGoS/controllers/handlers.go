package controllers

import (
	"github.com/gin-contrib/sessions"

	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"mime/multipart"
	"strconv"
	//"io/ioutil"

	globals "AM-UNGoS/globals"
	helpers "AM-UNGoS/helpers"
)

type UploadForm struct {
	File *multipart.FileHeader `form:"file" binding:"required"`
}

func RegisterGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		if user != nil {
			c.HTML(http.StatusBadRequest, "register.html",
				gin.H{
					"content": "Please logout first",
					"user":    user,
				})
			return
		}
		c.HTML(http.StatusOK, "register.html", gin.H{
			"content": "",
			"user":    user,
		})
	}
}

func RegisterPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		if user != nil {
			c.HTML(http.StatusBadRequest, "register.html", gin.H{"content": "Please logout first"})
			return
		}

		username := c.PostForm("username")
		password := c.PostForm("password")

		if helpers.EmptyUserPass(username, password) {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{"content": "Parameters can't be empty"})
			return
		}

		if !helpers.CheckExistingUser(username) {
			c.HTML(http.StatusUnauthorized, "register.html", gin.H{"content": "Username already taken!"})
			return
		}

		session.Set(globals.Userkey, username)
		if err := session.Save(); err != nil {
			c.HTML(http.StatusInternalServerError, "register.html", gin.H{"content": "Failed to save session"})
			return
		}
		if !helpers.RegisterUser(username, password) {
			c.HTML(http.StatusInternalServerError, "register.html", gin.H{"content": "Failed to create user"})
			return
		}
		c.Redirect(http.StatusMovedPermanently, "/dashboard")
	}
}

func LoginGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		if user != nil {
			c.HTML(http.StatusBadRequest, "login.html",
				gin.H{
					"content": "Please logout first",
					"user":    user,
				})
			return
		}
		c.HTML(http.StatusOK, "login.html", gin.H{
			"content": "",
			"user":    user,
		})
	}
}

func LoginPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		if user != nil {
			c.HTML(http.StatusBadRequest, "login.html", gin.H{"content": "Please logout first"})
			return
		}

		username := c.PostForm("username")
		password := c.PostForm("password")

		if helpers.EmptyUserPass(username, password) {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"content": "Parameters can't be empty"})
			return
		}

		if !helpers.CheckUserPass(username, password) {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"content": "Incorrect username or password"})
			return
		}

		session.Set(globals.Userkey, username)
		if err := session.Save(); err != nil {
			c.HTML(http.StatusInternalServerError, "login.html", gin.H{"content": "Failed to save session"})
			return
		}

		c.Redirect(http.StatusMovedPermanently, "/dashboard")
	}
}

func LogoutGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		log.Println("logging out user:", user)
		if user == nil {
			log.Println("Invalid session token")
		}
		session.Set(globals.Userkey, "")
		session.Clear()
		session.Options(sessions.Options{Path: "/", MaxAge: -1})
		if err := session.Save(); err != nil {
			log.Println("Failed to save session:", err)
			return
		}
		c.Redirect(http.StatusMovedPermanently, "/")
	}
}

func IndexGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		if user == nil {
			c.HTML(http.StatusOK, "index.html", gin.H{
				"content": "Loaded successfully",
				"user":    user,
			})
		}
		c.Redirect(http.StatusMovedPermanently, "/dashboard")
	}
}

func DashboardGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		stats, err := helpers.GetStats()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "dashboard.html", gin.H{"error": "Failed to fetch data"})
			return
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"content": stats,
			"user":    user,
		})
	}
}

func BoxesGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		boxes, err := helpers.GetBoxes()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to fetch box data"})
			return
		}
		usernames, err := helpers.GetUsernames()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to user data"})
			return
		}
		c.HTML(http.StatusOK, "boxes.html", gin.H{
			"content": boxes,
			"usernames": usernames,
			"user":    user,
		})
	}
}

func UpdateCredentialsPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.PostForm("id"))
		attr := c.PostForm("field")
		value := c.PostForm("value")
		if !helpers.UpdateCredentials(id, attr, value) {
			c.HTML(http.StatusInternalServerError, "credentials.html", gin.H{"error": "Failed to update credential information"})
			return
		} 
	}
}

func UpdateCodenamePostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		codename := c.PostForm("codename")
		ip := c.PostForm("ip")
		
		if !helpers.UpdateCodename(codename, ip) {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to update codename"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/boxes")
	}
}

func UpdateServiceDetailsPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		details := c.PostForm("content")
		id, _ := strconv.Atoi(c.PostForm("id"))
		
		if !helpers.UpdateServiceDetails(details, id) {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to update service details"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/boxes")
	}
}

func UpdateAssigneePostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.PostForm("ip")
		assign_id, _ := strconv.Atoi(c.PostForm("assignee"))
		if !helpers.UpdateAssignee(assign_id, ip) {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to update assignee"})
			return
		} 
	}
}

func UpdateShellsPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.PostForm("ip")
		shells, _ := strconv.Atoi(c.PostForm("shells"))
		shelltype := c.PostForm("type")
		if !helpers.UpdateShells(shells, ip, shelltype) {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to update shell count"})
			return
		} 
	}
}

func UploadGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		c.HTML(http.StatusOK, "upload.html", gin.H{
			"content": "",
			"user":    user,
		})
	}
}

func UploadPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"content": "Failed to upload file"})
			return
		}
		log.Println("Received uploaded file: ", file.Filename)
		
		if !helpers.UploadFile(file) {
			c.HTML(http.StatusInternalServerError, "upload.html", gin.H{"content": "Failed to process file"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/boxes")
	}
}

func ProfileGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		profile, err := helpers.GetProfile(user.(string))
		if err != nil {
			log.Println(err)
			c.HTML(http.StatusInternalServerError, "profile.html", gin.H{"error": "Failed to fetch user data"})
			return
		}
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"content": profile,
			"user":    user,
		})
	}
}

func UpdateColorPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		color := c.PostForm("value")
		id, _ := strconv.Atoi(c.PostForm("id"))

		if string(color[0]) != "#" {
			color = "#"+color 
		}
		
		if !helpers.UpdateColor(color, id) {
			c.HTML(http.StatusInternalServerError, "profile.html", gin.H{"error": "Failed to update color"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/profile")
	}
}

func UpdatePasswordPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		password := c.PostForm("value")
		id, _ := strconv.Atoi(c.PostForm("id"))
		
		if !helpers.UpdatePassword(password, id) {
			c.HTML(http.StatusInternalServerError, "profile.html", gin.H{"error": "Failed to update password"})
			return
		} 
	}
}

func CredentialsGetHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get(globals.Userkey)
		credentials, err := helpers.GetCredentials()
		if err != nil {

			c.HTML(http.StatusInternalServerError, "credentials.html", gin.H{"error": "Failed to fetch credential data"})
			return
		}
		c.HTML(http.StatusOK, "credentials.html", gin.H{
			"content": credentials,
			"user":    user,
		})
	}
}

func CredentialsPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.PostForm("ip")
		hostname := c.PostForm("hostname")
		port, _ := strconv.Atoi(c.PostForm("port"))
		service := c.PostForm("service")
		username := c.PostForm("username")
		password := c.PostForm("password")

		if !helpers.CreateCredentials(ip, hostname, service, username, password, port) {
			c.HTML(http.StatusInternalServerError, "credentials.html", gin.H{"error": "Failed to create credential data"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/credentials")
	}
}

func DeleteCredentialPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.PostForm("id"))

		if !helpers.DeleteCredential(id) {
			c.HTML(http.StatusInternalServerError, "credentials.html", gin.H{"error": "Failed to delete credential data"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/credentials")
	}
}

func DeleteBoxPostHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.PostForm("ip")

		if !helpers.DeleteBox(ip) {
			c.HTML(http.StatusInternalServerError, "boxes.html", gin.H{"error": "Failed to delete box data"})
			return
		} 
		c.Redirect(http.StatusMovedPermanently, "/dashboard/boxes")
	}
}
