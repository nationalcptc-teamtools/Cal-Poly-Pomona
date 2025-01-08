package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"slorpin/models"
)

func addPublicRoutes(g *gin.RouterGroup) {
	g.GET("/", viewIndex)
	g.GET("/login", viewLogin)
	g.POST("/login", login)
}

func addPrivateRoutes(g *gin.RouterGroup) {
	// generic
	g.GET("/about", viewAbout)
	g.GET("/logout", logout)
	g.GET("/dashboard", viewDashboard)
	g.GET("/settings", viewSettings)
	g.POST("/settings/edit/:userId", editSettings)
	g.GET("/sse", stream.serveHTTP(), sse)

	/* inventory */
	// boxes
	g.GET("/boxes", viewBoxes)
	g.GET("/web", viewWebsites)
	g.GET("/boxes/export", viewExportBoxes)
	g.POST("/boxes/upload", uploadNmap)
	g.POST("/web/upload", uploadGobuster)
	g.POST("/boxes/edit/details/:boxId", editBoxDetails)
	g.POST("/web/edit/details/:webId", editWebDetails)
	g.POST("/boxes/edit/note/:boxId", editBoxNote)
	g.POST("/web/edit/note/:webId", editWebNote)
	g.POST("/web/edit/directory/note/:directoryId", editDirectoryNote)
	g.GET("/boxes/note/:boxId", viewBoxNote)
	g.GET("/web/note/:webId", viewWebNote)
	g.GET("/web/directory/note/:directoryId", viewDirectoryNote)
	g.GET("/api/boxes", getBoxes)
	g.GET("/api/web/:webId", getWeb)
	g.GET("/web/directories/:webId", getWebDirectoryIds)

	// credentials
	g.GET("/credentials", viewCredentials)
	g.POST("/credentials/add", addCredential)
	g.POST("/credentials/edit/:credentialId", editCredential)
	g.POST("/credentials/delete/:credentialId", deleteCredential)

	/* tasks */
	g.GET("/tasks", viewTasks)
	g.POST("/tasks/add", addTask)
	g.POST("/tasks/edit/:taskId", editTask)
	g.POST("/tasks/delete/:taskId", deleteTask)
}

func pageData(c *gin.Context, title string, ginMap gin.H) gin.H {
	newGinMap := gin.H{}
	newGinMap["title"] = title
	newGinMap["user"] = getUser(c)
	newGinMap["config"] = tomlConf
	newGinMap["operation"] = tomlConf.Operation
	// newGinMap["boxes"] = boxes
	for key, value := range ginMap {
		newGinMap[key] = value
	}
	return newGinMap
}

// public routes

func viewIndex(c *gin.Context) {
	if !getUser(c).IsValid() {
		c.Redirect(http.StatusSeeOther, "/login")
	}
	c.HTML(http.StatusOK, "index.html", pageData(c, "SLORPIN", nil))
}

func viewLogin(c *gin.Context) {
	if getUser(c).IsValid() {
		c.Redirect(http.StatusSeeOther, "/dashboard")
	}
	c.HTML(http.StatusOK, "login.html", pageData(c, "Login", nil))
}

// private routes

func viewDashboard(c *gin.Context) {
	boxes, err := dbGetBoxes()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "dashboard.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}

	pwnCount := 0
	usershells := 0
	rootshells := 0
	for _, box := range boxes {
		if box.Usershells > 0 || box.Rootshells > 0 {
			pwnCount++
			usershells += box.Usershells
			rootshells += box.Rootshells
		}
	}
	c.HTML(http.StatusOK, "dashboard.html", pageData(c, "Dashboard", gin.H{"boxes": boxes, "pwnCount": pwnCount, "percent": (100 * float32(pwnCount) / float32(len(boxes))), "usershells": usershells, "rootshells": rootshells}))
}

func viewSettings(c *gin.Context) {
	user := getUser(c)
	c.HTML(http.StatusOK, "settings.html", pageData(c, "Settings", gin.H{"user": user}))
}

func editSettings(c *gin.Context) {
	user := getUser(c)
	user.Color = c.PostForm("color")
	err := dbEditSettings(&user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Saved changes!"})
}

func viewBoxes(c *gin.Context) {
	boxes, err := dbGetBoxes()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	ports, err := dbGetPorts()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	users, err := dbGetUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "boxes.html", pageData(c, "Boxes", gin.H{"boxes": boxes, "ports": ports, "users": users}))
}

func viewWebsites(c *gin.Context) {
	webs, err := dbGetWebs()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	directories, err := dbGetDirectories()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	users, err := dbGetUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "web.html", pageData(c, "Web", gin.H{"webs": webs, "directories": directories, "users": users}))
}

func viewExportBoxes(c *gin.Context) {
	boxes, err := dbGetBoxes()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	ports, err := dbGetPorts()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	users, err := dbGetUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"boxes": boxes, "ports": ports, "users": users}))
}

func viewAbout(c *gin.Context) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(tomlConf); err != nil {
		c.HTML(http.StatusInternalServerError, "settings.html", pageData(c, "Settings", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "about.html", pageData(c, "About", gin.H{"config": buf.String()}))
}

type Upload struct {
	Files []*multipart.FileHeader `form:"files" binding:"required"`
}

type Script []struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
	Elem   struct {
		Key string `xml:"key,attr"`
	} `xml:"elem"`
}

func removeBlankLines(input string) string {
	var result strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(input))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			result.WriteString(line + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading string:", err)
	}

	return result.String()
}

func formatFingerprint(script Script) string {
	output := ""

	for _, script := range script {
		output += fmt.Sprintf("%s:\n\t%s\n", script.ID, script.Output)
	}

	cleanString := removeBlankLines(output)
	fmt.Println(cleanString)

	return cleanString
}

func uploadNmap(c *gin.Context) {
	var form Upload
	err := c.ShouldBind(&form)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	var nmapXML models.Nmaprun
	var box models.Box
	var port models.Port
	var dataErrors []string
	var fileErrors int
	var boxCount int

	for _, formFile := range form.Files {
		errorOnIteration := false
		openedFile, _ := formFile.Open()
		file, _ := io.ReadAll(openedFile)

		err := xml.Unmarshal(file, &nmapXML)
		if err != nil {
			return
		}
		log.Println(fmt.Sprintf("Upload %s success!", formFile.Filename))
		for _, host := range nmapXML.Host {
			boxCount++

			box = models.Box{
				Status: host.Status.State,
			}

			// Extract the IP address
			for _, address := range host.Address {
				if address.Addrtype == "ipv4" {
					box.IP = address.Addr
				}
			}

			// Extract Hostname
			for _, p := range host.Ports.Port {
				if p.Service.Hostname != "" {
					box.Hostname = p.Service.Hostname
					break
				}
			}

			// Extract OS
			for _, p := range host.Ports.Port {
				if p.Service.Ostype != "" {
					box.OS = p.Service.Ostype
					break
				}
			}

			// Store the box
			box, err = dbPropagateData(box)
			if err != nil {
				dataErrors = append(dataErrors, errors.Wrap(err, "Data propagation error:").Error())
				errorOnIteration = true
			}
			_ = db.Create(&box)

			// Process ports
			for _, p := range host.Ports.Port {
				port = models.Port{
					Port:        p.Portid,
					BoxID:       box.ID,
					Protocol:    p.Protocol,
					State:       p.State.State,
					Service:     p.Service.Name,
					Tunnel:      p.Service.Tunnel,
					Fingerprint: formatFingerprint(p.Script),
					Version:     p.Service.Version,
				}
				db.Create(&port)
			}
		}
		if errorOnIteration {
			fileErrors++
		}
	}
	if len(dataErrors) != 0 {
		for err := range dataErrors {
			c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": err})
		}
	}
	sendSSE([]string{"boxes", "ports", "dirty"})
	c.JSON(http.StatusOK, gin.H{"status": true, "message": fmt.Sprintf("Received %d file(s) successfully! Found %d box(es) successfully.", len(form.Files)-fileErrors, boxCount-len(dataErrors))})
}

func mapStatusCode(statusCode int) string {
	message := http.StatusText(statusCode)
	if message == "" {
		return "Unknown"
	}
	return message
}

func extractURL(scan string) string {
	re := regexp.MustCompile(`https?://[^/ \n]+`)
	match := re.FindString(scan)
	fmt.Println(match)
	if match != "" {
		testre := regexp.MustCompile(`[^a-zA-Z0-9/:.-]`)
		strippedString := testre.ReplaceAllString(match, "")
		return strippedString
	}
	return ""
}

func extractIP(url string) string {
	re := regexp.MustCompile(`((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`)
	match := re.FindString(url)
	return match
}

func extractPort(url string) int {
	parts := strings.Split(url, ":")
	var port int = 0

	if len(parts) > 2 {
		port, _ = strconv.Atoi(parts[len(parts)-1])
	} else {
		if strings.HasPrefix(url, "http") {
			port = 80
		}
		if strings.HasPrefix(url, "https") {
			port = 443
		}
	}
	return port
}

func extractDirectories(web *models.Web, scan string) {
	re := regexp.MustCompile(`(.+?)\s+\(Status: (\d+)\) \[Size: (\d+)]`)
	matches := re.FindAllStringSubmatch(scan, -1)

	var directory models.Directory
	for _, match := range matches {
		fmt.Println(match)
		if len(match) == 4 {
			statusCode := 0
			size := 0
			fmt.Sscanf(match[2], "%d", &statusCode)
			fmt.Sscanf(match[3], "%d", &size)
			directory = models.Directory{
				WebID:           web.ID,
				Path:            strings.Replace(match[1], web.URL, "", -1),
				ResponseCode:    statusCode,
				ResponseMessage: mapStatusCode(statusCode),
				Size:            size,
			}
			fmt.Println(directory)
			db.Create(&directory)
		}
	}
}

func uploadGobuster(c *gin.Context) {
	var form Upload
	err := c.ShouldBind(&form)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	var web models.Web
	var dataErrors []string
	var fileErrors int

	for _, formFile := range form.Files {
		errorOnIteration := false
		openedFile, _ := formFile.Open()
		file, _ := io.ReadAll(openedFile)

		// Initialize
		web = models.Web{}
		var webId uint

		// Extract
		url := extractURL(string(file))
		web.URL = url
		web.IP = extractIP(url)
		web.Port = extractPort(url)

		// Store
		webId, err = findOrCreateWeb(web)
		web, err := dbGetWeb(int(webId))
		if err != nil {
			dataErrors = append(dataErrors, errors.Wrap(err, "Data propagation error:").Error())
			//errorOnIteration = true
		}
		fmt.Println("WEB==========================" +
			"==========")
		fmt.Println(web)
		fmt.Println("WEB====================================")

		extractDirectories(web, string(file))
		if errorOnIteration {
			fileErrors++
		}
	}
	if len(dataErrors) != 0 {
		for err := range dataErrors {
			c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": err})
		}
	}
	sendSSE([]string{"web", "directories", "dirty"})
	c.JSON(http.StatusOK, gin.H{"status": true, "message": fmt.Sprintf("Received %d file(s) successfully!", len(form.Files)-fileErrors)})
}

func editBoxDetails(c *gin.Context) {
	boxId, err := strconv.ParseUint(c.Param("boxId"), 10, 32)
	claimerId, err := strconv.ParseUint(c.PostForm("claim"), 10, 32)
	usershells, err := strconv.Atoi(c.PostForm("usershells"))
	rootshells, err := strconv.Atoi(c.PostForm("rootshells"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedBox := models.Box{
		ID:         uint(boxId),
		Usershells: usershells,
		Rootshells: rootshells,
		ClaimerID:  uint(claimerId),
	}

	err = dbUpdateBoxDetails(&updatedBox)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	sendSSE([]string{"boxes"})
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Updated box details successfully!"})
}

func editWebDetails(c *gin.Context) {
	webId, err := strconv.ParseUint(c.Param("webId"), 10, 32)
	title := c.PostForm("title")
	backend := c.PostForm("backend")

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedweb := models.Web{
		ID:      uint(webId),
		Title:   title,
		Backend: backend,
	}

	err = dbUpdateWebDetails(&updatedweb)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	sendSSE([]string{"webs"})
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Updated web details successfully!"})
}

func editBoxNote(c *gin.Context) {
	boxId, err := strconv.ParseUint(c.Param("boxId"), 10, 32)
	note := c.PostForm("note")

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedBox := models.Box{
		ID:   uint(boxId),
		Note: note,
	}

	err = dbUpdateBoxNote(&updatedBox)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Updated box note successfully!"})
}

func editWebNote(c *gin.Context) {
	webId, err := strconv.ParseUint(c.Param("webId"), 10, 32)
	fmt.Println(webId)
	note := c.PostForm("note")

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedweb := models.Web{
		ID:   uint(webId),
		Note: note,
	}

	err = dbUpdateWebNote(&updatedweb)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Updated web note successfully!"})
}

func editDirectoryNote(c *gin.Context) {
	directoryId, err := strconv.ParseUint(c.Param("directoryId"), 10, 32)
	note := c.PostForm("note")

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedDirectory := models.Directory{
		ID:   uint(directoryId),
		Note: note,
	}

	err = dbUpdateDirectoryNote(&updatedDirectory)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Updated directory note successfully!"})
}

func viewBoxNote(c *gin.Context) {
	idParam := c.Param("boxId")
	id, err := strconv.ParseUint(idParam, 10, 32)

	note, err := dbGetNote("boxes", uint(id))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", pageData(c, "Note", gin.H{"error": err}))
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "note": note})
}

func viewWebNote(c *gin.Context) {
	idParam := c.Param("webId")
	id, err := strconv.ParseUint(idParam, 10, 32)

	note, err := dbGetNote("webs", uint(id))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", pageData(c, "Note", gin.H{"error": err}))
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "note": note})
}

func viewDirectoryNote(c *gin.Context) {
	idParam := c.Param("directoryId")
	id, err := strconv.ParseUint(idParam, 10, 32)

	note, err := dbGetNote("directories", uint(id))
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", pageData(c, "Note", gin.H{"error": err}))
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "note": note})
}

func viewCredentials(c *gin.Context) {
	boxes, err := dbGetBoxes()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	ports, err := dbGetPorts()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "export-boxes.html", pageData(c, "Export Boxes", gin.H{"error": err}))
		return
	}
	credentials, err := dbGetCredentials()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "credentials.html", pageData(c, "Credentials", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "credentials.html", pageData(c, "Credentials", gin.H{"boxes": boxes, "ports": ports, "credentials": credentials}))
}

func addCredential(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	note := c.PostForm("note")

	newCredential := models.Credential{
		Username: username,
		Password: password,
		Note:     note,
	}

	err := dbAddCredential(&newCredential)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Added credential successfully!"})
}

func editCredential(c *gin.Context) {
	credentialId, err := strconv.ParseUint(c.Param("credentialId"), 10, 32)
	username := c.PostForm("username")
	password := c.PostForm("password")
	note := c.PostForm("note")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	updatedCredential := models.Credential{
		ID:       uint(credentialId),
		Username: username,
		Password: password,
		Note:     note,
	}

	err = dbEditCredential(&updatedCredential)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Edited credential successfully!"})
}

func deleteCredential(c *gin.Context) {
	credentialId, err := strconv.ParseUint(c.Param("credentialId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	err = dbDeleteCredential(uint(credentialId))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Deleted credential successfully!"})
}

func sse(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Transfer-Encoding", "chunked")

	// Continuously send messages to the client
	v, ok := c.Get("clientChan")
	if !ok {
		return
	}
	clientChan, ok := v.(ClientChan)
	if !ok {
		return
	}
	c.Stream(func(w io.Writer) bool {
		// Stream message to client from message channel
		if msg, ok := <-clientChan; ok {
			c.SSEvent("message", msg)
			return true
		}
		return false
	})
}

func sendSSE(models []string) {
	if stream != nil {
		jsonString, err := json.Marshal(models)
		if err != nil {
			log.Printf("%s: %+v", errors.Wrap(err, "SSE json error").Error(), models)
			return
		}
		// send the message through the available channel
		stream.Message <- string(jsonString)
	}
}

func getBoxes(c *gin.Context) {
	boxes, err := dbGetBoxes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": errors.Wrap(err, "AJAX").Error()})
		return
	}
	users, err := dbGetUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": errors.Wrap(err, "AJAX").Error()})
		return
	}
	var boxIds []int
	jsonBoxes := map[int]models.Box{}
	for _, box := range boxes {
		boxIds = append(boxIds, int(box.ID))
		jsonBoxes[int(box.ID)] = box
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "boxIds": boxIds, "boxes": jsonBoxes, "users": users})
}

func getWeb(c *gin.Context) {
	idParam := c.Param("webId")
	id, err := strconv.ParseUint(idParam, 10, 32)

	web, err := dbGetWeb(int(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": errors.Wrap(err, "AJAX").Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "web": web})
}

func getWebDirectoryIds(c *gin.Context) {
	idParam := c.Param("webId")
	id, err := strconv.ParseUint(idParam, 10, 32)

	ids, err := dbGetDirectoryIds(int(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": false, "message": errors.Wrap(err, "AJAX").Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": true, "ids": ids})
}

func viewTasks(c *gin.Context) {
	users, err := dbGetUsers()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "tasks.html", pageData(c, "Tasks", gin.H{"error": err}))
		return
	}
	tasks, err := dbGetTasks()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "tasks.html", pageData(c, "Tasks", gin.H{"error": err}))
		return
	}
	c.HTML(http.StatusOK, "tasks.html", pageData(c, "Tasks", gin.H{"users": users, "tasks": tasks}))
}

type TaskForm struct {
	Assignee *int      `form:"assignee" binding:"required"`
	Note     string    `form:"note" binding:"required"`
	Status   string    `form:"status" binding:"required"`
	DueTime  time.Time `form:"due-time"`
}

func addTask(c *gin.Context) {
	var form TaskForm
	err := c.ShouldBind(&form)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	newTask := models.Task{
		AssigneeID: uint(*form.Assignee),
		Status:     form.Status,
		Note:       form.Note,
	}
	if !form.DueTime.IsZero() {
		newTask.DueTime = form.DueTime
	}

	err = dbAddTask(&newTask)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Added task successfully!"})
}

func editTask(c *gin.Context) {
	var form TaskForm
	err := c.ShouldBind(&form)
	taskId, err := strconv.ParseUint(c.Param("taskId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	newTask := models.Task{
		ID:         uint(taskId),
		DueTime:    form.DueTime,
		Status:     form.Status,
		Note:       form.Note,
		AssigneeID: uint(*form.Assignee),
	}

	err = dbEditTask(&newTask)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Edited task successfully!"})
}

func deleteTask(c *gin.Context) {
	taskId, err := strconv.ParseUint(c.Param("taskId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}

	err = dbDeleteTask(uint(taskId))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": false, "message": errors.Wrap(err, "Error").Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": true, "message": "Deleted task successfully!"})
}
