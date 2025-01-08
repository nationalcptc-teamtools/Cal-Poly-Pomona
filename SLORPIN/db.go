package main

import (
	"fmt"
	"slorpin/models"
)

func dbGetBoxes() ([]models.Box, error) {
	var boxes []models.Box

	subquery := db.Table("boxes").Select("id,MAX(timestamp)").Group("ip")
	result := db.Table("boxes").Joins("INNER JOIN (?) as grouped on boxes.id = grouped.id", subquery).Find(&boxes)

	if result.Error != nil {
		return nil, result.Error
	}

	return boxes, nil
}

func dbGetWebs() ([]models.Web, error) {
	var webs []models.Web

	subquery := db.Table("webs").Select("id,MAX(timestamp)").Group("ip")
	result := db.Table("webs").Joins("INNER JOIN (?) as grouped on webs.id = grouped.id", subquery).Find(&webs)

	if result.Error != nil {
		return nil, result.Error
	}

	return webs, nil
}

func dbGetWeb(id int) (*models.Web, error) {
	var web models.Web

	subquery := db.Table("webs").Select("id, MAX(timestamp) AS max_time").Group("ip")
	result := db.Table("webs").Joins("INNER JOIN (?) as grouped ON webs.id = grouped.id AND webs.timestamp = grouped.max_time", subquery).
		Where("webs.id = ?", id).First(&web)

	if result.Error != nil {
		return nil, result.Error
	}

	return &web, nil
}

func dbGetDirectories() (map[uint][]models.Directory, error) {
	var directories []models.Directory

	subquery := db.Table("directories").
		Select("id, MAX(timestamp)").
		Group("web_id, path")

	result := db.Table("directories").
		Joins("INNER JOIN (?) as grouped on directories.id = grouped.id", subquery).
		Order("path").
		Find(&directories)

	if result.Error != nil {
		return nil, result.Error
	}
	directoryMap := map[uint][]models.Directory{}
	for _, directory := range directories {
		directoryMap[directory.WebID] = append(directoryMap[directory.WebID], directory)
	}
	return directoryMap, nil
}

func dbGetDirectoryIds(webId int) ([]int, error) {
	var ids []int

	result := db.Table("directories").Select("id").Where("web_id = ?", webId).Find(&ids)

	if result.Error != nil {
		return nil, result.Error
	}
	return ids, nil
}

func dbGetPorts() (map[uint][]models.Port, error) {
	var ports []models.Port

	subquery := db.Table("ports").
		Select("id, MAX(timestamp)").
		Group("box_id, port")

	result := db.Table("ports").
		Joins("INNER JOIN (?) as grouped on ports.id = grouped.id", subquery).
		Order("CAST(port AS UNSIGNED)").
		Find(&ports)

	if result.Error != nil {
		return nil, result.Error
	}
	portMap := map[uint][]models.Port{}
	for _, port := range ports {
		portMap[port.BoxID] = append(portMap[port.BoxID], port)
	}
	return portMap, nil
}

func dbGetNote(table string, id uint) (string, error) {
	var note string
	err := db.Table(table).Select("note").Where("id = ?", id).Row().Scan(&note)
	if err != nil {
		return "", err
	}
	return note, nil
}

func dbGetUser(id uint) (models.UserData, error) {
	var user models.UserData

	result := db.First(&user, id)

	if result.Error != nil {
		return models.UserData{}, result.Error
	}

	return user, nil
}

func dbGetUsers() (map[uint]models.UserData, error) {
	var users []models.UserData

	result := db.Table("user_data").Find(&users)

	if result.Error != nil {
		return nil, result.Error
	}

	userMap := map[uint]models.UserData{}
	for _, user := range users {
		userMap[user.ID] = user
	}
	return userMap, nil
}

func dbGetCredentials() ([]models.Credential, error) {
	var credentials []models.Credential

	result := db.Table("credentials").Find(&credentials)

	if result.Error != nil {
		return nil, result.Error
	}

	return credentials, nil
}

func dbAddCredential(credential *models.Credential) error {
	result := db.Create(&credential)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbEditCredential(credential *models.Credential) error {
	result := db.Model(credential).Select("username", "password", "note").Updates(&credential)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbDeleteCredential(id uint) error {
	result := db.Delete(&models.Credential{}, id)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbAddUsers(users []models.UserData) error {
	for _, user := range users {
		if db.Model(&user).Where("name = ?", user.Name).Updates(&user).RowsAffected == 0 {
			db.Create(&user)
		}
	}

	return nil
}

func dbUpdateBoxDetails(box *models.Box) error {
	subquery := db.Model(box).Select("id,MAX(timestamp)").Group("ip")
	result := db.Model(box).Select("usershells", "rootshells", "claimer_id").Joins("INNER JOIN (?) as grouped on boxes.id = grouped.id", subquery).Updates(box)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func dbUpdateWebDetails(web *models.Web) error {
	subquery := db.Model(web).Select("id,MAX(timestamp)").Group("ip")
	result := db.Model(web).Select("title", "backend").Joins("INNER JOIN (?) as grouped on webs.id = grouped.id", subquery).Updates(web)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func dbUpdateBoxNote(box *models.Box) error {
	subquery := db.Model(box).Select("id,MAX(timestamp)").Group("ip")
	result := db.Model(box).Select("note").Joins("INNER JOIN (?) as grouped on boxes.id = grouped.id", subquery).Updates(box)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func dbUpdateWebNote(web *models.Web) error {
	subquery := db.Model(web).Select("id,MAX(timestamp)").Group("ip")
	result := db.Model(web).Select("note").Joins("INNER JOIN (?) as grouped on webs.id = grouped.id", subquery).Updates(web)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func dbUpdateDirectoryNote(directory *models.Directory) error {
	subquery := db.Model(directory).Select("id,MAX(timestamp)").Group("ip")
	result := db.Model(directory).Select("note").Joins("INNER JOIN (?) as grouped on directories.id = grouped.id", subquery).Updates(directory)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func dbEditSettings(user *models.UserData) error {
	result := db.Model(user).Select("color").Updates(&user)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbPropagateData(box models.Box) (models.Box, error) {
	var oldBox models.Box

	// see if IP exists
	if err := db.Table("boxes").Where("ip = (?)", box.IP).First(&models.Box{}).Error; err != nil {
		return box, nil
	}

	subquery := db.Table("boxes").Select("id,ip,MAX(timestamp)").Group("ip")
	result := db.Table("boxes").Joins("INNER JOIN (?) as grouped on boxes.id = grouped.id", subquery).Where("boxes.IP = ?", box.IP).First(&oldBox)

	if result.Error != nil {
		return models.Box{}, result.Error
	}
	// these shouldn't change when merging scans
	box.ClaimerID = oldBox.ClaimerID
	box.Rootshells = oldBox.Rootshells
	box.Usershells = oldBox.Usershells
	box.Note = oldBox.Note

	return box, nil
}

func dbPropagateWeb(web models.Web) (models.Web, error) {
	var oldWeb models.Web

	// see if URL exists
	if err := db.Table("webs").Where("url = ?", web.URL).First(&models.Web{}).Error; err != nil {
		return web, nil
	}

	subquery := db.Table("webs").Select("id, url, MAX(timestamp)").Group("url")
	result := db.Table("webs").Joins("INNER JOIN (?) as grouped on webs.id = grouped.id", subquery).Where("webs.url = ?", web.URL).First(&oldWeb)

	if result.Error != nil {
		return models.Web{}, result.Error
	}

	// these shouldn't change when merging scans
	web.Note = oldWeb.Note

	return web, nil
}

func findOrCreateWeb(web models.Web) (uint, error) {
	var oldWeb models.Web

	// Check if URL exists
	result := db.Table("webs").Where("url = ?", web.URL).First(&oldWeb)

	if result.RowsAffected > 0 {
		// URL exists, return the ID
		fmt.Println("URL EXISTS, RETURNING OLD OBJECT")
		return oldWeb.ID, nil
	}

	// URL does not exist, create a new instance
	newWeb := models.Web{
		URL:  web.URL,
		IP:   web.IP,
		Port: web.Port,
	}
	createResult := db.Table("webs").Create(&newWeb)

	if createResult.Error != nil {
		return 0, createResult.Error
	}

	// Return the ID of the newly created entry
	fmt.Println("NEW DATABASE ENTRY JUST DROPPED")
	return newWeb.ID, nil
}

func dbGetTasks() ([]models.Task, error) {
	var tasks []models.Task

	result := db.Preload("Assignee").Find(&tasks)

	if result.Error != nil {
		return nil, result.Error
	}

	return tasks, nil
}

func dbGetMyTasks(id uint) ([]models.Task, error) {
	var tasks []models.Task

	result := db.Preload("tasks").Find(&tasks)

	if result.Error != nil {
		return nil, result.Error
	}

	return tasks, nil
}

func dbAddTask(task *models.Task) error {
	result := db.Create(&task)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbEditTask(task *models.Task) error {
	result := db.Model(task).Select("note", "due_time", "status", "assignee_id").Updates(&task)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func dbDeleteTask(id uint) error {
	result := db.Delete(&models.Task{}, id)

	if result.Error != nil {
		return result.Error
	}

	return nil
}
