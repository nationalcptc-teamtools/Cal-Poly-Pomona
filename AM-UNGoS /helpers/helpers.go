package helpers

import (
	"log"
	"fmt"
	"strings"
	"database/sql"
	"io/ioutil"
	"mime/multipart"
	"encoding/xml"

	_ "github.com/mattn/go-sqlite3"
)

type DashboardStats struct {
	TotalBoxes	int
	PwnedBoxes	int
	UserShells	int
	RootShells	int
}

type DBCredential struct {
	ID		int
	IP		string
	Hostname	string
	Port		int
	Service		string
	Username	string
	Password	string
}

type DBPort struct {
	ID		int
	Port		int
	Protocol	string
	Service		string
	IP		string
}

type Box struct {
	IP		string
	Hostname	string
	Ports		[]string
	NMAPResults	string
	Codename	string
	Assignee	int
	Color		string
	UserShells	int
	RootShells	int
}

type Hosts struct {
	XMLName xml.Name	`xml:"nmaprun"`
	Hosts	[]Host		`xml:"host"`
}

type Host struct {
	XMLName		xml.Name	`xml:"host"`
	IPs		[]Address	`xml:"address"`
	Hostnames 	[]Hostname	`xml:"hostnames>hostname"`
	Ports		[]Port		`xml:"ports>port"`
}

type Service struct {
	XMLName		xml.Name	`xml:"service"`
	Name		string		`xml:"name,attr"`
}

type Port struct {
	XMLName		xml.Name	`xml:"port"`
	Port		int		`xml:"portid,attr"`
	Protocol	string		`xml:"protocol,attr"`
	Service		Service		`xml:"service"`
}

type Hostname struct {
	XMLName	xml.Name	`xml:"hostname"`
	Name	string		`xml:"name,attr"`
}

type Address struct {
	XMLName xml.Name	`xml:"address"`
	Addr	string		`xml:"addr,attr"`
	AddType	string		`xml:"addrtype,attr"`
}

type DBUser struct {
	ID		int
	Username	string
	Password	string
	Color		string
}

func GetProfile(user string) (*DBUser, error) {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	stmt, err := db.Prepare("SELECT * FROM users WHERE username = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	
	var profile DBUser

	err = stmt.QueryRow(user).Scan(&profile.ID, &profile.Username, &profile.Password, &profile.Color)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	
	return &profile, nil
}

func UpdatePassword (password string, id int) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()

	stmt, err := db.Prepare("UPDATE users SET password = ? WHERE user_id = ?")
	if err != nil {
		return false
	}
	defer stmt.Close()

	_, err = stmt.Exec(password, id)
	
	if err != nil {
		return false
	}
	defer stmt.Close()

	return true
}

func UpdateColor (color string, id int) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()

	stmt, err := db.Prepare("UPDATE users SET color = ? WHERE user_id = ?")
	if err != nil {
		return false
	}
	defer stmt.Close()

	_, err = stmt.Exec(color, id)
	
	if err != nil {
		return false
	}
	defer stmt.Close()

	return true
}

func GetCredentials() ([]DBCredential, error) {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT * FROM credentials")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var credentials []DBCredential

	for rows.Next() {
		var credential DBCredential
		if err := rows.Scan(&credential.ID, &credential.IP, &credential.Hostname, &credential.Port, &credential.Service, &credential.Username, &credential.Password); err != nil {
			log.Println(err)
			return credentials, err
		}
		credentials = append(credentials, credential)
	}
	if err = rows.Err(); err != nil {
		return credentials, err
	}
	return credentials, nil
}

func DeleteCredential (id int) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("DELETE FROM credentials WHERE credential_id = ?")
	if err != nil {
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(id)
	
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func CreateCredentials (ip, hostname, service, username, password string, port int) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("INSERT INTO credentials (ip, hostname, port, service, username, password) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(ip, hostname, port, service, username, password)
	
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func UpdateCodename (codename, ip string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("UPDATE boxes SET codename = ? WHERE ip = ?")
	if err != nil {
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(codename, ip)
	
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func GetUsernames () ([]string, error) {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	stmt, err := db.Prepare("SELECT username FROM users")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var usernames []string

	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			log.Println(err)
			return usernames, err
		}
		usernames = append(usernames, username)
	}
	return usernames, nil
}

func UpdateAssignee (assign_id int, ip string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("UPDATE boxes SET assignee = ? WHERE ip = ?")
	if err != nil {
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(assign_id, ip)
	
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func UpdateShells (shells int, ip string, shelltype string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	var stmt *sql.Stmt
	if shelltype == "user" {
		stmt, err = db.Prepare("UPDATE boxes SET usershells = ? WHERE ip = ?")
	} else if shelltype == "root" {
		stmt, err = db.Prepare("UPDATE boxes SET rootshells = ? WHERE ip = ?")
	} else {
		return false
	}
	if err != nil {
		return false
	}
	defer stmt.Close()
	_, err = stmt.Exec(shells, ip)
	log.Println("test")
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func GetStats () (*DashboardStats, error) {
	boxes, err := GetBoxes()
	if err != nil {
		return nil, err
	}

	var stats DashboardStats 
	stats.TotalBoxes = len(boxes)
	for _, box := range boxes {
		if box.UserShells > 0 || box.RootShells > 0 {
			stats.PwnedBoxes += 1
		}
		stats.UserShells += box.UserShells
		stats.RootShells += box.RootShells
	}
	return &stats, nil
}

func GetBoxes () ([]Box, error) {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT * FROM boxes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var boxes []Box

	for rows.Next() {
		var box Box
		if err := rows.Scan(&box.IP, &box.Hostname, &box.NMAPResults, &box.Codename, &box.Assignee, &box.UserShells, &box.RootShells); err != nil {
			log.Println(err)
			return boxes, err
		}
		var ports []string
		dbports, err := db.Query("SELECT * FROM ports WHERE box_ip = ?", box.IP)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for dbports.Next() {
			var dbport DBPort
			if err := dbports.Scan(&dbport.ID, &dbport.Port, &dbport.Protocol, &dbport.Service, &dbport.IP); err != nil {
				return nil, err
			}
			ports = append(ports, fmt.Sprintf("Port %d/%s %s", dbport.Port, dbport.Protocol, dbport.Service))
		}
		if err = dbports.Err(); err != nil {
			return boxes, err
		}
		box.Ports = ports
		stmt, err := db.Prepare("SELECT color FROM users WHERE user_id = ?")
		if err != nil {
			return boxes, err
		}
		defer stmt.Close()

		err = stmt.QueryRow(box.Assignee).Scan(&box.Color)
		if err != nil {
			return boxes, err
		}
		defer stmt.Close()

		boxes = append(boxes, box)
	}
	if err = rows.Err(); err != nil {
		return boxes, err
	}
	return boxes, nil
}

func UploadFile (file *multipart.FileHeader) bool {
	content, _ := file.Open()
	bytes, err := ioutil.ReadAll(content)
	if err != nil {
		return false
	}
	var hosts Hosts
	xml.Unmarshal(bytes, &hosts)
	for _, host := range hosts.Hosts {
		for _, addr := range host.IPs {
			// skip router
			if addr.AddType != "ipv4" || (addr.AddType == "ipv4" && addr.Addr[strings.LastIndex(addr.Addr, ".")+1:] == "1") {
				log.Println("Skipping because it is a router or has no ipv4:",addr.Addr)
				continue
			}
			// skip router
			var ip string
			var hostname string
			var nmapresults string
			var codename string
			ip = addr.Addr
			if len(host.Hostnames) > 0 {
				hostname = host.Hostnames[0].Name
			}
			db, err := sql.Open("sqlite3", "database.db")
			if err != nil {
				return false
			}
			defer db.Close()
			
			stmt, err := db.Prepare("SELECT COUNT(*) FROM  boxes WHERE ip = ?")
			if err != nil {
				return false
			}
			defer stmt.Close()
			var existingbox int
			err = stmt.QueryRow(ip).Scan(&existingbox)
			
			if err != nil {
				return false
			}
			defer stmt.Close()
			// create box entry
			if existingbox > 0 {
				stmt, err := db.Prepare("UPDATE boxes SET hostname = ?, nmapresults = ? WHERE ip = ?")

				if err != nil {
					return false
				}
				defer stmt.Close()

				_, err = stmt.Exec(hostname, nmapresults, ip)
				if err != nil {
					return false
				}
				defer stmt.Close()
			} else {
				stmt, err := db.Prepare("INSERT INTO boxes (ip, hostname, nmapresults, codename) VALUES (?, ?, ?, ?)")

				if err != nil {
					return false
				}
				defer stmt.Close()

				_, err = stmt.Exec(ip, hostname, nmapresults, codename)
				if err != nil {
					return false
				}
				defer stmt.Close()
			}
			// create port entries
			if len(host.Ports) > 0 {
				var skip bool
				for _, port := range host.Ports {
					skip = false
					rows, err := db.Query("SELECT * FROM ports WHERE box_ip = ?", ip)
					if err != nil {
						return false
					}
					defer rows.Close()
					for rows.Next() {
						var dbport DBPort
						if err := rows.Scan(&dbport.ID, &dbport.Port, &dbport.Protocol, &dbport.Service, &dbport.IP); err != nil {
							return false
						}
						if port.Port == dbport.Port && port.Protocol == dbport.Protocol {
							skip = true
						} 
					}
					if skip == true {
						continue
					}
					stmt, err := db.Prepare("INSERT INTO ports (port_number, protocol, service_name, box_ip) VALUES (?, ?, ?, ?)")
					if err != nil {
						return false
					}
					defer stmt.Close()

					_, err = stmt.Exec(port.Port, port.Protocol, port.Service.Name, ip)
					if err != nil {
						return false
					}
					defer stmt.Close()
				}
			}
			db.Close()
		}
	}
	return true
}

func RegisterUser (username, password string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("INSERT INTO users (username, password) VALUES (?, ?)")

	if err != nil {
		return false
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, password)
	if err != nil {
		return false
	}
	defer stmt.Close()
	return true
}

func CheckExistingUser(username string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("SELECT count(*) FROM users WHERE username = ? AND user_id > 0")

	if err != nil {
		return false
	}
	defer stmt.Close()
	var existinguser int
	err = stmt.QueryRow(username).Scan(&existinguser)
	if err != nil {
		return false
	}
	defer stmt.Close()
	if existinguser == 0 {
		return true
	}
	return false
}

func CheckUserPass(username, password string) bool {
	db, err := sql.Open("sqlite3", "database.db")
	if err != nil {
		return false
	}
	defer db.Close()
	stmt, err := db.Prepare("SELECT password FROM users WHERE username = ?")

	if err != nil {
		return false
	}
	defer stmt.Close()

	var dbpass string
	err = stmt.QueryRow(username).Scan(&dbpass)
	if err != nil {
		return false
	}
	defer stmt.Close()

	if dbpass == password {
		log.Println(fmt.Sprintf("User %s logged in", username))
		return true
	} else {
		return false
	}
}

func EmptyUserPass(username, password string) bool {
	return strings.Trim(username, " ") == "" || strings.Trim(password, " ") == ""
}
