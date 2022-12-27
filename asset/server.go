/*
Server Management using Golang.
This file contains funtions related to add asset,list all asset as infra admin(role).
*/
package asset

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	dbs "servermanagement.com/infraadmin/database"
)

type Asset[T any] struct {
	Asset_Id                int       `json:"Asset_Id"`
	Asset_Name              string    `json:"Asset_Name"`
	Server_Serial           string    `json:"Server_Serial"`
	Server_Model            string    `json:"Server_Model"`
	Manufacturer            string    `json:"Manufacturer"`
	Owner                   string    `json:"Owner"`
	Category                string    `json:"Category"`
	Still_needed            bool      `json:"Still_needed"`
	Current_Project         string    `json:"Current_Project"`
	Notes                   string    `json:"Notes"`
	Previous_Project        string    `json:"Previous_Project"`
	BOM                     string    `json:"BOM"`
	Support_case            string    `json:"Support_case"`
	Cluster_Id              string    `json:"Cluster_Id"`
	Asset_Location          string    `json:"Asset_Location"`
	Lab                     string    `json:"Lab"`
	Row                     int       `json:"Row"`
	Rack                    int       `json:"Rack"`
	RU                      int       `json:"RU"`
	DC_status               string    `json:"DC_status"`
	Cpu_model               string    `json:"Cpu_model"`
	Generation              string    `json:"Generation"`
	CPU_Sockets             string    `json:"CPU_Sockets"`
	PDU_IP                  string    `json:"PDU_IP"`
	PDU_User                string    `json:"PDU_User"`
	PDU_Password            string    `json:"PDU_Password"`
	BMC_IP                  string    `json:"BMC_IP"`
	BMC_User                string    `json:"BMC_User"`
	BMC_Password            string    `json:"BMC_Password"`
	BMC_FQDN                string    `json:"BMC_FQDN"`
	Operating_System        string    `json:"Operating_System"`
	OS_IP                   string    `json:"OS_IP"`
	OS_User                 string    `json:"OS_User"`
	OS_Password             string    `json:"OS_Password"`
	DIMM_Size               string    `json:"DIMM_Size"`
	DIMM_Capacity           string    `json:"DIMM_Capacity"`
	Storage_Vendor          string    `json:"Storage_Vendor"`
	Storage_Controller      string    `json:"Storage_Controller"`
	Storage_Capacity        string    `json:"Storage_Capacity"`
	Network_Type            bool      `json:"Network_Type"`
	Network_speed           string    `json:"Network_speed"`
	Number_Of_Network_Ports string    `json:"Number_Of_Network_Ports"`
	Special_Switching_Needs string    `json:"Special_Switching_Needs"`
	Required_Start_Date     time.Time `json:"Required_Start_Date"`
	Required_Finish_Date    time.Time `json:"Required_Finish_Date"`
	Created_on              time.Time `json:"Created_on"`
	Created_by              string    `json:"Created_by"`
	Assigned_to             T         `json:"Assigned_to"`
	Assigned_from           time.Time `json:"Assigned_from"`
	Assigned_by             string    `json:"Assigned_by"`
	Updated_on              time.Time `json:"Updated_on"`
	Updated_by              string    `json:"Updated_by"`
	Purpose                 string    `json:"Purpose"`
	Delete                  int       `json:"Delete"`
	Reserved                bool      `json:"Reserved"`
}
type userDetails struct {
	User_Id    int       `json:"User_Id"`
	Email_Id   string    `json:"Email_Id"`
	Password   string    `json:"Password"`
	First_Name string    `json:"First_Name"`
	Last_Name  string    `json:"Last_Name"`
	Created_on time.Time `json:"Created_on"`
	Created_by string    `json:"Created_by"`
	Updated_on time.Time `json:"Updated_on"`
	Updated_by string    `json:"Updated_by"`
	Role       string    `json:"Role"`
	Teams      string    `json:"Teams"`
	Delete     int       `json:"Delete"`
}
type Historic_details[T any] struct {
	Id            int       `json:"Id"`
	Asset_Id      int       `json:"Asset_Id"`
	Asset_Name    string    `json:"Asset_Name"`
	Created_on    time.Time `json:"Created_on"`
	Created_by    string    `json:"Created_by"`
	BMC_IP        string    `json:"BMC_IP"`
	Assigned_to   T         `json:"Assigned_to"`
	Assigned_from time.Time `json:"Assigned_from"`
	Updated_on    time.Time `json:"Updated_on"`
	Updated_by    string    `json:"Updated_by"`
	Remarks       string    `json:"Remarks"`
}
type Server_Request struct {
	Id                      int       `json:"Id"`
	User_No                 int       `json:"User_No"`
	Requester               string    `json:"Requester"`
	Required_Start_Date     time.Time `json:"Required_Start_Date"`
	Required_End_Date       time.Time `json:"Required_End_Date"`
	Manufacturer            string    `json:"Manufacturer"`
	Operating_System        string    `json:"Operating_System"`
	Cpu_model               string    `json:"Cpu_model"`
	CPU_Sockets             string    `json:"CPU_Sockets"`
	DIMM_Size               string    `json:"DIMM_Size"`
	DIMM_Capacity           string    `json:"DIMM_Capacity"`
	Storage_Vendor          string    `json:"Storage_Vendor"`
	Storage_Controller      string    `json:"Storage_Controller"`
	Storage_Capacity        string    `json:"Storage_Capacity"`
	Network_Type            bool      `json:"Network_Type"`
	Network_speed           string    `json:"Network_speed"`
	Number_Of_Network_Ports string    `json:"Number_Of_Network_Ports"`
	Special_Switching_Needs string    `json:"Special_Switching_Needs"`
	Chat                    string    `json:"Chat"`
	Request                 bool      `json:"Request"`
	Updated_on              time.Time `json:"Updated_on"`
	Updated_by              string    `json:"Updated_by"`
}

type Chats struct {
	Id      int        `json:"Id"`
	Comment [][]string `json:"Comment"`
}

type changepwd struct {
	Email_Id     string `json:"Email_Id"`
	Old_Password string `json:"Old_Password"`
	New_Password string `json:"New_Password"`
}
type Users_DETAILS struct {
	Email_Id string `json:"Email_Id"`
	Password string `json:"Password"`
}
type loginDetails struct {
	Email_Id string `json:"Email_Id"`
	Password string `json:"Password"`
}
type Claims struct {
	Username string `json:"Username"`
	jwt.StandardClaims
}

type Page struct {
	Count  int    `json:"Count"`
	Page   int    `json:"Page"`
	Search string `json:"Search"`
}

var db = dbs.Connect() //database connection using function
var secretkey string = "Infobellitsolution"
var jwtKey = []byte("InfobellItSolutions")
var v Server_Request

//----------------------------------------------------authorization file----------------------------------------------------------

func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Printf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	//SetupCORS(&w)
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Hello, %s", claims.Username)))
}

func HandleFunc() {
	mux := http.NewServeMux()

	//-------------------------------------------------------login----------------------------------------------------------------------
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Login(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var l loginDetails

		err := json.NewDecoder(r.Body).Decode(&l)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
			return
		}

		if l.Email_Id == "" || l.Password == "" {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "202", "Message": "Email/Password Can't be empty"})
			return

		} else {
			row := db.QueryRow("SELECT User_ID,Email_ID,Password,Role from Users where Email_ID = '" + l.Email_Id + "'")
			// if(row==null || [])
			var EMAIL, PASSWORD, ROLE string
			var id int
			ID := strconv.Itoa(id)
			err_scan := row.Scan(&ID, &EMAIL, &PASSWORD, &ROLE)
			fmt.Println(EMAIL)
			if err_scan != nil {
				//panic(err_scan.Error())
				fmt.Println(err_scan)
				//fmt.Println("error in email")
			}
			fmt.Println("Compared result :", CheckPasswordHash(l.Password, PASSWORD))
			if ID == "" || EMAIL == "" || PASSWORD == "" || ROLE == "" {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]string{"Status Code": "202", "Message": "Invalid Email"})
			} else if CheckPasswordHash(l.Password, PASSWORD) {
				expirationTime := time.Now().Add(time.Minute * 5)
				claims := &Claims{
					Username: EMAIL,
					StandardClaims: jwt.StandardClaims{
						ExpiresAt: expirationTime.Unix(),
					},
				}

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString(jwtKey)
				if err != nil {
					fmt.Println("Error in generating JWT Err : ", err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{"Message": "The server encountered an unexpected condition that prevented it from fulfilling the request", "Status Code": "500 "})

					return
				}

				// http.SetCookie(w, &http.Cookie{
				//  Name:    "token",
				//  Value:   tokenString,
				//  Expires: expirationTime,
				// })

				username := strings.Split(l.Email_Id, "@")
				json.NewEncoder(w).Encode(map[string]string{"User_Id": ID, "Role": ROLE, "Username": username[0], "Token": tokenString, "status": "200 OK", "Message": "Successfully Logged In"})
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"Status Code": "401", "Message": "Invalid password"})
			}

		}
	})

	//--------------------------------------------------------logout-----------------------------------------------------------------
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Logout(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodGet {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		cookie, err := r.Cookie("token")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenStr := cookie.Value

		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tokenStr, claims,
			func(t *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !tkn.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200ok", "Message": "successfully logout", "By:": claims.Username})
	})

	//----------------------------------------------------Change Password----------------------------------------------------------
	mux.HandleFunc("/ChangePassword", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func ChangePassword(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var p changepwd

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
			return
		}
		if p.Old_Password == "nil" || p.New_Password == "nil" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid input syntax"})
			return

		} else {
			//id := strconv.Itoa(p.User_id)
			row := db.QueryRow("SELECT Email_Id,Password from Users where Email_Id = $1", p.Email_Id)
			//fmt.Println(row)
			var db_user, Password string
			err_scan := row.Scan(&db_user, &Password)
			if err_scan != nil {
				//panic(err_scan.Error())
				fmt.Println(err_scan.Error())
			}
			if db_user == "" || Password == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid input syntax"})
			} else {
				//if user is available in table and password you entered matches the old password,new password is updated on table.
				temp_pwd, _ := GeneratehashPassword(p.New_Password)
				fmt.Println(temp_pwd)
				if CheckPasswordHash(p.Old_Password, Password) {
					hash_pwd, err_h := GeneratehashPassword(p.New_Password)
					fmt.Println(hash_pwd)
					if err_h != nil {
						log.Fatal(err_h)
					}
					change, err := db.Exec("update Users set Password =$1 where Email_Id=$2", hash_pwd, p.Email_Id)
					if err != nil {
						log.Fatal(err)
					}
					affectedRow, err := change.RowsAffected()
					if err != nil {
						log.Fatal(err)
					}
					json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "Password Updated", "updated row": affectedRow})
				} else {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"Status Code": "401", "Message": "Unauthorised Password"})

				}
			}

		}
	})

	//-----------------------------------------------------Reset password-----------------------------------------------------
	mux.HandleFunc("/ResetPassword", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func ResetPassword(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var p Users_DETAILS //declare a variable p for type Users_DETAILS
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		//To convert the password in the encrypted form
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(p.Password), 14)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid input syntax"})
			return
		}

		var EmailId string
		err = db.QueryRow("SELECT Email_Id from Users where Email_Id =$1", p.Email_Id).Scan(&EmailId)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User doesn't Exist", "err": err, "Status Code": "404"})
			return
		}
		_, err2 := db.Exec("UPDATE Users SET Password=$2 WHERE Email_Id=$1;", p.Email_Id, string(hashedPassword))

		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err2, "Status Code": "202 Accepted"})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Password Reset Successfully !", "Status Code": "200 OK"})

	})

	//------------------------------------------------add asset(creating asset)---------------------------------------------------------------------
	mux.HandleFunc("/add_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func AddAsset(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var assets Asset[int]
		var Asset_Id int
		Asset_Id = 0

		err := json.NewDecoder(r.Body).Decode(&assets)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
			return
		}

		err = db.QueryRow("Select Asset_Id from Asset where Asset_Id=$1", assets.Asset_Id).Scan(&Asset_Id)
		hashedPassword1, err := bcrypt.GenerateFromPassword([]byte(assets.PDU_Password), 8)
		hashedPassword2, err := bcrypt.GenerateFromPassword([]byte(assets.BMC_Password), 8)
		hashedPassword3, err := bcrypt.GenerateFromPassword([]byte(assets.OS_Password), 8)
		Asset_Id = Asset_Id + 1
		addStatement := `INSERT INTO asset (Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,Cluster_Id,Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,Updated_on,Updated_by,Purpose,Delete,Reserved) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,LOCALTIMESTAMP(0),$45,LOCALTIMESTAMP(0),$46,$47,'0','f')`
		_, err = db.Exec(addStatement, assets.Asset_Name, assets.Server_Serial, assets.Server_Model, assets.Manufacturer, assets.Owner, assets.Category, assets.Still_needed, assets.Current_Project, assets.Notes, assets.Previous_Project, assets.BOM, assets.Support_case, assets.Cluster_Id, assets.Asset_Location, assets.Lab, assets.Row, assets.Rack, assets.RU, assets.DC_status, assets.Cpu_model, assets.Generation, assets.CPU_Sockets, assets.PDU_IP, assets.PDU_User, string(hashedPassword1), assets.BMC_IP, assets.BMC_User, string(hashedPassword2), assets.BMC_FQDN, assets.Operating_System, assets.OS_IP, assets.OS_User, string(hashedPassword3), assets.DIMM_Size, assets.DIMM_Capacity, assets.Storage_Vendor, assets.Storage_Controller, assets.Storage_Capacity, assets.Network_Type, assets.Network_speed, assets.Number_Of_Network_Ports, assets.Special_Switching_Needs, assets.Required_Start_Date.Format("2006-01-02"), assets.Required_Finish_Date.Format("2006-01-02"), assets.Created_by, assets.Updated_by, assets.Purpose)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid input syntax for IP ", "Status Code": "400 ", "Error": err})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200 OK", "Message": "Recorded sucessfully"})
	})

	//----------------------------------------------------Platform Profile---------------------------------------------------------------------
	mux.HandleFunc("/platformProfile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func PlatformProfile(w http.ResponseWriter, r *http.Request) {
		//	SetupCORS(&w)
		if r.Method != http.MethodGet {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		b, _ := ioutil.ReadFile("PlatformProfile.json")
		rawIn := json.RawMessage(string(b))
		var objmap map[string]*json.RawMessage
		err := json.Unmarshal(rawIn, &objmap)
		if err != nil {
			fmt.Println(err)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"PlatformProfile": objmap, "Status Code": "200 OK", "Message": "Recorded sucessfully"})
	})

	//--------------------------------------------------------Assign Server--------------------------------------------------------------------------
	mux.HandleFunc("/assign_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Assign_asset(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var p Asset[int]
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid Syntax", "Status Code": "400 "})
			return
		}

		var reserved bool
		var delete int
		err = db.QueryRow("SELECT Reserved , Delete FROM Asset where Asset_ID=$1", p.Asset_Id).Scan(&reserved, &delete)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Already in Use", "Status Code": "401 "})
			return
		}
		if !reserved && delete == 0 {

			_, err = db.Exec("UPDATE asset SET Assigned_to=$2,Assigned_from=LOCALTIMESTAMP(0),Assigned_by=$3,Updated_on=LOCALTIMESTAMP(0),Updated_by=$4,reserved = 'true' WHERE Asset_ID=$1;", p.Asset_Id, p.Assigned_to, p.Assigned_by, p.Updated_by)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
				return
			}

			_, err := db.Exec(`INSERT into Historic_details (Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,Remarks)
		SELECT Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,'Server Assigned' FROM Asset where Asset_ID=$1`, p.Asset_Id)

			if err != nil {
				fmt.Println(err)
			}

			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Assigned", "Status Code": "200 OK"})

		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Can't be Assigned", "Status Code": "401"})

		}
	})

	//-------------------------------------------------Delete Server(Updating delete and reserved column in asset table)-------------------------------
	mux.HandleFunc("/delete_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Delete_asset(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var p Asset[int]
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		_, err = db.Exec("UPDATE asset SET Delete='1', Reserved = 'f' , Assigned_to = null, Assigned_by=null,Updated_on=LOCALTIMESTAMP(0),Updated_by=$2  WHERE Asset_Id=$1;", p.Asset_Id, p.Updated_by)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Deleted!", "Status Code": "200 OK"})
		row := db.QueryRow("SELECT Delete from asset where Asset_Id=$1;", p.Asset_Id)
		var del int
		err1 := row.Scan(&del)
		if err1 != nil {
			log.Fatal(err1)
		}
		if !p.Reserved && del == 1 {
			_, err := db.Query(`INSERT into Historic_details (Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_ON,Updated_by,Remarks) 
		SELECT Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,COALESCE(Assigned_from, '0001-01-01'),Updated_ON,Updated_by,'Server Deleted' FROM Asset where Asset_Id=$1`, p.Asset_Id)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}
		} else {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Update Required", "Status Code": "202"})
		}
	})

	//-----------------------------------------------------List server ------------------------------------------------
	mux.HandleFunc("/list_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func ListServer(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodGet {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		str := "SELECT Asset_Id,Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,COALESCE(Cluster_ID,''),Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,COALESCE(Assigned_to, 0),COALESCE(Assigned_from, '0001-01-01'),COALESCE(Assigned_by, ''),COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''),Purpose,Delete,Reserved FROM Asset"

		rows, err := db.Query(str)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		result := []Asset[string]{} // creating slice
		for rows.Next() {
			var Asset_Id, Assigned_to, Delete, Row, Rack, RU int
			var Asset_Name, Server_Serial, Server_Model, Manufacturer, OS_IP, OS_User, OS_Password,
				BMC_IP, BMC_User, BMC_Password, BMC_FQDN, Asset_Location,
				Assigned_by, Created_by, Updated_by, Cluster_Id, Purpose, Generation,
				Lab, DC_status, PDU_IP, PDU_User, PDU_Password, Owner, Category,
				Current_Project, Notes, Previous_Project, BOM, Support_case, Cpu_model, CPU_Sockets,
				DIMM_Capacity, DIMM_Size, Storage_Vendor, Storage_Controller,
				Storage_Capacity, Network_speed, Number_Of_Network_Ports, Special_Switching_Needs, Operating_System string
			var Created_on, Updated_on, Assigned_from, Required_Start_Date, Required_Finish_Date time.Time
			var Reserved, Still_needed, Network_Type bool

			err := rows.Scan(&Asset_Id, &Asset_Name, &Server_Serial, &Server_Model, &Manufacturer, &Owner, &Category, &Still_needed, &Current_Project, &Notes, &Previous_Project, &BOM, &Support_case, &Cluster_Id, &Asset_Location, &Lab, &Row, &Rack, &RU, &DC_status, &Cpu_model, &Generation, &CPU_Sockets, &PDU_IP, &PDU_User, &PDU_Password, &BMC_IP, &BMC_User, &BMC_Password, &BMC_FQDN, &Operating_System, &OS_IP, &OS_User, &OS_Password, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Required_Start_Date, &Required_Finish_Date, &Created_on, &Created_by, &Assigned_to, &Assigned_from, &Assigned_by, &Updated_on, &Updated_by, &Purpose, &Delete, &Reserved)

			if err != nil {
				fmt.Println(err)
				log.Printf("Failed to build content from sql rows: %v\n", err)

			}

			marshal, _ := json.Marshal(result)
			var c []Historic_details[string]
			var username []string
			var mail string
			var user string
			_ = json.Unmarshal(marshal, &c)
			err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
			if err != nil {
				fmt.Println(err)
			}
			username = strings.Split(mail, "@")
			user = username[0]
			result = append(result, Asset[string]{Asset_Id: Asset_Id, Asset_Name: Asset_Name, Server_Serial: Server_Serial, Server_Model: Server_Model, Manufacturer: Manufacturer, Owner: Owner, Category: Category, Still_needed: Still_needed, Current_Project: Current_Project, Notes: Notes, Previous_Project: Previous_Project, BOM: BOM, Support_case: Support_case, Cluster_Id: Cluster_Id, Asset_Location: Asset_Location, Lab: Lab, Row: Row, Rack: Rack, RU: RU, DC_status: DC_status, Cpu_model: Cpu_model, Generation: Generation, CPU_Sockets: CPU_Sockets, PDU_IP: PDU_IP, PDU_User: PDU_User, PDU_Password: PDU_Password, BMC_IP: BMC_IP, BMC_User: BMC_User, BMC_Password: BMC_Password, BMC_FQDN: BMC_FQDN, Operating_System: Operating_System, OS_IP: OS_IP, OS_User: OS_User, OS_Password: OS_Password, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Required_Start_Date: Required_Start_Date, Required_Finish_Date: Required_Finish_Date, Created_on: Created_on, Created_by: Created_by, Assigned_to: user, Assigned_from: Assigned_from, Assigned_by: Assigned_by, Updated_on: Updated_on, Updated_by: Updated_by, Purpose: Purpose, Delete: Delete, Reserved: Reserved})
		}
		rev_slc := []Asset[string]{}
		for i := range result {
			// reverse the order
			rev_slc = append(rev_slc, result[len(result)-1-i])
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ListAsset": rev_slc, "Status Code": "200 OK", "Message": "Listing All Servers"})
	})

	// ----------------------------------------------list of Reserved Assets-----------------------------------------------------------
	mux.HandleFunc("/list_asset/Reserved", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Reserved(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var pg Page
		err := json.NewDecoder(r.Body).Decode(&pg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var total int
		err2 := db.QueryRow("SELECT count(*) from asset where reserved='t'  and asset ::text ~* $1", pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		str := "SELECT Asset_Id,Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,COALESCE(Cluster_ID,''),Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,COALESCE(Assigned_to, 0),COALESCE(Assigned_from, '0001-01-01'),COALESCE(Assigned_by, ''),COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''),Purpose,Delete,Reserved FROM Asset WHERE Reserved='true' and asset ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;"
		rows, err := db.Query(str, pg.Count, pg.Page, pg.Search)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		result := []Asset[string]{} // creating slice
		for rows.Next() {
			var Asset_Id, Assigned_to, Delete, Row, Rack, RU int
			var Asset_Name, Server_Serial, Server_Model, Manufacturer, OS_IP, OS_User, OS_Password,
				BMC_IP, BMC_User, BMC_Password, BMC_FQDN,
				Asset_Location, Assigned_by, Created_by, Updated_by, Cluster_Id, Purpose, Generation,
				Lab, DC_status, PDU_IP, PDU_User, PDU_Password, Owner, Category,
				Current_Project, Notes, Previous_Project, BOM, Support_case, Cpu_model, CPU_Sockets,
				DIMM_Capacity, DIMM_Size, Storage_Vendor, Storage_Controller,
				Storage_Capacity, Network_speed, Number_Of_Network_Ports, Special_Switching_Needs, Operating_System string
			var Created_on, Updated_on, Assigned_from, Required_Start_Date, Required_Finish_Date time.Time
			var Reserved, Still_needed, Network_Type bool

			err := rows.Scan(&Asset_Id, &Asset_Name, &Server_Serial, &Server_Model, &Manufacturer, &Owner, &Category, &Still_needed, &Current_Project, &Notes, &Previous_Project, &BOM, &Support_case, &Cluster_Id, &Asset_Location, &Lab, &Row, &Rack, &RU, &DC_status, &Cpu_model, &Generation, &CPU_Sockets, &PDU_IP, &PDU_User, &PDU_Password, &BMC_IP, &BMC_User, &BMC_Password, &BMC_FQDN, &Operating_System, &OS_IP, &OS_User, &OS_Password, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Required_Start_Date, &Required_Finish_Date, &Created_on, &Created_by, &Assigned_to, &Assigned_from, &Assigned_by, &Updated_on, &Updated_by, &Purpose, &Delete, &Reserved)

			if err != nil {
				fmt.Println(err)
				log.Printf("Failed to build content from sql rows: %v\n", err)

			}

			marshal, _ := json.Marshal(result)
			var c []Historic_details[string]
			var username []string
			var mail string
			var user string
			_ = json.Unmarshal(marshal, &c)
			err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
			if err != nil {
				fmt.Println(err)
			}
			username = strings.Split(mail, "@")
			user = username[0]
			result = append(result, Asset[string]{Asset_Id: Asset_Id, Asset_Name: Asset_Name, Server_Serial: Server_Serial, Server_Model: Server_Model, Manufacturer: Manufacturer, Owner: Owner, Category: Category, Still_needed: Still_needed, Current_Project: Current_Project, Notes: Notes, Previous_Project: Previous_Project, BOM: BOM, Support_case: Support_case, Cluster_Id: Cluster_Id, Asset_Location: Asset_Location, Lab: Lab, Row: Row, Rack: Rack, RU: RU, DC_status: DC_status, Cpu_model: Cpu_model, Generation: Generation, CPU_Sockets: CPU_Sockets, PDU_IP: PDU_IP, PDU_User: PDU_User, PDU_Password: PDU_Password, BMC_IP: BMC_IP, BMC_User: BMC_User, BMC_Password: BMC_Password, BMC_FQDN: BMC_FQDN, Operating_System: Operating_System, OS_IP: OS_IP, OS_User: OS_User, OS_Password: OS_Password, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Required_Start_Date: Required_Start_Date, Required_Finish_Date: Required_Finish_Date, Created_on: Created_on, Created_by: Created_by, Assigned_to: user, Assigned_from: Assigned_from, Assigned_by: Assigned_by, Updated_on: Updated_on, Updated_by: Updated_by, Purpose: Purpose, Delete: Delete, Reserved: Reserved})
		} // appending deatils to the result
		// rev_slc := []Asset[string]{}
		// for i := range result {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, result[len(result)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "ListAsset": result, "Status Code": "200 OK", "Message": "Listing All Servers"})
	})

	// --------------------------------------------------list of pools Assets--------------------------------------------------------
	mux.HandleFunc("/list_asset/pool", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Pool(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var pg Page
		err := json.NewDecoder(r.Body).Decode(&pg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var total int
		err2 := db.QueryRow("SELECT count(*) from asset where reserved='f' and asset ::text ~* $1", pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		str := "SELECT Asset_Id,Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,COALESCE(Cluster_ID,''),Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,COALESCE(Assigned_to, 0),COALESCE(Assigned_from, '0001-01-01'),COALESCE(Assigned_by, ''),COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''),Purpose,Delete,Reserved FROM Asset WHERE (Delete=B'0' AND Reserved='false' OR Reserved is null) and asset ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;"

		rows, err := db.Query(str, pg.Count, pg.Page, pg.Search)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		result := []Asset[string]{} // creating slice
		for rows.Next() {

			var Asset_Id, Assigned_to, Delete, Row, Rack, RU int
			var Asset_Name, Server_Serial, Server_Model, Manufacturer, OS_IP, OS_User, OS_Password,
				BMC_IP, BMC_User, BMC_Password, BMC_FQDN,
				Asset_Location, Assigned_by, Created_by, Updated_by, Cluster_Id, Purpose, Generation,
				Lab, DC_status, PDU_IP, PDU_User, PDU_Password, Owner, Category,
				Current_Project, Notes, Previous_Project, BOM, Support_case, Cpu_model, CPU_Sockets,
				DIMM_Capacity, DIMM_Size, Storage_Vendor, Storage_Controller,
				Storage_Capacity, Network_speed, Number_Of_Network_Ports, Special_Switching_Needs, Operating_System string
			var Created_on, Updated_on, Assigned_from, Required_Start_Date, Required_Finish_Date time.Time
			var Reserved, Still_needed, Network_Type bool

			err := rows.Scan(&Asset_Id, &Asset_Name, &Server_Serial, &Server_Model, &Manufacturer, &Owner, &Category, &Still_needed, &Current_Project, &Notes, &Previous_Project, &BOM, &Support_case, &Cluster_Id, &Asset_Location, &Lab, &Row, &Rack, &RU, &DC_status, &Cpu_model, &Generation, &CPU_Sockets, &PDU_IP, &PDU_User, &PDU_Password, &BMC_IP, &BMC_User, &BMC_Password, &BMC_FQDN, &Operating_System, &OS_IP, &OS_User, &OS_Password, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Required_Start_Date, &Required_Finish_Date, &Created_on, &Created_by, &Assigned_to, &Assigned_from, &Assigned_by, &Updated_on, &Updated_by, &Purpose, &Delete, &Reserved)

			if err != nil {
				fmt.Println(err)
				log.Printf("Failed to build content from sql rows: %v\n", err)

			}

			marshal, _ := json.Marshal(result)
			var c []Historic_details[string]
			var username []string
			var mail string
			var user string
			_ = json.Unmarshal(marshal, &c)
			err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
			if err != nil {
				fmt.Println(err)
			}
			username = strings.Split(mail, "@")
			user = username[0]
			result = append(result, Asset[string]{Asset_Id: Asset_Id, Asset_Name: Asset_Name, Server_Serial: Server_Serial, Server_Model: Server_Model, Manufacturer: Manufacturer, Owner: Owner, Category: Category, Still_needed: Still_needed, Current_Project: Current_Project, Notes: Notes, Previous_Project: Previous_Project, BOM: BOM, Support_case: Support_case, Cluster_Id: Cluster_Id, Asset_Location: Asset_Location, Lab: Lab, Row: Row, Rack: Rack, RU: RU, DC_status: DC_status, Cpu_model: Cpu_model, Generation: Generation, CPU_Sockets: CPU_Sockets, PDU_IP: PDU_IP, PDU_User: PDU_User, PDU_Password: PDU_Password, BMC_IP: BMC_IP, BMC_User: BMC_User, BMC_Password: BMC_Password, BMC_FQDN: BMC_FQDN, Operating_System: Operating_System, OS_IP: OS_IP, OS_User: OS_User, OS_Password: OS_Password, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Required_Start_Date: Required_Start_Date, Required_Finish_Date: Required_Finish_Date, Created_on: Created_on, Created_by: Created_by, Assigned_to: user, Assigned_from: Assigned_from, Assigned_by: Assigned_by, Updated_on: Updated_on, Updated_by: Updated_by, Purpose: Purpose, Delete: Delete, Reserved: Reserved})
		} // appending deatils to the result
		// rev_slc := []Asset[string]{}
		// for i := range result {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, result[len(result)-1-i])
		// }

		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "ListAsset": result, "Status Code": "200 OK", "Message": "Listing All Servers"})
	})

	//--------------------------------------------------update asset details------------------------------------------------------
	mux.HandleFunc("/update_asset_details", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func UpdateAssetDetails(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var assets Asset[int]
		Delete := assets.Delete
		err := json.NewDecoder(r.Body).Decode(&assets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hashedPassword1, err := bcrypt.GenerateFromPassword([]byte(assets.PDU_Password), 8)
		hashedPassword2, err := bcrypt.GenerateFromPassword([]byte(assets.BMC_Password), 8)
		hashedPassword3, err := bcrypt.GenerateFromPassword([]byte(assets.OS_Password), 8)
		_, err1 := db.Exec("UPDATE Asset SET Asset_Name=$2,Server_Serial=$3,Server_model=$4,Manufacturer=$5,Owner=$6,Category=$7,Still_needed=$8,Current_Project=$9,Notes=$10,Previous_Project=$11,BOM=$12,Support_case=$13,Cluster_Id=$14,Asset_location=$15,Lab=$16,Row=$17,Rack=$18,RU=$19,DC_status=$20,Cpu_model=$21,Generation=$22,CPU_Sockets=$23,PDU_IP=$24,PDU_User=$25,PDU_Password=$26,BMC_IP=$27,BMC_User=$28,BMC_Password=$29,BMC_FQDN=$30,Operating_System=$31,OS_IP=$32,OS_User=$33,OS_Password=$34,DIMM_Size=$35,DIMM_Capacity=$36,Storage_Vendor=$37,Storage_Controller=$38,Storage_Capacity=$39,Network_Type=$40,Network_speed=$41,Number_Of_Network_Ports=$42,Special_Switching_Needs=$43,Required_Start_Date=$44,Required_Finish_Date=$45,Updated_on=LOCALTIMESTAMP(0),Updated_by=$46,Purpose=$47 WHERE Asset_ID=$1;",
			assets.Asset_Id, assets.Asset_Name, assets.Server_Serial, assets.Server_Model, assets.Manufacturer, assets.Owner, assets.Category, assets.Still_needed, assets.Current_Project, assets.Notes, assets.Previous_Project, assets.BOM, assets.Support_case, assets.Cluster_Id, assets.Asset_Location, assets.Lab, assets.Row, assets.Rack, assets.RU, assets.DC_status, assets.Cpu_model, assets.Generation, assets.CPU_Sockets, assets.PDU_IP, assets.PDU_User, string(hashedPassword1), assets.BMC_IP, assets.BMC_User, string(hashedPassword2), assets.BMC_FQDN, assets.Operating_System, assets.OS_IP, assets.OS_User, string(hashedPassword3), assets.DIMM_Size, assets.DIMM_Capacity, assets.Storage_Vendor, assets.Storage_Controller, assets.Storage_Capacity, assets.Network_Type, assets.Network_speed, assets.Number_Of_Network_Ports, assets.Special_Switching_Needs, assets.Required_Start_Date.Format("2006-01-02"), assets.Required_Finish_Date.Format("2006-01-02"), assets.Updated_by, assets.Purpose)
		if err1 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err1, "Status Code": "202 "})
			fmt.Println(err1)
			return
		}

		if Delete == 1 || Delete == 0 {
			_, err := db.Query(`INSERT into Historic_details (Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,Remarks)
            SELECT Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,'Server Updated' FROM Asset where Asset_ID=$1`, assets.Asset_Id)

			if err != nil {
				fmt.Println(err)
			}
			//fmt.Fprintf(w, "Record Updated!")
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Record Updated!", "Status Code": "200 OK"})

		} else {
			fmt.Println("No update is required")
		}
	})

	//----------------------------------------------Release server (updating Reserve table)------------------------
	mux.HandleFunc("/release_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Release(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var p Asset[int]
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			panic(err.Error())
		}
		var reserved bool
		err = db.QueryRow("SELECT Reserved FROM Asset where Asset_ID=$1", p.Asset_Id).Scan(&reserved)
		if err != nil {
			fmt.Println(err)

		}
		if reserved {

			_, err = db.Exec("UPDATE Asset SET Reserved='false',Assigned_to=null,Assigned_by=null,Updated_on=LOCALTIMESTAMP(0),Updated_by=$2 where Asset_ID=$1;", p.Asset_Id, p.Updated_by) // query for updating
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}

			_, err := db.Exec(`INSERT into Historic_details (Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,Remarks)
        	SELECT Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,LOCALTIMESTAMP(0),Updated_by,'Server Released' FROM Asset where Asset_ID=$1`, p.Asset_Id)

			if err != nil {
				fmt.Println(err)
			}

			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Released", "Status Code": "200 OK"})

		} else {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Server Can't be Released", "Status Code": "400"})

		}
	})

	//------------------------------------------------------getmyasset--------------------------------------------------------
	mux.HandleFunc("/my_asset", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func GetAsset(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		a, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var p Asset[int]
		if err := json.Unmarshal(a, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var pg Page
		if err := json.Unmarshal(a, &pg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var total int
		err2 := db.QueryRow("SELECT count(*) from asset where Reserved='Yes' AND Assigned_to=$1 and asset ::text ~* $2", p.Assigned_to, pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		// var pg Page
		// err := json.NewDecoder(r.Body).Decode(&pg)
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusBadRequest)
		// 	return
		// }

		// var p Asset[int]
		// err1 := json.NewDecoder(r.Body).Decode(&p)
		// if err1 != nil {
		// 	http.Error(w, err.Error(), http.StatusBadRequest)
		// 	return
		// }

		rows, err := db.Query("SELECT * from Asset where Reserved ='Yes' AND Assigned_to = $1 AND asset ::text ~* $4 order by updated_on desc limit $2 offset ($3-1)*$2;", p.Assigned_to, pg.Count, pg.Page, pg.Search)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}

		assets := []Asset[string]{}
		for rows.Next() {
			var Asset_Id, Assigned_to, Delete, Row, Rack, RU int
			var Asset_Name, Server_Serial, Server_Model, Manufacturer, OS_IP, OS_User, OS_Password,
				BMC_IP, BMC_User, BMC_Password, BMC_FQDN, Asset_Location,
				Assigned_by, Created_by, Updated_by, Cluster_Id, Purpose, Generation,
				Lab, DC_status, PDU_IP, PDU_User, PDU_Password, Owner, Category,
				Current_Project, Notes, Previous_Project, BOM, Support_case, Cpu_model, CPU_Sockets,
				DIMM_Capacity, DIMM_Size, Storage_Vendor, Storage_Controller,
				Storage_Capacity, Network_speed, Number_Of_Network_Ports, Special_Switching_Needs, Operating_System string
			var Created_on, Updated_on, Assigned_from, Required_Start_Date, Required_Finish_Date time.Time
			var Reserved, Still_needed, Network_Type bool

			err1 := rows.Scan(&Asset_Id, &Asset_Name, &Server_Serial, &Server_Model, &Manufacturer, &Owner, &Category, &Still_needed, &Current_Project, &Notes, &Previous_Project, &BOM, &Support_case, &Cluster_Id, &Asset_Location, &Lab, &Row, &Rack, &RU, &DC_status, &Cpu_model, &Generation, &CPU_Sockets, &PDU_IP, &PDU_User, &PDU_Password, &BMC_IP, &BMC_User, &BMC_Password, &BMC_FQDN, &Operating_System, &OS_IP, &OS_User, &OS_Password, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Required_Start_Date, &Required_Finish_Date, &Created_on, &Created_by, &Assigned_to, &Assigned_from, &Assigned_by, &Updated_on, &Updated_by, &Purpose, &Delete, &Reserved)

			if err1 != nil {
				log.Printf("Failed to build content from sql rows: %v \n", err1)
				return
			}
			marshal, _ := json.Marshal(assets)
			var c []Historic_details[string]
			var username []string
			var mail string
			var user string
			_ = json.Unmarshal(marshal, &c)
			err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
			if err != nil {
				fmt.Println(err)
			}
			username = strings.Split(mail, "@")
			user = username[0]
			assets = append(assets, Asset[string]{Asset_Id: Asset_Id, Asset_Name: Asset_Name, Server_Serial: Server_Serial, Server_Model: Server_Model, Manufacturer: Manufacturer, Owner: Owner, Category: Category, Still_needed: Still_needed, Current_Project: Current_Project, Notes: Notes, Previous_Project: Previous_Project, BOM: BOM, Support_case: Support_case, Cluster_Id: Cluster_Id, Asset_Location: Asset_Location, Lab: Lab, Row: Row, Rack: Rack, RU: RU, DC_status: DC_status, Cpu_model: Cpu_model, Generation: Generation, CPU_Sockets: CPU_Sockets, PDU_IP: PDU_IP, PDU_User: PDU_User, PDU_Password: PDU_Password, BMC_IP: BMC_IP, BMC_User: BMC_User, BMC_Password: BMC_Password, BMC_FQDN: BMC_FQDN, Operating_System: Operating_System, OS_IP: OS_IP, OS_User: OS_User, OS_Password: OS_Password, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Required_Start_Date: Required_Start_Date, Required_Finish_Date: Required_Finish_Date, Created_on: Created_on, Created_by: Created_by, Assigned_to: user, Assigned_from: Assigned_from, Assigned_by: Assigned_by, Updated_on: Updated_on, Updated_by: Updated_by, Purpose: Purpose, Delete: Delete, Reserved: Reserved})
		}
		// rev_slc := []Asset[string]{}
		// for i := range assets {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, assets[len(assets)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "ListAsset": assets, "Status Code": "200 OK", "Message": "Listing Specified Servers"})

		if len(assets) == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "User Not Found", "Status Code": "404 "})
			return
		}
	})

	//-------------------------------------------Historic Details(By Asset ID)-----------------------------------------------------------------------------------------------
	mux.HandleFunc("/historic_details_id", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		a, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var p Historic_details[int]
		if err := json.Unmarshal(a, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var pg Page
		if err := json.Unmarshal(a, &pg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var total int
		err2 := db.QueryRow("SELECT count(*) from historic_details where asset_id=$1 and historic_details ::text ~* $2", p.Asset_Id, pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		rows, err := db.Query("SELECT Id, Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,COALESCE(Assigned_to, 0), COALESCE(Assigned_from, '0001-01-01'), COALESCE(Updated_on,'0001-01-01'), Updated_by,Remarks FROM Historic_details WHERE Asset_ID=$1 AND historic_details ::text ~* $4 order by updated_on desc limit $2 offset ($3-1)*$2;", p.Asset_Id, pg.Count, pg.Page, pg.Search)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		result := []Historic_details[string]{} // creating slice
		for rows.Next() {

			var Id, Asset_Id, Assigned_to int
			var Created_by, Updated_by, Remarks, Asset_Name, BMC_IP string
			var Created_on, Updated_on, Assigned_from time.Time

			err := rows.Scan(&Id, &Asset_Id, &Asset_Name, &Created_on, &Created_by, &BMC_IP, &Assigned_to, &Assigned_from, &Updated_on, &Updated_by, &Remarks)

			if err != nil {
				fmt.Println(err)
				log.Printf("Failed to build content from sql rows: %v\n", err)

			}
			marshal, _ := json.Marshal(result)
			var c []Historic_details[string]
			var username []string
			var user string
			var mail string
			_ = json.Unmarshal(marshal, &c)
			err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
			if err != nil {
				fmt.Println(err)
			}
			username = strings.Split(mail, "@")
			user = username[0]
			result = append(result, Historic_details[string]{Id: Id, Asset_Id: Asset_Id, Asset_Name: Asset_Name, Created_on: Created_on, Created_by: Created_by, BMC_IP: BMC_IP, Assigned_to: user, Assigned_from: Assigned_from, Updated_on: Updated_on, Updated_by: Updated_by, Remarks: Remarks})
		}
		// rev_slc := []Historic_details[string]{}
		// for i := range result {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, result[len(result)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "Historic_Details": result, "Status Code": "200 OK", "Message": "Listing Historic details"})

	})

	// -------------------------------------------------view users list---------------------------------------------------------------
	mux.HandleFunc("/view_users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func View_Role(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var pg Page
		err := json.NewDecoder(r.Body).Decode(&pg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var total int
		err2 := db.QueryRow("SELECT count(*) from users where users ::text ~* $1", pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		var users userDetails

		//database connection using funcation
		//rows, err := db.Query("SELECT User_ID, Email_ID, First_Name, Last_Name, Created_on, Created_by,COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''), Role, Teams from USERS where Delete=B'0' AND users ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;", pg.Count, pg.Page, pg.Search) // data selecting from user_table
		rows, err := db.Query("SELECT User_ID, Email_ID, First_Name, Last_Name, Created_on, Created_by,COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''), Role, Teams from USERS where email_id like '%$4%' ORDER BY DESC ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;", users.Email_Id, pg.Count, pg.Page, pg.Search)
		//rows, err := db.Query("SELECT User_ID, Email_ID, First_Name, Lsast_Name, Created_on, Created_by,COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''), Role, Teams from USERS where email_id like ='%$1%'", user.Email_Id)
		//rows, err := db.Query("SELECT *from users where first_name LIKE '%$1%'", users.First_Name)
		query := "SELECT ProductId,Name,Description,Price,SKU FROM Products WHERE Name LIKE ?"
		rows, err := r.db.QueryContext(ctx, query, "%"+name+"%")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400", "Message": err})

		}
		for rows.Next() {
			users := []userDetails{}
			var User_Id int
			var Email_Id, First_Name, Last_Name, Created_by, Updated_by, Role, Teams string
			var Created_on, Updated_on time.Time

			err = rows.Scan(&User_Id, &Email_Id, &First_Name, &Last_Name, &Created_on, &Created_by, &Updated_on, &Updated_by, &Role, &Teams)

			if err != nil {
				log.Printf("Failed to build content from sql rows: %v \n", err)
			}
			users = append(users, userDetails{User_Id: User_Id, Email_Id: Email_Id, First_Name: First_Name, Last_Name: Last_Name, Created_on: Created_on, Created_by: Created_by, Updated_on: Updated_on, Updated_by: Updated_by, Role: Role, Teams: Teams})

		}
		// rev_slc := []userDetails{}
		// for i := range users {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, users[len(users)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "Listusers": users, "status code": " 200 Ok", "Message": "Record Found"})
	})

	//----------------------------------------------------- create user------------------------------------------------------------------
	mux.HandleFunc("/create_user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Create_User(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var user userDetails
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid Input Email Syntax"})

			return
		}
		var User_Id int
		User_Id = 0
		var Email string
		User_Id = User_Id + 1
		err = db.QueryRow("SELECT Email_ID FROM Users where Email_ID=$1", user.Email_Id).Scan(&Email)
		if user.Email_Id == Email {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status": "202", "Message": "Email Already Exists"})
			return
		} else {

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 8)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid Input Syntax for IP ", "Status Code": "400 ", "Error": err})
			}
			adduser := `insert into Users(Email_ID,Password,First_Name,Last_Name,Created_on,Created_by,Updated_on,Updated_by,Role,Teams,Delete) values ($1, $2, $3, $4,LOCALTIMESTAMP(0), $5,LOCALTIMESTAMP(0), $6, $7, $8,'0')`
			_, err = db.Exec(adduser, user.Email_Id, string(hashedPassword), user.First_Name, user.Last_Name, user.Created_by, user.Updated_by, user.Role, user.Teams)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"Message": " User Added Succesfully!", "Status": "200 OK"})
		}
	})

	//------------------------------------------------ soft delete(1-not deleted,0-deleted)---------------------------------------------------
	mux.HandleFunc("/delete_user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Delete_User(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var users userDetails
		err := json.NewDecoder(r.Body).Decode(&users)
		if err != nil {
			http.Error(w, err.Error(), http.StatusAccepted)
			return
		}
		rows, err := db.Query("SELECT User_ID, Email_ID,Password, First_Name, Last_Name, Created_on, Created_by,COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''), Role, Teams,Delete FROM USERS WHERE User_ID = $1", users.User_Id)
		User_ID := 0
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}

		for rows.Next() {
			err := rows.Scan(&users.User_Id, &users.Email_Id, &users.Password, &users.First_Name, &users.Last_Name, &users.Created_on, &users.Created_by, &users.Updated_on, &users.Updated_by, &users.Role, &users.Teams, &users.Delete)
			w.WriteHeader(http.StatusAccepted)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}
			User_ID++
		}
		if User_ID == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "404", "Message": "User Not Found"})

		} else {
			rows, err := db.Query("UPDATE users SET delete = '1' WHERE user_id= $1", users.User_Id)
			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}
			users := []userDetails{}
			for rows.Next() {
				var User_Id = 0
				var Email_Id, Password, Role, First_Name, Last_Name, Created_by, Updated_by, Teams string
				var Delete int
				var Created_on, Updated_on time.Time

				err = json.NewDecoder(r.Body).Decode(&users)
				if err != nil {
					w.WriteHeader(http.StatusAccepted)
					json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
					return
				}
				err = rows.Scan(&User_Id, &Email_Id, &Password, &First_Name, &Last_Name, &Created_on, &Created_by, &Updated_on, &Updated_by, &Role, &Teams, &Delete)
				if err != nil {
					log.Printf("Failed to build content from sql rows: %v \n", err)
				}
				users = append(users, userDetails{User_Id: User_Id, Email_Id: Email_Id, Password: Password, Role: Role, First_Name: First_Name, Last_Name: Last_Name, Created_on: Created_on, Created_by: Created_by, Updated_on: Updated_on, Updated_by: Updated_by, Teams: Teams, Delete: Delete})
				w.WriteHeader(http.StatusOK)
			}
			json.NewEncoder(w).Encode(map[string]string{"Message": "Deleted Successfully", "Status Code": "200 OK"})
		}
	})

	// ------------------------------------------------------------update user-----------------------------------------------------------------
	mux.HandleFunc("/update_users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func Update_User(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var users userDetails
		err := json.NewDecoder(r.Body).Decode(&users)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(users.Password), 8)
		if err != nil {
			log.Printf("Failed to build content from sql rows: %v \n", err)
		}
		_, err = db.Exec("UPDATE users SET password=$2, first_name=$3, last_name=$4, updated_on=LOCALTIMESTAMP(0), updated_by=$5,  role=$6, teams=$7 WHERE user_id=$1;", users.User_Id, string(hashedPassword), users.First_Name, users.Last_Name, users.Updated_by, users.Role, users.Teams)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200", "Message": "Record Updated!"})
	})

	//-------------------------------------------------- List of request table ------------------------------------------------
	mux.HandleFunc("/list_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func ListRequest(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var pg Page
		err := json.NewDecoder(r.Body).Decode(&pg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var total int
		err2 := db.QueryRow("SELECT count(*) from server_request where server_request ::text ~* $1", pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}

		rows, err := db.Query("SELECT Id,User_No,Requester,Required_Start_Date,Required_End_Date,Manufacturer,Operating_System,Cpu_model,CPU_Sockets,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,COALESCE(Chat, ''),COALESCE(Request, false),COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, '') from Server_Request where Request='f' AND server_request ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;", pg.Count, pg.Page, pg.Search)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400", "Message": err})
			return
		}

		users := []Server_Request{}
		for rows.Next() {
			var Id, User_No int
			var Network_Type, Request bool
			var Updated_by, Requester, Manufacturer, Operating_System, Cpu_model, CPU_Sockets, Number_Of_Network_Ports, DIMM_Size, DIMM_Capacity, Storage_Vendor, Storage_Controller, Storage_Capacity, Network_speed, Chat, Special_Switching_Needs string
			var Required_Start_Date, Required_End_Date, Updated_on time.Time

			err = rows.Scan(&Id, &User_No, &Requester, &Required_Start_Date, &Required_End_Date, &Manufacturer, &Operating_System, &Cpu_model, &CPU_Sockets, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Chat, &Request, &Updated_on, &Updated_by)

			if err != nil {
				w.WriteHeader(http.StatusAccepted)
				fmt.Println(err)
				json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
				return
			}

			users = append(users, Server_Request{Id: Id, User_No: User_No, Requester: Requester, Required_Start_Date: Required_Start_Date, Required_End_Date: Required_End_Date, Manufacturer: Manufacturer, Operating_System: Operating_System, Cpu_model: Cpu_model, CPU_Sockets: CPU_Sockets, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Chat: Chat, Request: Request, Updated_on: Updated_on, Updated_by: Updated_by})

		}
		// rev_slc := []Server_Request{}
		// for i := range users {
		// 	// reverse the order
		// 	rev_slc = append(rev_slc, users[len(users)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "Listusers": users, "Status Code": "200 OK", "Message": "List of Requests"})
	})

	//---------------------------------------------------Creating user Request-----------------------------------------------------------------
	mux.HandleFunc("/create_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func CreateRequest(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}

		var requests Server_Request
		var ID int
		ID = 0

		err := json.NewDecoder(r.Body).Decode(&v)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400 Bad Request", "Message": err})
			return
		}

		err = db.QueryRow("Select ID from Server_Request where Id=$1", requests.Id).Scan(&ID)
		ID = ID + 1

		addStatement := `INSERT INTO Server_Request(User_No,Requester,Required_Start_Date,Required_End_Date,Manufacturer,Operating_System,Cpu_model,CPU_Sockets,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed ,Number_Of_Network_Ports ,Special_Switching_Needs,Chat, Request,Updated_on,Updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'',$18,LOCALTIMESTAMP(0),$19)`
		_, err = db.Exec(addStatement, v.User_No, v.Requester, v.Required_Start_Date.Format("2006-01-02"), v.Required_End_Date.Format("2006-01-02"), v.Manufacturer, v.Operating_System, v.Cpu_model, v.CPU_Sockets, v.DIMM_Size, v.DIMM_Capacity, v.Storage_Vendor, v.Storage_Controller, v.Storage_Capacity, v.Network_Type, v.Network_speed, v.Number_Of_Network_Ports, v.Special_Switching_Needs, v.Request, v.Updated_by)

		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200 OK", "Message": "Request Added successfully"})
	})

	//-----------------------------------------------------------GetMyRequest--------------------------------------------
	mux.HandleFunc("/my_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func GetMyRequest(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		a, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		p := Server_Request{}
		if err := json.Unmarshal(a, &p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var pg Page
		if err := json.Unmarshal(a, &pg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var total int
		err2 := db.QueryRow("SELECT count(*) from server_request WHERE  Request='f' AND User_No = $1 and server_request ::text ~* $2", p.User_No, pg.Search).Scan(&total) // exporting table
		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		// err := json.NewDecoder(r.Body).Decode(&p)
		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusBadRequest)
		// 	return
		// }

		rows, err := db.Query("SELECT * from Server_Request WHERE  Request='f' AND User_No = $1 AND Server_Request ::text ~*  $4 order by Updated_on desc limit $2 offset ($3-1)*$2;", p.User_No, pg.Count, pg.Page, pg.Search)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202"})
			return
		}

		Requests := []Server_Request{}
		for rows.Next() {
			var Id, User_No int
			var Network_Type, Request bool
			var Updated_by, Requester, Manufacturer, Operating_System, Cpu_model, CPU_Sockets, DIMM_Size, DIMM_Capacity, Storage_Vendor, Storage_Controller, Storage_Capacity, Network_speed, Number_Of_Network_ports, Special_Switching_Needs, Chat string
			var Required_Start_Date, Required_End_Date, Updated_on time.Time

			err1 := rows.Scan(&Id, &User_No, &Requester, &Required_Start_Date, &Required_End_Date, &Manufacturer, &Operating_System, &Cpu_model, &CPU_Sockets, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_ports, &Special_Switching_Needs, &Chat, &Request, &Updated_on, &Updated_by)
			if err1 != nil {
				log.Printf("Failed to build content from sql rows: %v \n", err1)
				return
			}

			Requests = append(Requests, Server_Request{Id: Id, User_No: User_No, Requester: Requester, Required_Start_Date: Required_Start_Date, Required_End_Date: Required_End_Date, Manufacturer: Manufacturer, Operating_System: Operating_System, Cpu_model: Cpu_model, CPU_Sockets: CPU_Sockets, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_ports, Special_Switching_Needs: Special_Switching_Needs, Chat: Chat, Request: Request, Updated_on: Updated_on, Updated_by: Updated_by})
		}
		// rev_slc := []Server_Request{}
		// for i := range Requests {
		// 	// reverse the order
		// 	fmt.Println("working")
		// 	rev_slc = append(rev_slc, Requests[len(Requests)-1-i])
		// }
		totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
		json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "ListMyRequests": Requests, "Status Code": "200 OK", "Message": "Listing Requests"})

		if len(Requests) == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "No Current Requests", "Status Code": "404"})
			return
		}
	})

	//----------------------------------------------------update user request---------------------------------------------------
	mux.HandleFunc("/update_u_comments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func UpdateUserComments(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		err := json.NewDecoder(r.Body).Decode(&v)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid Input Syntax"})

			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]string{"Message": "method not found", "Status Code": "405"})
			return
		}
		currentTime := time.Now()

		// _, err1 := db.Exec("UPDATE Server_Request SET User_No=$2,Requester=$3,Required_Start_Date=$4,Required_End_Date=$5,Manufacturer=$6,Operating_System=$7,Cpu_model=$8,CPU_Sockets=$9,DIMM_Size=$10,DIMM_Capacity=$11,Storage_Vendor=$12,Storage_Controller=$13,Storage_Capacity=$14,Network_Type=$15,Network_speed=$16,Number_Of_Network_Ports=$17,Special_Switching_Needs=$18,Updated_on=LOCALTIMESTAMP(0),Updated_by=$19 WHERE ID=$1  ;", v.Id, v.User_No, v.Requester, v.Required_Start_Date, v.Required_End_Date, v.Manufacturer, v.Operating_System, v.Cpu_model, v.CPU_Sockets, v.DIMM_Size, v.DIMM_Capacity, v.Storage_Vendor, v.Storage_Controller, v.Storage_Capacity, v.Network_Type, v.Network_speed, v.Number_Of_Network_Ports, v.Special_Switching_Needs, v.Updated_by)

		// if err1 != nil {
		// 	w.WriteHeader(http.StatusAccepted)
		// 	json.NewEncoder(w).Encode(map[string]interface{}{"Message": err1, "Status Code": "202 "})
		// 	return
		// }

		_, err2 := db.Exec("UPDATE Server_Request SET Chat= $2 WHERE ID=$1;", v.Id, v.Chat+","+currentTime.Format("2006-01-02 15:04:05"))

		if err2 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err2, "Status Code": "202 "})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Record Updated!", "Status Code": "200 OK"})
	})

	//-------------------------------------------------------Chat-----------------------------------------------------
	mux.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		p := Server_Request{}
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := db.Query("SELECT Id,COALESCE(Chat, '') from Server_Request where Id=$1", p.Id)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "400", "Message": err})
			return
		}
		var chat []Chats
		var a []string
		for rows.Next() {
			var Id int
			var Chat string
			err := rows.Scan(&Id, &Chat)
			if err != nil {
				log.Fatal(err)
				json.NewEncoder(w).Encode(map[string]interface{}{"status": "400 Bad Request", "Message": err})
			}
			fmt.Println(Chat)
			index := strings.Split(string(Chat), ",")
			for i := 0; i < len(index); i++ {
				a = append(a, index[i])
			}
			c := 4
			r := (len(a) + c - 1) / c
			b := make([][]string, r)
			lo, hi := 0, c
			for i := range b {
				if hi > len(a) {
					hi = len(a)
				}
				b[i] = a[lo:hi:hi]
				lo, hi = hi, hi+c

			}

			chat = append(chat, Chats{Id: Id, Comment: b})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"Chat": chat, "Status": "200 OK"})

	})

	//------------------------------------------------add asset(from request)---------------------------------------------------------------------
	mux.HandleFunc("/add_asset_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func AddAsset(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var assets Asset[int]
		var Asset_Id int
		Asset_Id = 0

		err := json.NewDecoder(r.Body).Decode(&assets)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
			return
		}
		hashedPassword1, err := bcrypt.GenerateFromPassword([]byte(assets.PDU_Password), 8)
		hashedPassword2, err := bcrypt.GenerateFromPassword([]byte(assets.BMC_Password), 8)
		hashedPassword3, err := bcrypt.GenerateFromPassword([]byte(assets.OS_Password), 8)
		err = db.QueryRow("Select Asset_Id from Asset where Asset_Id=$1", assets.Asset_Id).Scan(&Asset_Id)

		Asset_Id = Asset_Id + 1
		_, err = db.Exec(`INSERT INTO asset (Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,Cluster_Id,Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,Assigned_to,Assigned_from,Assigned_by,Updated_on,Updated_by,Purpose,Delete,Reserved) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,LOCALTIMESTAMP(0),$45,$46,LOCALTIMESTAMP(0),$47,LOCALTIMESTAMP(0),$48,$49,'0','t')`,
			assets.Asset_Name, assets.Server_Serial, assets.Server_Model, assets.Manufacturer, assets.Owner, assets.Category, assets.Still_needed, assets.Current_Project, assets.Notes, assets.Previous_Project, assets.BOM, assets.Support_case, assets.Cluster_Id, assets.Asset_Location, assets.Lab, assets.Row, assets.Rack, assets.RU, assets.DC_status, assets.Cpu_model, assets.Generation, assets.CPU_Sockets, assets.PDU_IP, assets.PDU_User, string(hashedPassword1), assets.BMC_IP, assets.BMC_User, string(hashedPassword2), assets.BMC_FQDN, assets.Operating_System, assets.OS_IP, assets.OS_User, string(hashedPassword3), assets.DIMM_Size, assets.DIMM_Capacity, assets.Storage_Vendor, assets.Storage_Controller, assets.Storage_Capacity, assets.Network_Type, assets.Network_speed, assets.Number_Of_Network_Ports, assets.Special_Switching_Needs, assets.Required_Start_Date.Format("2006-01-02"), assets.Required_Finish_Date.Format("2006-01-02"), assets.Created_by, assets.Assigned_to, assets.Assigned_by, assets.Updated_by, assets.Purpose)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Println(err)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Invalid Input Syntax for IP ", "Status Code": "400 ", "Error": err})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200 OK", "Message": "Recorded Sucessfully"})

		if assets.Delete == 0 {
			_, err = db.Exec(`INSERT into Historic_details (Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,Remarks)
		SELECT Asset_ID,Asset_Name,Created_on,Created_by,BMC_IP,Assigned_to,Assigned_from,Updated_on,Updated_by,'Server Assigned' FROM Asset where Asset_ID=(SELECT Asset_ID FROM Asset ORDER BY Asset_ID DESC LIMIT 1);`)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "History Updated", "Status Code": "200 OK"})
		}
	})

	//------------------------------------------------approve request(from request)---------------------------------------------------------------------
	mux.HandleFunc("/approve_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
			return
		}
		var s Server_Request
		err := json.NewDecoder(r.Body).Decode(&s)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Message": "Invalid Input Syntax", "Status Code": "400 "})
			return
		}

		_, err = db.Exec("UPDATE server_request SET Request='t' WHERE Id=$1;", s.Id)
		if err != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"Status Code": "200 OK", "Message": "Approved Sucessfully"})

	})

	// // ----------------------------------------------list page-----------------------------------------------------------
	// mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
	// 	w.Header().Set("Access-Control-Allow-Origin", "*")
	// 	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	// 	//func Reserved(w http.ResponseWriter, r *http.Request) {
	// 	//SetupCORS(&w)
	// 	if r.Method != http.MethodPost {
	// 		w.WriteHeader(405) // Return 405 Method Not Allowed.
	// 		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "method not found", "Status Code": "405 "})
	// 		return
	// 	}

	// 	var pg Page
	// 	err := json.NewDecoder(r.Body).Decode(&pg)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusBadRequest)
	// 		return
	// 	}

	// 	var total int
	// 	err2 := db.QueryRow("SELECT count(*) from asset where asset ::text ~* $1", pg.Search).Scan(&total) // exporting table
	// 	if err2 != nil {
	// 		w.WriteHeader(http.StatusAccepted)
	// 		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "202 "})
	// 		return
	// 	}

	// 	str := "SELECT Asset_Id,Asset_Name,Server_Serial,Server_Model,Manufacturer,Owner,Category ,Still_needed,Current_Project,Notes,Previous_Project,BOM,Support_case,COALESCE(Cluster_ID,''),Asset_location,Lab,Row,Rack,RU,DC_status,Cpu_model,Generation,CPU_Sockets,PDU_IP,PDU_User,PDU_Password,BMC_IP, BMC_User, BMC_Password, BMC_FQDN,Operating_System,OS_IP,OS_User,OS_Password,DIMM_Size,DIMM_Capacity,Storage_Vendor,Storage_Controller,Storage_Capacity,Network_Type,Network_speed,Number_Of_Network_Ports,Special_Switching_Needs,Required_Start_Date,Required_Finish_Date,Created_on,Created_by,COALESCE(Assigned_to, 0),COALESCE(Assigned_from, '0001-01-01'),COALESCE(Assigned_by, ''),COALESCE(Updated_on,'0001-01-01'),COALESCE(Updated_by, ''),Purpose,Delete,Reserved FROM Asset where asset ::text ~* $3 order by updated_on desc limit $1 offset ($2-1)*$1;"
	// 	rows, err := db.Query(str, pg.Count, pg.Page, pg.Search)
	// 	if err != nil {
	// 		w.WriteHeader(http.StatusBadRequest)
	// 		json.NewEncoder(w).Encode(map[string]interface{}{"Message": err, "Status Code": "400 "})
	// 		return
	// 	}
	// 	result := []Asset[string]{} // creating slice
	// 	for rows.Next() {
	// 		var Asset_Id, Assigned_to, Delete, Row, Rack, RU int
	// 		var Asset_Name, Server_Serial, Server_Model, Manufacturer, OS_IP, OS_User, OS_Password,
	// 			BMC_IP, BMC_User, BMC_Password, BMC_FQDN,
	// 			Asset_Location, Assigned_by, Created_by, Updated_by, Cluster_Id, Purpose, Generation,
	// 			Lab, DC_status, PDU_IP, PDU_User, PDU_Password, Owner, Category,
	// 			Current_Project, Notes, Previous_Project, BOM, Support_case, Cpu_model, CPU_Sockets,
	// 			DIMM_Capacity, DIMM_Size, Storage_Vendor, Storage_Controller,
	// 			Storage_Capacity, Network_speed, Number_Of_Network_Ports, Special_Switching_Needs, Operating_System string
	// 		var Created_on, Updated_on, Assigned_from, Required_Start_Date, Required_Finish_Date time.Time
	// 		var Reserved, Still_needed, Network_Type bool

	// 		err := rows.Scan(&Asset_Id, &Asset_Name, &Server_Serial, &Server_Model, &Manufacturer, &Owner, &Category, &Still_needed, &Current_Project, &Notes, &Previous_Project, &BOM, &Support_case, &Cluster_Id, &Asset_Location, &Lab, &Row, &Rack, &RU, &DC_status, &Cpu_model, &Generation, &CPU_Sockets, &PDU_IP, &PDU_User, &PDU_Password, &BMC_IP, &BMC_User, &BMC_Password, &BMC_FQDN, &Operating_System, &OS_IP, &OS_User, &OS_Password, &DIMM_Size, &DIMM_Capacity, &Storage_Vendor, &Storage_Controller, &Storage_Capacity, &Network_Type, &Network_speed, &Number_Of_Network_Ports, &Special_Switching_Needs, &Required_Start_Date, &Required_Finish_Date, &Created_on, &Created_by, &Assigned_to, &Assigned_from, &Assigned_by, &Updated_on, &Updated_by, &Purpose, &Delete, &Reserved)

	// 		if err != nil {
	// 			fmt.Println(err)
	// 			log.Printf("Failed to build content from sql rows: %v\n", err)

	// 		}

	// 		marshal, _ := json.Marshal(result)
	// 		var c []Historic_details[string]
	// 		var username []string
	// 		var mail string
	// 		var user string
	// 		_ = json.Unmarshal(marshal, &c)
	// 		err = db.QueryRow(" SELECT Email_ID FROM users where User_ID=$1;", Assigned_to).Scan(&mail)
	// 		if err != nil {
	// 			fmt.Println(err)
	// 		}
	// 		username = strings.Split(mail, "@")
	// 		user = username[0]
	// 		result = append(result, Asset[string]{Asset_Id: Asset_Id, Asset_Name: Asset_Name, Server_Serial: Server_Serial, Server_Model: Server_Model, Manufacturer: Manufacturer, Owner: Owner, Category: Category, Still_needed: Still_needed, Current_Project: Current_Project, Notes: Notes, Previous_Project: Previous_Project, BOM: BOM, Support_case: Support_case, Cluster_Id: Cluster_Id, Asset_Location: Asset_Location, Lab: Lab, Row: Row, Rack: Rack, RU: RU, DC_status: DC_status, Cpu_model: Cpu_model, Generation: Generation, CPU_Sockets: CPU_Sockets, PDU_IP: PDU_IP, PDU_User: PDU_User, PDU_Password: PDU_Password, BMC_IP: BMC_IP, BMC_User: BMC_User, BMC_Password: BMC_Password, BMC_FQDN: BMC_FQDN, Operating_System: Operating_System, OS_IP: OS_IP, OS_User: OS_User, OS_Password: OS_Password, DIMM_Size: DIMM_Size, DIMM_Capacity: DIMM_Capacity, Storage_Vendor: Storage_Vendor, Storage_Controller: Storage_Controller, Storage_Capacity: Storage_Capacity, Network_Type: Network_Type, Network_speed: Network_speed, Number_Of_Network_Ports: Number_Of_Network_Ports, Special_Switching_Needs: Special_Switching_Needs, Required_Start_Date: Required_Start_Date, Required_Finish_Date: Required_Finish_Date, Created_on: Created_on, Created_by: Created_by, Assigned_to: user, Assigned_from: Assigned_from, Assigned_by: Assigned_by, Updated_on: Updated_on, Updated_by: Updated_by, Purpose: Purpose, Delete: Delete, Reserved: Reserved})
	// 	} // appending deatils to the result
	// 	// rev_slc := []Asset[string]{}
	// 	// for i := range result {
	// 	// 	// reverse the order
	// 	// 	rev_slc = append(rev_slc, result[len(result)-1-i])
	// 	// }
	// 	totalPage := math.Ceil(float64(total*1.0) / float64(pg.Count*1.0))
	// 	json.NewEncoder(w).Encode(map[string]interface{}{"Count": pg.Count, "Page_no": pg.Page, "Total_entry": total, "Search": pg.Search, "Total_Page": totalPage, "ListAsset": result, "Status Code": "200 OK", "Message": "Listing All Servers"})
	// })

	//----------------------------------------------------update request---------------------------------------------------
	mux.HandleFunc("/update_request", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization,application/json ")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		//func UpdateUserComments(w http.ResponseWriter, r *http.Request) {
		//SetupCORS(&w)
		err := json.NewDecoder(r.Body).Decode(&v)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"Status Code": "400", "Message": "Invalid Input Syntax"})

			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(405) // Return 405 Method Not Allowed.
			json.NewEncoder(w).Encode(map[string]string{"Message": "method not found", "Status Code": "405"})
			return
		}

		_, err1 := db.Exec("UPDATE Server_Request SET User_No=$2,Requester=$3,Required_Start_Date=$4,Required_End_Date=$5,Manufacturer=$6,Operating_System=$7,Cpu_model=$8,CPU_Sockets=$9,DIMM_Size=$10,DIMM_Capacity=$11,Storage_Vendor=$12,Storage_Controller=$13,Storage_Capacity=$14,Network_Type=$15,Network_speed=$16,Number_Of_Network_Ports=$17,Special_Switching_Needs=$18,Updated_on=LOCALTIMESTAMP(0),Updated_by=$19 WHERE ID=$1  ;", v.Id, v.User_No, v.Requester, v.Required_Start_Date, v.Required_End_Date, v.Manufacturer, v.Operating_System, v.Cpu_model, v.CPU_Sockets, v.DIMM_Size, v.DIMM_Capacity, v.Storage_Vendor, v.Storage_Controller, v.Storage_Capacity, v.Network_Type, v.Network_speed, v.Number_Of_Network_Ports, v.Special_Switching_Needs, v.Updated_by)

		if err1 != nil {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{"Message": err1, "Status Code": "202 "})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"Message": "Record Updated!", "Status Code": "200 OK"})
	})

	handler := cors.Default().Handler(mux)
	http.ListenAndServe(":5002", handler)
}
