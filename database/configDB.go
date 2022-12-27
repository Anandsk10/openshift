package database

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"strings"

	// library for conenct postgresql
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

var (
	// DB variable for connection DB postgresql
	db *sql.DB
)

// Connects to database and creates schema, returns connection object
func Connect() *sql.DB {

	fmt.Println("Connecting to database ... ")
	viper.SetConfigName("configdb") // name of config file (without extension)
	viper.SetConfigType("json")     // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")        // Look for config in the working directory
	//C:\Users\Administrator\Desktop\SMP\DATABASE2\configuration 2\models\configdb.json
	fmt.Println("Reading configuration from json file ... ")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error reading json config file: %w \n", err))
	}

	user := viper.GetString("user") // viper is to read both from configuration file and environment variables.
	password := viper.GetString("password")
	host := viper.GetString("host")
	port := viper.GetString("port")
	dbname := viper.GetString("dbname")
	psqlInfo := "host=" + host + " port=" + port + " user=" + user + " password=" + password + " sslmode=disable"
	fmt.Printf(psqlInfo)
	db1, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		fmt.Printf("Check your config file, Database not connected ...")
		//fmt.Printf(err)
		return nil
	}

	_, err = db1.Exec("create database " + dbname)
	conninfob := psqlInfo + " database=" + dbname
	db2, err := sql.Open("postgres", conninfob)
	file, err := ioutil.ReadFile("./dbschema.sql")

	requests := strings.Split(string(file), ";")

	for _, request := range requests {
		result, err := db2.Exec(request)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(result)
	}

	db = db2
	return db
}
