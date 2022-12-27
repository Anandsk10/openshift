package main

import (
	_ "github.com/lib/pq"
	s "servermanagement.com/infraadmin/asset"
)

func main() {
	s.HandleFunc()
}
