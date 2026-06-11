package main

import (
	"flag"
	"fmt"
)

func main() {
	requestFile := flag.String("r", "", "path to request file")
	flag.Parse()

	if *requestFile == "" {
		fmt.Println("usage: tamper -r request file")
		return
	}

	req, err := ParseRequestFile(*requestFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Method:", req.Method)
	fmt.Println("Host:", req.Host)
	fmt.Println("BodyType:", req.BodyType)
	fmt.Println("Fields:", req.Fields)

	body := RebuildBody(req)
	fmt.Println("Rebuilt body: ", body)
}
