package main

import (
	"log"
)

func main() {
	client, err := NewClient()
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Stop()
	if err := client.Run(); err != nil {
		panic(err)
	}
}
