package main

import (
	"log"
	"os"
	"os/signal"
)

func main() {
	quitChannel := make(chan os.Signal, 1)
	signal.Notify(quitChannel, os.Interrupt)

	go startRadiusServer()
	go startOAuthServer()

	<-quitChannel
	log.Println("Shutting down...")
	os.Exit(0)
}
