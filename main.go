package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/litemars/802.11Decrypter/wpa2Decrypter"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Printf("Usage: %s <interface> <channel> <ssid> <passphrase> <mac_address1,mac_address2,...>\n", os.Args[0])
		os.Exit(1)
	}
	iface := os.Args[1]
	channel := os.Args[2]
	ssid := os.Args[3]
	pass := os.Args[4]
	macs := strings.Split(os.Args[5], ",")

	done := make(chan error)
	activeProcesses := 0

	for _, mac := range macs {
		mac = strings.TrimSpace(mac)
		if mac == "" {
			continue
		}
		activeProcesses++
		go func(mac string) {
			done <- wpa2Decrypter.ProcessMAC(iface, channel, ssid, pass, mac)
		}(mac)
	}

	// Wait for all processes to complete
	for i := 0; i < activeProcesses; i++ {
		if err := <-done; err != nil {
			fmt.Println(err)
		}
	}
}
