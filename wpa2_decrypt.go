// wpa2_decrypt.go
// Minimal Go program to invoke aircrack-ng for WPA2 decryption on a pcap file.
// Requires: aircrack-ng installed and in PATH.
// Usage: go run wpa2_decrypt.go <interface> <ssid> <passphrase>

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <interface> <ssid> <passphrase>\n", os.Args[0])
		os.Exit(1)
	}
	iface := os.Args[1]
	ssid := os.Args[2]
	pass := os.Args[3]

	pcap := "capture.pcap"
	// Start tcpdump to capture EAPOL frames and all traffic
	cmd := exec.Command("tcpdump", "-i", iface, "-w", pcap)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start tcpdump:", err, stderr)
		os.Exit(1)
	}
	fmt.Println("Capturing traffic. Waiting for EAPOL handshake...")

	// Start another tcpdump to print packets for EAPOL detection
	cmd2 := exec.Command("tcpdump", "-i", iface, "ether proto 0x888e")
	pipe, _ := cmd2.StdoutPipe()
	if err := cmd2.Start(); err != nil {
		fmt.Println("Failed to start tcpdump for EAPOL detection:", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	// Scan output for EAPOL
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "EAPOL") {
				fmt.Println("EAPOL handshake detected!")
				return
			}
		}
	}()

	// Wait for EAPOL or user input
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Press Enter to stop capturing after handshake is detected...")
	reader.ReadString('\n')

	cmd.Process.Kill()
	cmd2.Process.Kill()
	fmt.Println("Capture stopped. Decrypting...")

	airdecap := exec.Command("airdecap-ng", "-e", ssid, "-p", pass, pcap)
	airdecap.Stdout = os.Stdout
	airdecap.Stderr = os.Stderr
	if err := airdecap.Run(); err != nil {
		fmt.Println("airdecap-ng failed:", err)
		os.Exit(1)
	}
	fmt.Println("Decryption completed.")
}
