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
	cmd := exec.Command("tcpdump", "-i", iface, "-w", pcap, "ether proto 0x888e or type Data")
	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start tcpdump:", err)
		os.Exit(1)
	}
	fmt.Println("Capturing traffic. Waiting for EAPOL handshake...")

	// Start another tcpdump to print packets for EAPOL detection
	cmd2 := exec.Command("tcpdump", "-i", iface, "ether proto 0x888e", "-l")
	pipe, _ := cmd2.StdoutPipe()
	if err := cmd2.Start(); err != nil {
		fmt.Println("Failed to start tcpdump for EAPOL detection:", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	// Scan output for EAPOL
	found := false
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "EAPOL") {
				fmt.Println("EAPOL handshake detected!")
				found = true
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

	// aircrack-ng -w <wordlist> -e <ssid> <pcap>
	// We'll create a temporary wordlist file with the passphrase
	wordlist := "wordlist.txt"
	if err := os.WriteFile(wordlist, []byte(pass+"\n"), 0600); err != nil {
		fmt.Println("Failed to write wordlist:", err)
		os.Exit(1)
	}
	defer os.Remove(wordlist)

	aircrack := exec.Command("aircrack-ng", "-w", wordlist, "-e", ssid, pcap)
	aircrack.Stdout = os.Stdout
	aircrack.Stderr = os.Stderr
	if err := aircrack.Run(); err != nil {
		fmt.Println("aircrack-ng failed:", err)
		os.Exit(1)
	}
}
