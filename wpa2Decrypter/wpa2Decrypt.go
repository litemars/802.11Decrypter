package wpa2Decrypter

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func waitOrEnter(duration time.Duration) {
	fmt.Printf("Waiting for %v or press Enter to continue immediately...\n", duration)

	enterPressed := make(chan struct{})

	// Goroutine to detect Enter key press
	go func() {
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		enterPressed <- struct{}{}
	}()

	select {
	case <-time.After(duration):
		fmt.Println("Timeout reached.")
	case <-enterPressed:
		fmt.Println("Enter pressed. Continuing early.")
	}
}

func setMonitorMode(iface string) error {
	// Check if the interface is already in monitor mode
	cmd := exec.Command("iwconfig", iface)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check interface mode: %v", err)
	}
	if strings.Contains(string(output), "Mode:Monitor") {
		fmt.Println("Interface is already in monitor mode.")
		return nil
	}

	cmd = exec.Command("sudo", "ifconfig", iface, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring down interface: %v", err)
	}

	cmd = exec.Command("sudo", "iwconfig", iface, "mode", "monitor")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set monitor mode: %v", err)
	}

	cmd = exec.Command("sudo", "ifconfig", iface, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	cmd_verify := exec.Command("iwconfig", iface)
	output_verify, err := cmd_verify.Output()
	if err != nil {
		return fmt.Errorf("failed to check interface mode: %v", err)
	}
	if !strings.Contains(string(output_verify), "Mode:Monitor") {
		return fmt.Errorf("interface is not in monitor mode")
	}

	return nil
}

func setChannel(iface string, channel string) error {
	// Check if the interface is already on the given channel
	cmd := exec.Command("iwconfig", iface)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check interface channel: %v", err)
	}
	if strings.Contains(string(output), fmt.Sprintf("Channel:%s", channel)) {
		fmt.Println("Interface is already on channel", channel)
		return nil
	}

	cmd = exec.Command("sudo", "iwconfig", iface, "channel", channel)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set channel: %v", err)
	}
	return nil
}

 func runAirmon(iface string) error {
	// fmt.Println("Running airmon-ng to start monitor mode on", iface)	
 	cmd := exec.Command("sudo", "airmon-ng","start",iface)
 	if output, err := cmd.Output(); err != nil {
 		return fmt.Errorf("failure %v - %s", err,output)
 	}
 	return nil
 }

func captureTraffic(iface string, pcap string, mac string) (*exec.Cmd, error) {
	cmd := exec.Command("tcpdump", "-i", iface, "-U", "-s", "0", "-w", pcap, "ether host", mac)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tcpdump: %v", err)
	}
	fmt.Println("Capturing traffic for MAC address", mac, ". Waiting for EAPOL handshake...")
	return cmd, nil
}

func detectEAPOL(iface string, mac string, cmd *exec.Cmd) (chan struct{}, error) {
	cmd2 := exec.Command("tcpdump", "-i", iface, "ether proto 0x888e", "and", "ether host", mac, "-l")
	pipe, _ := cmd2.StdoutPipe()
	if err := cmd2.Start(); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("failed to start tcpdump for EAPOL detection: %v", err)
	}

	done := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "EAPOL") {
				fmt.Println("EAPOL handshake detected for MAC address", mac, "!")
				close(done)
				return
			}
		}
	}()
	return done, nil
}

func decryptTraffic(ssid string, pass string, pcap string) error {
	airdecap := exec.Command("airdecap-ng", "-e", ssid, "-p", pass, pcap)
	airdecap.Stdout = os.Stdout
	airdecap.Stderr = os.Stderr
	if err := airdecap.Run(); err != nil {
		return fmt.Errorf("airdecap-ng failed: %v", err)
	}
	fmt.Println("Decryption completed.")
	return nil
}

func ProcessMAC(iface, channel, ssid, pass, mac string) error {

	if err := runAirmon(iface); err != nil {
		return fmt.Errorf("error running airmon %v", err)
	}


	if err := setMonitorMode(iface); err != nil {
		return fmt.Errorf("error setting monitor mode for %s: %v", mac, err)
	}

	if err := setChannel(iface, channel); err != nil {
		return fmt.Errorf("error setting channel for %s: %v", mac, err)
	}


	timestamp := time.Now().Format("20060102_150405")

	pcap := fmt.Sprintf("capture/capture_%s_%s.pcap", mac, timestamp)
	
	captureCmd, err := captureTraffic(iface, pcap, mac)
	if err != nil {
		return err
	}

	done, err := detectEAPOL(iface, mac, captureCmd)
	if err != nil {
		captureCmd.Process.Kill()
		return err
	}

	<-done // Wait for EAPOL detection
	waitOrEnter(10 * time.Minute) 
	captureCmd.Process.Kill()
	fmt.Printf("[%s] Capture stopped. Decrypting...\n", mac)

	if err := decryptTraffic(ssid, pass, pcap); err != nil {
		return err
	}

	return nil
}
