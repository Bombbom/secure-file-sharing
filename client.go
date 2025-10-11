package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Message types
const (
	MsgRegister   = "REGISTER"
	MsgLogin      = "LOGIN"
	MsgUpload     = "UPLOAD"
	MsgDownload   = "DOWNLOAD"
	MsgList       = "LIST"
	MsgShare      = "SHARE"
	MsgDisconnect = "DISCONNECT"
)

type Message struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Data      json.RawMessage `json:"data"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UploadRequest struct {
	Filename string `json:"filename"`
	FileSize int64  `json:"filesize"`
	Checksum string `json:"checksum"`
}

type DownloadRequest struct {
	FileID int64 `json:"file_id"`
}

type ShareRequest struct {
	FileID         int64  `json:"file_id"`
	TargetUsername string `json:"target_username"`
}

type Response struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type FileInfo struct {
	ID        int64     `json:"id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	OwnerID   int64     `json:"owner_id"`
	Owner     string    `json:"owner"`
	Checksum  string    `json:"checksum"`
	CreatedAt time.Time `json:"created_at"`
}

type Client struct {
	conn      *tls.Conn
	encoder   *json.Encoder
	decoder   *json.Decoder
	sessionID string
	username  string
}

func NewClient(serverAddr string) (*Client, error) {
	config := &tls.Config{
		InsecureSkipVerify: true, // For demo purposes only
	}

	conn, err := tls.Dial("tcp", serverAddr, config)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}

	client := &Client{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		decoder: json.NewDecoder(conn),
	}

	return client, nil
}

func (c *Client) sendMessage(msgType string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	msg := Message{
		Type:      msgType,
		SessionID: c.sessionID,
		Data:      dataBytes,
	}

	return c.encoder.Encode(msg)
}

func (c *Client) receiveResponse() (*Response, error) {
	var resp Response
	if err := c.decoder.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Register(username, password, email string) error {
	req := RegisterRequest{
		Username: username,
		Password: password,
		Email:    email,
	}

	if err := c.sendMessage(MsgRegister, req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	fmt.Println("✓ Registration successful!")
	return nil
}

func (c *Client) Login(username, password string) error {
	req := LoginRequest{
		Username: username,
		Password: password,
	}

	if err := c.sendMessage(MsgLogin, req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	var data map[string]string
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return err
	}

	c.sessionID = data["session_id"]
	c.username = username

	fmt.Println("✓ Login successful!")
	return nil
}

func (c *Client) UploadFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("file open failed: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("file stat failed: %v", err)
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("file read failed: %v", err)
	}

	checksum := calculateChecksum(data)

	req := UploadRequest{
		Filename: stat.Name(),
		FileSize: stat.Size(),
		Checksum: checksum,
	}

	if err := c.sendMessage(MsgUpload, req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	// Send file data
	buffer := make([]byte, 32*1024)
	var totalSent int64

	fmt.Printf("Uploading %s (%d bytes)...\n", stat.Name(), stat.Size())

	for totalSent < stat.Size() {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read failed: %v", err)
		}
		if n == 0 {
			break
		}

		if _, err := c.conn.Write(buffer[:n]); err != nil {
			return fmt.Errorf("write failed: %v", err)
		}

		totalSent += int64(n)
		progress := float64(totalSent) / float64(stat.Size()) * 100
		fmt.Printf("\rProgress: %.2f%%", progress)
	}

	fmt.Println("\n✓ Upload successful!")
	return nil
}

func (c *Client) DownloadFile(fileID int64, savePath string) error {
	req := DownloadRequest{
		FileID: fileID,
	}

	if err := c.sendMessage(MsgDownload, req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	var downloadInfo map[string]interface{}
	if err := json.Unmarshal(resp.Data, &downloadInfo); err != nil {
		return err
	}

	filename := downloadInfo["filename"].(string)
	filesize := int64(downloadInfo["filesize"].(float64))

	if savePath == "" {
		savePath = filename
	}

	file, err := os.Create(savePath)
	if err != nil {
		return fmt.Errorf("file creation failed: %v", err)
	}
	defer file.Close()

	buffer := make([]byte, 32*1024)
	var totalReceived int64

	fmt.Printf("Downloading %s (%d bytes)...\n", filename, filesize)

	for totalReceived < filesize {
		n, err := c.conn.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read failed: %v", err)
		}
		if n == 0 {
			break
		}

		if _, err := file.Write(buffer[:n]); err != nil {
			return fmt.Errorf("write failed: %v", err)
		}

		totalReceived += int64(n)
		progress := float64(totalReceived) / float64(filesize) * 100
		fmt.Printf("\rProgress: %.2f%%", progress)
	}

	fmt.Println("\n✓ Download successful!")
	return nil
}

func (c *Client) ListFiles() error {
	if err := c.sendMessage(MsgList, nil); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	var files []FileInfo
	if err := json.Unmarshal(resp.Data, &files); err != nil {
		return err
	}

	if len(files) == 0 {
		fmt.Println("No files available.")
		return nil
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         YOUR FILES                             ║")
	fmt.Println("╠════╦═══════════════════════╦═══════════╦═══════════════════════╣")
	fmt.Printf("║ %-2s ║ %-21s ║ %-9s ║ %-21s ║\n", "ID", "Filename", "Size", "Owner")
	fmt.Println("╠════╬═══════════════════════╬═══════════╬═══════════════════════╣")

	for _, f := range files {
		size := formatSize(f.Size)
		filename := truncate(f.Filename, 21)
		owner := truncate(f.Owner, 21)
		fmt.Printf("║ %-2d ║ %-21s ║ %-9s ║ %-21s ║\n", f.ID, filename, size, owner)
	}

	fmt.Println("╚════╩═══════════════════════╩═══════════╩═══════════════════════╝")
	return nil
}

func (c *Client) ShareFile(fileID int64, targetUsername string) error {
	req := ShareRequest{
		FileID:         fileID,
		TargetUsername: targetUsername,
	}

	if err := c.sendMessage(MsgShare, req); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf(resp.Message)
	}

	fmt.Println("✓ File shared successfully!")
	return nil
}

func (c *Client) Disconnect() error {
	if err := c.sendMessage(MsgDisconnect, nil); err != nil {
		return err
	}

	resp, err := c.receiveResponse()
	if err != nil {
		return err
	}

	fmt.Println(resp.Message)
	c.conn.Close()
	return nil
}

func calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func printBanner() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════╗
║          SECURE FILE SHARING SYSTEM - CLIENT                  ║
║              End-to-End Encrypted File Transfer               ║
╚═══════════════════════════════════════════════════════════════╝
`)
}

func printMenu() {
	fmt.Println("\n┌─────────────────────────────────────┐")
	fmt.Println("│            MAIN MENU                │")
	fmt.Println("├─────────────────────────────────────┤")
	fmt.Println("│ 1. Register                         │")
	fmt.Println("│ 2. Login                            │")
	fmt.Println("│ 3. Upload File                      │")
	fmt.Println("│ 4. Download File                    │")
	fmt.Println("│ 5. List Files                       │")
	fmt.Println("│ 6. Share File                       │")
	fmt.Println("│ 7. Disconnect                       │")
	fmt.Println("│ 8. Exit                             │")
	fmt.Println("└─────────────────────────────────────┘")
	fmt.Print("\nChoice: ")
}

func main() {
	printBanner()

	serverAddr := "localhost:8443"
	if len(os.Args) > 1 {
		serverAddr = os.Args[1]
	}

	fmt.Printf("Connecting to server: %s\n", serverAddr)

	client, err := NewClient(serverAddr)
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		return
	}

	fmt.Println("✓ Connected to server (TLS secured)")

	scanner := bufio.NewScanner(os.Stdin)

	for {
		printMenu()

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Print("Username: ")
			scanner.Scan()
			username := strings.TrimSpace(scanner.Text())

			fmt.Print("Password: ")
			scanner.Scan()
			password := strings.TrimSpace(scanner.Text())

			fmt.Print("Email: ")
			scanner.Scan()
			email := strings.TrimSpace(scanner.Text())

			if err := client.Register(username, password, email); err != nil {
				fmt.Printf("✗ Registration failed: %v\n", err)
			}

		case "2":
			fmt.Print("Username: ")
			scanner.Scan()
			username := strings.TrimSpace(scanner.Text())

			fmt.Print("Password: ")
			scanner.Scan()
			password := strings.TrimSpace(scanner.Text())

			if err := client.Login(username, password); err != nil {
				fmt.Printf("✗ Login failed: %v\n", err)
			}

		case "3":
			if client.sessionID == "" {
				fmt.Println("✗ Please login first")
				continue
			}

			fmt.Print("File path: ")
			scanner.Scan()
			filepath := strings.TrimSpace(scanner.Text())

			if err := client.UploadFile(filepath); err != nil {
				fmt.Printf("✗ Upload failed: %v\n", err)
			}

		case "4":
			if client.sessionID == "" {
				fmt.Println("✗ Please login first")
				continue
			}

			fmt.Print("File ID: ")
			scanner.Scan()
			var fileID int64
			fmt.Sscanf(scanner.Text(), "%d", &fileID)

			fmt.Print("Save as (press Enter for original name): ")
			scanner.Scan()
			savePath := strings.TrimSpace(scanner.Text())

			if err := client.DownloadFile(fileID, savePath); err != nil {
				fmt.Printf("✗ Download failed: %v\n", err)
			}

		case "5":
			if client.sessionID == "" {
				fmt.Println("✗ Please login first")
				continue
			}

			if err := client.ListFiles(); err != nil {
				fmt.Printf("✗ List failed: %v\n", err)
			}

		case "6":
			if client.sessionID == "" {
				fmt.Println("✗ Please login first")
				continue
			}

			fmt.Print("File ID: ")
			scanner.Scan()
			var fileID int64
			fmt.Sscanf(scanner.Text(), "%d", &fileID)

			fmt.Print("Target username: ")
			scanner.Scan()
			targetUsername := strings.TrimSpace(scanner.Text())

			if err := client.ShareFile(fileID, targetUsername); err != nil {
				fmt.Printf("✗ Share failed: %v\n", err)
			}

		case "7":
			if err := client.Disconnect(); err != nil {
				fmt.Printf("✗ Disconnect failed: %v\n", err)
			}
			return

		case "8":
			if client.sessionID != "" {
				client.Disconnect()
			}
			fmt.Println("Goodbye!")
			return

		default:
			fmt.Println("✗ Invalid choice")
		}
	}
}