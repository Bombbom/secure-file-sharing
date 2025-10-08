package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
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

// Protocol structures
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
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
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

// Server structure
type Server struct {
	db            *sql.DB
	listener      net.Listener
	clients       map[string]*ClientSession
	clientsMutex  sync.RWMutex
	fileStorage   string
	serverID      string
	privateKey    *rsa.PrivateKey
	shutdownChan  chan struct{}
	wg            sync.WaitGroup
}

type ClientSession struct {
	conn       net.Conn
	userID     int64
	username   string
	sessionID  string
	lastActive time.Time
	mutex      sync.Mutex
}

// Database initialization
func initDatabase(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		filepath TEXT NOT NULL,
		filesize INTEGER NOT NULL,
		owner_id INTEGER NOT NULL,
		checksum TEXT NOT NULL,
		encryption_key TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS file_shares (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		shared_by INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (file_id) REFERENCES files(id),
		FOREIGN KEY (user_id) REFERENCES users(id),
		FOREIGN KEY (shared_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT UNIQUE NOT NULL,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(session_id);
	CREATE INDEX IF NOT EXISTS idx_shares_user ON file_shares(user_id);
	`

	_, err = db.Exec(schema)
	return db, err
}

// Generate self-signed certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Secure File Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// NewServer creates a new server instance
func NewServer(address, dbPath, storageDir, serverID string) (*Server, error) {
	db, err := initDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("database init failed: %v", err)
	}

	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("storage dir creation failed: %v", err)
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("cert generation failed: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("listen failed: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	server := &Server{
		db:           db,
		listener:     listener,
		clients:      make(map[string]*ClientSession),
		fileStorage:  storageDir,
		serverID:     serverID,
		privateKey:   privateKey,
		shutdownChan: make(chan struct{}),
	}

	log.Printf("[%s] Server started on %s with TLS", serverID, address)
	return server, nil
}

// Start server
func (s *Server) Start() {
	go s.cleanupExpiredSessions()

	for {
		select {
		case <-s.shutdownChan:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.shutdownChan:
					return
				default:
					log.Printf("[%s] Accept error: %v", s.serverID, err)
					continue
				}
			}

			s.wg.Add(1)
			go s.handleClient(conn)
		}
	}
}

// Handle client connection
func (s *Server) handleClient(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	log.Printf("[%s] New connection from %s", s.serverID, conn.RemoteAddr())

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var session *ClientSession

	for {
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			if err != io.EOF {
				log.Printf("[%s] Decode error: %v", s.serverID, err)
			}
			break
		}

		var response Response

		switch msg.Type {
		case MsgRegister:
			response = s.handleRegister(msg.Data)
		case MsgLogin:
			response, session = s.handleLogin(msg.Data, conn)
		case MsgUpload:
			if session == nil {
				response = Response{Success: false, Message: "Not authenticated"}
			} else {
				response = s.handleUpload(msg.Data, session, conn)
			}
		case MsgDownload:
			if session == nil {
				response = Response{Success: false, Message: "Not authenticated"}
			} else {
				response = s.handleDownload(msg.Data, session, conn)
			}
		case MsgList:
			if session == nil {
				response = Response{Success: false, Message: "Not authenticated"}
			} else {
				response = s.handleList(session)
			}
		case MsgShare:
			if session == nil {
				response = Response{Success: false, Message: "Not authenticated"}
			} else {
				response = s.handleShare(msg.Data, session)
			}
		case MsgDisconnect:
			if session != nil {
				s.removeSession(session.sessionID)
			}
			response = Response{Success: true, Message: "Goodbye"}
			encoder.Encode(response)
			return
		default:
			response = Response{Success: false, Message: "Unknown command"}
		}

		if err := encoder.Encode(response); err != nil {
			log.Printf("[%s] Encode error: %v", s.serverID, err)
			break
		}
	}

	if session != nil {
		s.removeSession(session.sessionID)
	}
}

// Handle registration
func (s *Server) handleRegister(data json.RawMessage) Response {
	var req RegisterRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return Response{Success: false, Message: "Invalid request"}
	}

	if req.Username == "" || req.Password == "" {
		return Response{Success: false, Message: "Username and password required"}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return Response{Success: false, Message: "Registration failed"}
	}

	_, err = s.db.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		req.Username, string(hash), req.Email,
	)

	if err != nil {
		return Response{Success: false, Message: "Username already exists"}
	}

	log.Printf("[%s] New user registered: %s", s.serverID, req.Username)
	return Response{Success: true, Message: "Registration successful"}
}

// Handle login
func (s *Server) handleLogin(data json.RawMessage, conn net.Conn) (Response, *ClientSession) {
	var req LoginRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return Response{Success: false, Message: "Invalid request"}, nil
	}

	var userID int64
	var passwordHash string
	err := s.db.QueryRow(
		"SELECT id, password_hash FROM users WHERE username = ?",
		req.Username,
	).Scan(&userID, &passwordHash)

	if err != nil {
		return Response{Success: false, Message: "Invalid credentials"}, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		return Response{Success: false, Message: "Invalid credentials"}, nil
	}

	sessionID := generateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = s.db.Exec(
		"INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, userID, expiresAt,
	)

	if err != nil {
		return Response{Success: false, Message: "Login failed"}, nil
	}

	session := &ClientSession{
		conn:       conn,
		userID:     userID,
		username:   req.Username,
		sessionID:  sessionID,
		lastActive: time.Now(),
	}

	s.clientsMutex.Lock()
	s.clients[sessionID] = session
	s.clientsMutex.Unlock()

	log.Printf("[%s] User logged in: %s (session: %s)", s.serverID, req.Username, sessionID)

	return Response{
		Success: true,
		Message: "Login successful",
		Data:    map[string]string{"session_id": sessionID},
	}, session
}

// Handle file upload
func (s *Server) handleUpload(data json.RawMessage, session *ClientSession, conn net.Conn) Response {
	var req UploadRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return Response{Success: false, Message: "Invalid request"}
	}

	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		return Response{Success: false, Message: "Encryption key generation failed"}
	}

	filename := fmt.Sprintf("%d_%s_%s", session.userID, time.Now().Format("20060102150405"), filepath.Base(req.Filename))
	storedPath := filepath.Join(s.fileStorage, filename)

	file, err := os.Create(storedPath)
	if err != nil {
		return Response{Success: false, Message: "File creation failed"}
	}
	defer file.Close()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return Response{Success: false, Message: "Encryption failed"}
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return Response{Success: false, Message: "IV generation failed"}
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: file}

	if _, err := file.Write(iv); err != nil {
		return Response{Success: false, Message: "Write failed"}
	}

	buffer := make([]byte, 32*1024)
	var totalWritten int64

	for totalWritten < req.FileSize {
		n, err := conn.Read(buffer)
		if err != nil {
			return Response{Success: false, Message: "Read failed"}
		}
		if _, err := writer.Write(buffer[:n]); err != nil {
			return Response{Success: false, Message: "Write failed"}
		}
		totalWritten += int64(n)
	}

	_, err = s.db.Exec(
		"INSERT INTO files (filename, filepath, filesize, owner_id, checksum, encryption_key) VALUES (?, ?, ?, ?, ?, ?)",
		req.Filename, filename, req.FileSize, session.userID, req.Checksum, hex.EncodeToString(encryptionKey),
	)

	if err != nil {
		os.Remove(storedPath)
		return Response{Success: false, Message: "Database insert failed"}
	}

	log.Printf("[%s] File uploaded by %s: %s (%d bytes)", s.serverID, session.username, req.Filename, req.FileSize)

	return Response{Success: true, Message: "Upload successful"}
}

// Handle file download
func (s *Server) handleDownload(data json.RawMessage, session *ClientSession, conn net.Conn) Response {
	var req DownloadRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return Response{Success: false, Message: "Invalid request"}
	}

	var storedPath, filename, encKeyHex string
	var filesize int64
	var ownerID int64

	err := s.db.QueryRow(`
		SELECT f.filepath, f.filename, f.filesize, f.encryption_key, f.owner_id
		FROM files f
		LEFT JOIN file_shares fs ON f.id = fs.file_id AND fs.user_id = ?
		WHERE f.id = ? AND (f.owner_id = ? OR fs.user_id = ?)
	`, session.userID, req.FileID, session.userID, session.userID).Scan(&storedPath, &filename, &filesize, &encKeyHex, &ownerID)

	if err != nil {
		return Response{Success: false, Message: "File not found or access denied"}
	}

	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return Response{Success: false, Message: "Decryption failed"}
	}

	fullPath := filepath.Join(s.fileStorage, storedPath)

	file, err := os.Open(fullPath)
	if err != nil {
		return Response{Success: false, Message: "File open failed"}
	}
	defer file.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := file.Read(iv); err != nil {
		return Response{Success: false, Message: "Read IV failed"}
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return Response{Success: false, Message: "Decryption failed"}
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	reader := &cipher.StreamReader{S: stream, R: file}

	response := Response{
		Success: true,
		Message: "Download ready",
		Data: map[string]interface{}{
			"filename": filename,
			"filesize": filesize,
		},
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		return Response{Success: false, Message: "Response send failed"}
	}

	buffer := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			log.Printf("Read error: %v", err)
			break
		}
		if n == 0 {
			break
		}
		if _, err := conn.Write(buffer[:n]); err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}

	log.Printf("[%s] File downloaded by %s: %s", s.serverID, session.username, filename)

	return Response{Success: true, Message: "Download completed"}
}

// Handle list files
func (s *Server) handleList(session *ClientSession) Response {
	rows, err := s.db.Query(`
		SELECT DISTINCT f.id, f.filename, f.filesize, f.owner_id, u.username, f.checksum, f.created_at
		FROM files f
		JOIN users u ON f.owner_id = u.id
		LEFT JOIN file_shares fs ON f.id = fs.file_id
		WHERE f.owner_id = ? OR fs.user_id = ?
		ORDER BY f.created_at DESC
	`, session.userID, session.userID)

	if err != nil {
		return Response{Success: false, Message: "Query failed"}
	}
	defer rows.Close()

	var files []FileInfo
	for rows.Next() {
		var f FileInfo
		if err := rows.Scan(&f.ID, &f.Filename, &f.Size, &f.OwnerID, &f.Owner, &f.Checksum, &f.CreatedAt); err != nil {
			continue
		}
		files = append(files, f)
	}

	return Response{Success: true, Message: "Files retrieved", Data: files}
}

// Handle share file
func (s *Server) handleShare(data json.RawMessage, session *ClientSession) Response {
	var req ShareRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return Response{Success: false, Message: "Invalid request"}
	}

	var ownerID int64
	err := s.db.QueryRow("SELECT owner_id FROM files WHERE id = ?", req.FileID).Scan(&ownerID)
	if err != nil || ownerID != session.userID {
		return Response{Success: false, Message: "File not found or not owned by you"}
	}

	var targetUserID int64
	err = s.db.QueryRow("SELECT id FROM users WHERE username = ?", req.TargetUsername).Scan(&targetUserID)
	if err != nil {
		return Response{Success: false, Message: "Target user not found"}
	}

	_, err = s.db.Exec(
		"INSERT INTO file_shares (file_id, user_id, shared_by) VALUES (?, ?, ?)",
		req.FileID, targetUserID, session.userID,
	)

	if err != nil {
		return Response{Success: false, Message: "Share failed"}
	}

	log.Printf("[%s] File %d shared by %s to %s", s.serverID, req.FileID, session.username, req.TargetUsername)

	return Response{Success: true, Message: "File shared successfully"}
}

// Utility functions
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) removeSession(sessionID string) {
	s.clientsMutex.Lock()
	delete(s.clients, sessionID)
	s.clientsMutex.Unlock()

	s.db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
}

func (s *Server) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
		case <-s.shutdownChan:
			return
		}
	}
}

func (s *Server) Shutdown() {
	close(s.shutdownChan)
	s.listener.Close()
	s.wg.Wait()
	s.db.Close()
	log.Printf("[%s] Server shut down", s.serverID)
}

func calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func main() {
	serverID := "SERVER-1"
	if len(os.Args) > 1 {
		serverID = os.Args[1]
	}

	address := ":8443"
	if len(os.Args) > 2 {
		address = os.Args[2]
	}

	dbPath := fmt.Sprintf("server_%s.db", serverID)
	storageDir := fmt.Sprintf("storage_%s", serverID)

	server, err := NewServer(address, dbPath, storageDir, serverID)
	if err != nil {
		log.Fatalf("Server creation failed: %v", err)
	}

	log.Printf("=== Secure File Sharing Server ===")
	log.Printf("Server ID: %s", serverID)
	log.Printf("Address: %s", address)
	log.Printf("Database: %s", dbPath)
	log.Printf("Storage: %s", storageDir)
	log.Printf("==================================")

	server.Start()
}