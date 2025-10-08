# Requirments 

A secure file-sharing system with end-to-end encryption, supporting multi-client, multi-server architecture, load balancing, and comprehensive security features.

## Features 

### Socket Logic
- **Basic Socket Operations**: TCP connection, send/receive data
- **Advanced Socket**: TLS/SSL encryption, connection pooling, timeout handling
- **Non-blocking I/O**: Concurrent connection handling với goroutines

### Application Logic
- **User Management**: Registration, Login, Session management
- **File Operations**: Upload, Download, List, Share
- **Access Control**: File ownership, permission checking
- **Protocol**: Custom JSON-based protocol với message types

### Input/Output
- **File I/O**: Read/write files với buffering
- **Network I/O**: TLS socket communication
- **Database I/O**: SQLite operations
- **Stream Processing**: Chunked file transfer

### Database
- **SQLite3**: Lightweight, serverless database
- **Tables**: users, files, file_shares, sessions
- **Relationships**: Foreign keys, indexes
- **Transactions**: ACID compliance

### Threading/Concurrency
- **Goroutines**: Concurrent client handling
- **Channels**: Safe communication between goroutines
- **Mutex/RWMutex**: Thread-safe data structures
- **WaitGroup**: Graceful shutdown

### Authentication
- **Sign Up**: User registration với password hashing (bcrypt)
- **Sign In**: Session-based authentication
- **Session Management**: Token-based với expiration
- **Authorization**: Role-based file access

### Multi-Client Support
- **Concurrent Connections**: Unlimited concurrent clients
- **Session Isolation**: Per-client session management
- **Thread-safe Operations**: Mutex-protected shared resources

### Multi-Server Support
- **Multiple Server Instances**: Run nhiều servers độc lập
- **Separate Databases**: Mỗi server có DB riêng
- **Load Balancing Ready**: Horizontal scaling

### Cryptography
- **TLS 1.2+**: Encrypted transport layer
- **AES-256-CFB**: File encryption at rest
- **RSA-2048**: Key exchange
- **SHA-256**: File integrity checking (checksum)
- **bcrypt**: Password hashing
- **Random IV**: Unique initialization vector per file

### Load Balancing
- **Round Robin**: Distribute evenly across backends
- **Least Connections**: Route to least busy server
- **Health Checks**: Automatic backend monitoring
- **Failover**: Automatic unhealthy backend removal

## TODO
