# Secure File Sharing System

A secure file-sharing system with end-to-end encryption, supporting multi-client, multi-server architecture, load balancing, and comprehensive security features.

## System Architecture


```
┌─────────┐     ┌─────────┐     ┌─────────┐
│Client 1 │     │Client 2 │     │Client 3 │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     │          TLS Encrypted        │
     └───────────────┼───────────────┘
                     │
              ┌──────▼──────┐
              │Load Balancer│ (Port 9000)
              │Round Robin  │
              └──────┬──────┘
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼───┐  ┌───▼────┐ ┌───▼────┐
    │Server 1│  │Server 2│ │Server 3│
    │:8443   │  │:8444   │ │:8445   │
    └────┬───┘  └───┬────┘ └───┬────┘
         │          │          │
    ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
    │SQLite 1│ │SQLite 2│ │SQLite 3│
    │Files 1 │ │Files 2 │ │Files 3 │
    └────────┘ └────────┘ └────────┘
```

- 

## Directory Structure


```
secure-file-sharing/
├── main.go              # Server implementation
├── client.go            # Client application
├── loadbalancer.go      # Load balancer
├── go.mod               # Go dependencies
├── README.md            # Documentation
├── scripts/
│   ├── start-servers.sh    # Script khởi động multi-server
│   ├── start-lb.sh         # Script khởi động load balancer
│   └── test-demo.sh        # Script demo
├── server_SERVER-1.db   # Database server 1
├── server_SERVER-2.db   # Database server 2
├── server_SERVER-3.db   # Database server 3
├── storage_SERVER-1/    # File storage server 1
├── storage_SERVER-2/    # File storage server 2
└── storage_SERVER-3/    # File storage server 3
```

## Install and Run demo

- Requirments 
- Build project


## Docs 
>> READ ...

## Future Enhancements 

1. **Web Interface**: HTTP/WebSocket frontend
2. **File Sharing Links**: Public/private share URLs
3. **Quota Management**: Per-user storage limits
4. **File Preview**: Thumbnail generation
5. **Compression**: Automatic compression for large files
6. **CDN Integration**: Static file distribution
7. **Database Migration**: PostgreSQL for production
8. **Kubernetes**: Container orchestration
9. **Monitoring**: Prometheus + Grafana
10. **CI/CD**: Automated testing and deployment


## References 

### Go Standard Library
- `crypto/tls` - TLS implementation
- `crypto/aes` - AES encryption
- `encoding/json` - JSON encoding
- `database/sql` - Database interface
- `net` - Network primitives

### Third-party Libraries
- `go-sqlite3` - SQLite driver
- `bcrypt` - Password hashing

### RFCs
- RFC 5246 - TLS 1.2
- RFC 5116 - AES-GCM
- RFC 7519 - JWT (for future enhancement)


## 📄 License

MIT License - Free to use and modify

---

**Made with ❤️ using Go**