package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Backend struct {
	Address   string
	Healthy   bool
	mutex     sync.RWMutex
	lastCheck time.Time
	failCount int32
}

type LoadBalancer struct {
	backends      []*Backend
	currentIndex  uint64
	listener      net.Listener
	healthCheck   time.Duration
	shutdownChan  chan struct{}
	wg            sync.WaitGroup
	algorithm     string // "round-robin" or "least-connections"
	connections   map[string]int32
	connMutex     sync.RWMutex
}

func NewLoadBalancer(listenAddr string, backends []string, algorithm string) (*LoadBalancer, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen failed: %v", err)
	}

	lb := &LoadBalancer{
		backends:     make([]*Backend, 0),
		listener:     listener,
		healthCheck:  10 * time.Second,
		shutdownChan: make(chan struct{}),
		algorithm:    algorithm,
		connections:  make(map[string]int32),
	}

	for _, addr := range backends {
		lb.backends = append(lb.backends, &Backend{
			Address: addr,
			Healthy: true,
		})
		lb.connections[addr] = 0
	}

	log.Printf("Load Balancer started on %s", listenAddr)
	log.Printf("Algorithm: %s", algorithm)
	log.Printf("Backends: %v", backends)

	return lb, nil
}

func (lb *LoadBalancer) Start() {
	go lb.healthCheckLoop()

	for {
		select {
		case <-lb.shutdownChan:
			return
		default:
			conn, err := lb.listener.Accept()
			if err != nil {
				select {
				case <-lb.shutdownChan:
					return
				default:
					log.Printf("Accept error: %v", err)
					continue
				}
			}

			lb.wg.Add(1)
			go lb.handleConnection(conn)
		}
	}
}

func (lb *LoadBalancer) getNextBackend() *Backend {
	if lb.algorithm == "least-connections" {
		return lb.getLeastConnectedBackend()
	}
	return lb.getRoundRobinBackend()
}

func (lb *LoadBalancer) getRoundRobinBackend() *Backend {
	for i := 0; i < len(lb.backends)*2; i++ {
		idx := atomic.AddUint64(&lb.currentIndex, 1) % uint64(len(lb.backends))
		backend := lb.backends[idx]

		backend.mutex.RLock()
		healthy := backend.Healthy
		backend.mutex.RUnlock()

		if healthy {
			return backend
		}
	}
	return nil
}

func (lb *LoadBalancer) getLeastConnectedBackend() *Backend {
	var selected *Backend
	var minConnections int32 = -1

	lb.connMutex.RLock()
	defer lb.connMutex.RUnlock()

	for _, backend := range lb.backends {
		backend.mutex.RLock()
		healthy := backend.Healthy
		backend.mutex.RUnlock()

		if !healthy {
			continue
		}

		conns := lb.connections[backend.Address]

		if minConnections == -1 || conns < minConnections {
			minConnections = conns
			selected = backend
		}
	}

	return selected
}

func (lb *LoadBalancer) handleConnection(clientConn net.Conn) {
	defer lb.wg.Done()
	defer clientConn.Close()

	backend := lb.getNextBackend()
	if backend == nil {
		log.Printf("No healthy backends available")
		return
	}

	lb.connMutex.Lock()
	lb.connections[backend.Address]++
	lb.connMutex.Unlock()

	defer func() {
		lb.connMutex.Lock()
		lb.connections[backend.Address]--
		lb.connMutex.Unlock()
	}()

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	backendConn, err := tls.Dial("tcp", backend.Address, config)
	if err != nil {
		log.Printf("Backend connection failed to %s: %v", backend.Address, err)
		backend.mutex.Lock()
		backend.failCount++
		if backend.failCount >= 3 {
			backend.Healthy = false
			log.Printf("Backend %s marked as unhealthy", backend.Address)
		}
		backend.mutex.Unlock()
		return
	}
	defer backendConn.Close()

	backend.mutex.Lock()
	backend.failCount = 0
	backend.mutex.Unlock()

	log.Printf("Forwarding connection %s -> %s", clientConn.RemoteAddr(), backend.Address)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientConn)
		backendConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

func (lb *LoadBalancer) healthCheckLoop() {
	ticker := time.NewTicker(lb.healthCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lb.checkBackends()
		case <-lb.shutdownChan:
			return
		}
	}
}

func (lb *LoadBalancer) checkBackends() {
	for _, backend := range lb.backends {
		go lb.checkBackend(backend)
	}
}

func (lb *LoadBalancer) checkBackend(backend *Backend) {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", backend.Address, config)
	if err != nil {
		backend.mutex.Lock()
		backend.Healthy = false
		backend.lastCheck = time.Now()
		backend.mutex.Unlock()
		log.Printf("Health check failed for %s: %v", backend.Address, err)
		return
	}
	conn.Close()

	backend.mutex.Lock()
	wasUnhealthy := !backend.Healthy
	backend.Healthy = true
	backend.lastCheck = time.Now()
	backend.failCount = 0
	backend.mutex.Unlock()

	if wasUnhealthy {
		log.Printf("Backend %s recovered and marked as healthy", backend.Address)
	}
}

func (lb *LoadBalancer) GetStatus() {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              LOAD BALANCER STATUS                          ║")
	fmt.Println("╠════════════════════════╦═══════════╦══════════╦════════════╣")
	fmt.Printf("║ %-22s ║ %-9s ║ %-8s ║ %-10s ║\n", "Backend", "Status", "Conns", "Last Check")
	fmt.Println("╠════════════════════════╬═══════════╬══════════╬════════════╣")

	for _, backend := range lb.backends {
		backend.mutex.RLock()
		status := "DOWN"
		if backend.Healthy {
			status = "UP"
		}
		lb.connMutex.RLock()
		conns := lb.connections[backend.Address]
		lb.connMutex.RUnlock()
		lastCheck := backend.lastCheck.Format("15:04:05")
		if backend.lastCheck.IsZero() {
			lastCheck = "Never"
		}
		backend.mutex.RUnlock()

		fmt.Printf("║ %-22s ║ %-9s ║ %-8d ║ %-10s ║\n",
			backend.Address, status, conns, lastCheck)
	}

	fmt.Println("╚════════════════════════╩═══════════╩══════════╩════════════╝")
}

func (lb *LoadBalancer) Shutdown() {
	close(lb.shutdownChan)
	lb.listener.Close()
	lb.wg.Wait()
	log.Println("Load Balancer shut down")
}

func main() {
	listenAddr := ":9000"
	algorithm := "round-robin"

	if len(os.Args) > 1 {
		listenAddr = os.Args[1]
	}

	if len(os.Args) > 2 {
		algorithm = os.Args[2]
	}

	backends := []string{
		"localhost:8443",
		"localhost:8444",
		"localhost:8445",
	}

	if len(os.Args) > 3 {
		backends = os.Args[3:]
	}

	lb, err := NewLoadBalancer(listenAddr, backends, algorithm)
	if err != nil {
		log.Fatalf("Load Balancer creation failed: %v", err)
	}

	fmt.Println(`
╔═══════════════════════════════════════════════════════════════╗
║          LOAD BALANCER - SECURE FILE SHARING SYSTEM           ║
╚═══════════════════════════════════════════════════════════════╝
`)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			lb.GetStatus()
		}
	}()

	lb.Start()
}