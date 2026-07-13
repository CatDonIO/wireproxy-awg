package wireproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ========== КОНСТАНТЫ ==========
const (
	udpBufferSize        = 1500
	maxUDPConnections    = 1000
	udpConnectionTimeout = 40 * time.Second
	udpCleanupInterval   = 30 * time.Second
	dnsCacheTTL          = 5 * time.Second
	dnsCacheMaxSize      = 1000
)

// ========== DNS КЭШ ==========
type dnsCache struct {
	cache   map[string]*cacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

type cacheEntry struct {
	ip        net.IP
	timestamp time.Time
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{
		cache:   make(map[string]*cacheEntry),
		ttl:     ttl,
		maxSize: dnsCacheMaxSize,
	}
}

func (d *dnsCache) Resolve(host string) (net.IP, error) {
	d.mu.RLock()
	if entry, exists := d.cache[host]; exists {
		if time.Since(entry.timestamp) < d.ttl {
			d.mu.RUnlock()
			return entry.ip, nil
		}
	}
	d.mu.RUnlock()

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP found for %s", host)
	}

	var ip net.IP
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	if ip == nil {
		ip = ips[0]
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Ограничиваем размер кэша
	if len(d.cache) >= d.maxSize {
		oldest := time.Now()
		var oldestKey string
		for key, entry := range d.cache {
			if entry.timestamp.Before(oldest) {
				oldest = entry.timestamp
				oldestKey = key
			}
		}
		if oldestKey != "" {
			delete(d.cache, oldestKey)
		}
	}

	d.cache[host] = &cacheEntry{
		ip:        ip,
		timestamp: time.Now(),
	}
	return ip, nil
}

func (d *dnsCache) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for host, entry := range d.cache {
		if now.Sub(entry.timestamp) > d.ttl*3/2 {
			delete(d.cache, host)
		}
	}
}

// ========== ПУЛЫ БУФЕРОВ ==========
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, udpBufferSize)
		return &buf
	},
}

func getUDPBuffer() []byte {
	return *udpBufferPool.Get().(*[]byte)
}

func putUDPBuffer(buf []byte) {
	if cap(buf) == udpBufferSize {
		buf = buf[:cap(buf)]
		udpBufferPool.Put(&buf)
	}
}

// ========== UDP СОЕДИНЕНИЕ ==========
type udpConnection struct {
	conn       net.Conn
	lastUsed   time.Time
	client     *net.UDPAddr
	targetAddr *net.UDPAddr
	resolvedIP net.IP
	closeChan  chan struct{}
	closed     bool
	mu         sync.Mutex
	writeMu    sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
}

func newUDPConnection(conn net.Conn, client *net.UDPAddr, targetAddr *net.UDPAddr, resolvedIP net.IP) *udpConnection {
	ctx, cancel := context.WithCancel(context.Background())
	return &udpConnection{
		conn:       conn,
		lastUsed:   time.Now(),
		client:     client,
		targetAddr: targetAddr,
		resolvedIP: resolvedIP,
		closeChan:  make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (c *udpConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.cancel()
	close(c.closeChan)
	_ = c.conn.Close()
}

func (c *udpConnection) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *udpConnection) Context() context.Context {
	return c.ctx
}

// ========== ПУЛ СОЕДИНЕНИЙ ==========
type udpConnectionPool struct {
	connections  map[string]*udpConnection
	mu           sync.RWMutex
	dnsCache     *dnsCache
	maxSize      int
	currentSize  int
	creationLock sync.Map
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

func newUDPConnectionPool(maxSize int) *udpConnectionPool {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &udpConnectionPool{
		connections: make(map[string]*udpConnection),
		dnsCache:    newDNSCache(dnsCacheTTL),
		maxSize:     maxSize,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Запускаем горутину очистки внутри пула
	pool.wg.Add(1)
	go pool.cleanupRoutine()

	return pool
}

func (p *udpConnectionPool) cleanupRoutine() {
	defer p.wg.Done()

	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			// Закрываем все соединения при завершении
			p.mu.Lock()
			for _, conn := range p.connections {
				conn.Close()
			}
			p.connections = make(map[string]*udpConnection)
			p.currentSize = 0
			p.mu.Unlock()
			return
		case <-ticker.C:
			p.Cleanup(udpConnectionTimeout)
			p.dnsCache.Cleanup()
		}
	}
}

func (p *udpConnectionPool) Get(key string) (*udpConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	conn, exists := p.connections[key]
	if exists && !conn.IsClosed() {
		conn.lastUsed = time.Now()
		return conn, true
	}
	return nil, false
}

func (p *udpConnectionPool) Set(key string, conn *udpConnection) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.currentSize >= p.maxSize {
		toRemove := p.maxSize / 5
		if toRemove < 1 {
			toRemove = 1
		}
		p.cleanupOldestLocked(toRemove)
		if p.currentSize >= p.maxSize {
			return false
		}
	}

	conn.lastUsed = time.Now()
	p.connections[key] = conn
	p.currentSize++
	return true
}

func (p *udpConnectionPool) Delete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, exists := p.connections[key]; exists {
		conn.Close()
		delete(p.connections, key)
		p.currentSize--
	}
	p.creationLock.Delete(key)
}

func (p *udpConnectionPool) Cleanup(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupOldLocked(maxAge)
}

func (p *udpConnectionPool) cleanupOldLocked(maxAge time.Duration) {
	now := time.Now()
	toDelete := make([]string, 0)

	for key, conn := range p.connections {
		if conn.IsClosed() || now.Sub(conn.lastUsed) > maxAge {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		if conn, exists := p.connections[key]; exists {
			conn.Close()
			delete(p.connections, key)
			p.currentSize--
		}
		p.creationLock.Delete(key)
	}
}

func (p *udpConnectionPool) cleanupOldestLocked(count int) {
	if p.currentSize <= count {
		return
	}

	type keyTime struct {
		key string
		t   time.Time
	}

	oldest := make([]keyTime, 0, count)
	for key, conn := range p.connections {
		if conn.IsClosed() {
			continue
		}
		if len(oldest) < count {
			oldest = append(oldest, keyTime{key: key, t: conn.lastUsed})
			continue
		}
		maxIdx := 0
		for i := 1; i < len(oldest); i++ {
			if oldest[i].t.Before(oldest[maxIdx].t) {
				maxIdx = i
			}
		}
		if conn.lastUsed.Before(oldest[maxIdx].t) {
			oldest[maxIdx] = keyTime{key: key, t: conn.lastUsed}
		}
	}

	for _, kt := range oldest {
		if conn, exists := p.connections[kt.key]; exists {
			conn.Close()
			delete(p.connections, kt.key)
			p.currentSize--
		}
		p.creationLock.Delete(kt.key)
	}
}

func (p *udpConnectionPool) resolveTarget(host string, port uint16) (string, net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, strconv.Itoa(int(port))), ip, nil
	}
	ip, err := p.dnsCache.Resolve(host)
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), ip, nil
}

func (p *udpConnectionPool) Shutdown() {
	p.cancel()
	p.wg.Wait()
}

// ========== ПАРСИНГ SOCKS5 UDP ЗАГОЛОВКА ==========
func parseSocks5UDPHeader(data []byte) (host string, port uint16, headerLen int, ok bool) {
	if len(data) < 4 {
		return "", 0, 0, false
	}

	if data[0] != 0x00 || data[1] != 0x00 {
		return "", 0, 0, false
	}

	atyp := data[3]

	switch atyp {
	case 0x01:
		if len(data) < 10 {
			return "", 0, 0, false
		}
		host = net.IPv4(data[4], data[5], data[6], data[7]).String()
		port = binary.BigEndian.Uint16(data[8:10])
		headerLen = 10
		ok = true

	case 0x03:
		if len(data) < 4 {
			return "", 0, 0, false
		}
		domainLen := int(data[4])
		if len(data) < 5+domainLen+2 {
			return "", 0, 0, false
		}
		host = string(data[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(data[5+domainLen : 5+domainLen+2])
		headerLen = 7 + domainLen
		ok = true

	case 0x04:
		if len(data) < 22 {
			return "", 0, 0, false
		}
		host = net.IP(data[4:20]).String()
		port = binary.BigEndian.Uint16(data[20:22])
		headerLen = 22
		ok = true

	default:
		return "", 0, 0, false
	}

	return
}

// ========== ОТПРАВКА UDP ОТВЕТА ==========
func sendUDPResponse(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetIP net.IP, targetPort int, data []byte) {
	var headerLen int
	if targetIP.To4() != nil {
		headerLen = 10
	} else {
		headerLen = 22
	}

	totalLen := headerLen + len(data)

	buf := getUDPBuffer()
	defer putUDPBuffer(buf)

	if cap(buf) < totalLen {
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}

	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00

	if targetIP.To4() != nil {
		buf[3] = 0x01
		copy(buf[4:8], targetIP.To4())
		binary.BigEndian.PutUint16(buf[8:10], uint16(targetPort))
		copy(buf[10:], data)
	} else {
		buf[3] = 0x04
		copy(buf[4:20], targetIP)
		binary.BigEndian.PutUint16(buf[20:22], uint16(targetPort))
		copy(buf[22:], data)
	}

	_, _ = serverConn.WriteToUDP(buf, clientAddr)
}

// ========== UDP READER ГОРУТИНА ==========
func startUDPReader(conn *udpConnection, serverConn *net.UDPConn, pool *udpConnectionPool, connKey string) {
	defer func() {
		if r := recover(); r != nil {
			errorLogger.Printf("UDP reader panic recovered: %v", r)
		}
		conn.Close()
		pool.Delete(connKey)
	}()

	buf := getUDPBuffer()
	defer putUDPBuffer(buf)

	for {
		select {
		case <-conn.closeChan:
			return
		case <-conn.ctx.Done():
			return
		default:
		}

		if err := conn.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			return
		}

		n, err := conn.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if conn.IsClosed() {
			return
		}

		conn.lastUsed = time.Now()
		
		// Копируем данные для отправки, т.к. буфер будет возвращен в пул
		data := make([]byte, n)
		copy(data, buf[:n])
		sendUDPResponse(serverConn, conn.client, conn.resolvedIP, conn.targetAddr.Port, data)
	}
}

// ========== ОБРАБОТКА UDP ПАКЕТА ==========
func handleUDPPacket(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, vt *VirtualTun, pool *udpConnectionPool) {
	host, port, headerLen, ok := parseSocks5UDPHeader(data)
	if !ok {
		errorLogger.Printf("Failed to parse SOCKS5 UDP header from %s", clientAddr.String())
		return
	}

	// Копируем полезную нагрузку, т.к. data будет возвращена в пул
	payload := make([]byte, len(data)-headerLen)
	copy(payload, data[headerLen:])

	connKey := clientAddr.String()

	if udpConn, exists := pool.Get(connKey); exists {
		udpConn.writeMu.Lock()
		defer udpConn.writeMu.Unlock()
		if !udpConn.IsClosed() {
			_, _ = udpConn.conn.Write(payload)
		}
		return
	}

	if _, loaded := pool.creationLock.LoadOrStore(connKey, struct{}{}); loaded {
		return
	}

	go func() {
		// Убеждаемся, что creationLock будет снят в любом случае
		defer pool.creationLock.Delete(connKey)

		targetAddr, resolvedIP, err := pool.resolveTarget(host, port)
		if err != nil {
			errorLogger.Printf("Failed to resolve target %s:%d: %v", host, port, err)
			return
		}

		host2, portStr, _ := net.SplitHostPort(targetAddr)
		port2, _ := strconv.Atoi(portStr)
		targetUDPAddr := &net.UDPAddr{
			IP:   net.ParseIP(host2),
			Port: port2,
		}

		udpConn, err := vt.Tnet.Dial("udp", targetAddr)
		if err != nil {
			errorLogger.Printf("Failed to dial target %s: %v", targetAddr, err)
			return
		}

		conn := newUDPConnection(udpConn, clientAddr, targetUDPAddr, resolvedIP)

		if !pool.Set(connKey, conn) {
			_ = udpConn.Close()
			errorLogger.Printf("UDP connection limit reached, dropping packet for %s", connKey)
			return
		}

		go startUDPReader(conn, serverConn, pool, connKey)

		conn.writeMu.Lock()
		defer conn.writeMu.Unlock()
		if !conn.IsClosed() {
			_, _ = conn.conn.Write(payload)
		}
	}()
}

// ========== SOCKS5 UDP СЕРВЕР ==========
type socks5UDPServer struct {
	addr   string
	vt     *VirtualTun
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	conn   *net.UDPConn
	pool   *udpConnectionPool
}

func newSocks5UDPServer(addr string, vt *VirtualTun) *socks5UDPServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &socks5UDPServer{
		addr:   addr,
		vt:     vt,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *socks5UDPServer) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	s.conn = conn

	errorLogger.Printf("SOCKS5 UDP listening on %s", s.addr)

	if err := conn.SetReadBuffer(64 * 1024); err != nil {
		errorLogger.Printf("Warning: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(64 * 1024); err != nil {
		errorLogger.Printf("Warning: failed to set write buffer: %v", err)
	}

	s.pool = newUDPConnectionPool(maxUDPConnections)

	s.wg.Add(1)
	go s.serve()

	return nil
}

func (s *socks5UDPServer) serve() {
	defer s.wg.Done()
	// nolint:errcheck // close errors are not critical
	defer s.conn.Close()
	defer s.pool.Shutdown()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		buf := getUDPBuffer()

		if err := s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			putUDPBuffer(buf)
			continue
		}

		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			putUDPBuffer(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			errorLogger.Printf("UDP read error: %v", err)
			return
		}

		// Создаем копию данных для горутины
		data := make([]byte, n)
		copy(data, buf[:n])
		putUDPBuffer(buf)

		select {
		case <-s.ctx.Done():
			return
		default:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				handleUDPPacket(s.conn, clientAddr, data, s.vt, s.pool)
			}()
		}
	}
}

func (s *socks5UDPServer) Shutdown() {
	s.cancel()
	s.wg.Wait()
}

// ========== SOCKS5 TCP СЕРВЕР ==========
type socks5TCPServer struct {
	addr     string
	vt       *VirtualTun
	username string
	password string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	listener net.Listener
}

func newSocks5TCPServer(addr string, vt *VirtualTun, username, password string) *socks5TCPServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &socks5TCPServer{
		addr:     addr,
		vt:       vt,
		username: username,
		password: password,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *socks5TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen TCP: %w", err)
	}
	s.listener = listener

	s.wg.Add(1)
	go s.serve()

	errorLogger.Printf("SOCKS5 TCP listening on %s", s.addr)
	return nil
}

func (s *socks5TCPServer) serve() {
	defer s.wg.Done()
	// nolint:errcheck // close errors are not critical
	defer s.listener.Close()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if !strings.Contains(err.Error(), "closed") {
					errorLogger.Printf("TCP accept error: %v", err)
				}
				continue
			}
		}

		select {
		case <-s.ctx.Done():
			conn.Close()
			return
		default:
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleTCP(conn)
			}()
		}
	}
}

func (s *socks5TCPServer) handleTCP(conn net.Conn) {
	// nolint:errcheck // close errors are not critical
	defer conn.Close()

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		errorLogger.Printf("Handshake read error: %v", err)
		return
	}

	if buf[0] != 0x05 {
		errorLogger.Printf("Not SOCKS5")
		return
	}

	// Аутентификация
	if s.username != "" {
		methods := buf[2:n]
		hasAuth := false
		for _, m := range methods {
			if m == 0x02 {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			// nolint:errcheck // write errors are not critical
			conn.Write([]byte{0x05, 0xFF})
			errorLogger.Printf("No auth method supported")
			return
		}

		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			errorLogger.Printf("Failed to write auth method: %v", err)
			return
		}

		n, err = conn.Read(buf)
		if err != nil {
			errorLogger.Printf("Auth read error: %v", err)
			return
		}

		if n < 3 || buf[0] != 0x01 {
			errorLogger.Printf("Invalid auth packet")
			return
		}

		userLen := int(buf[1])
		if n < 2+userLen+1 {
			errorLogger.Printf("Auth packet too short")
			return
		}
		username := string(buf[2 : 2+userLen])
		passLen := int(buf[2+userLen])
		if n < 3+userLen+passLen {
			errorLogger.Printf("Auth packet too short for password")
			return
		}
		password := string(buf[3+userLen : 3+userLen+passLen])

		if username != s.username || password != s.password {
			// nolint:errcheck // write errors are not critical
			conn.Write([]byte{0x05, 0x01})
			errorLogger.Printf("Auth failed")
			return
		}

		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			errorLogger.Printf("Failed to write auth success: %v", err)
			return
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			errorLogger.Printf("Failed to write no-auth: %v", err)
			return
		}
	}

	n, err = conn.Read(buf)
	if err != nil {
		errorLogger.Printf("Command read error: %v", err)
		return
	}

	if n < 4 {
		errorLogger.Printf("Command too short")
		return
	}

	cmd := buf[1]

	// DNS запрос
	if cmd == 0xF0 {
		domainLen := int(buf[4])
		if n < 5+domainLen {
			// nolint:errcheck // write errors are not critical
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}
		domain := string(buf[5 : 5+domainLen])

		addr, err := s.vt.ResolveAddrWithContext(s.ctx, domain)
		if err != nil {
			errorLogger.Printf("DNS resolution failed: %v", err)
			// nolint:errcheck // write errors are not critical
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return
		}

		ip := addr.AsSlice()
		response := []byte{0x05, 0x00, 0x00, 0x01}
		response = append(response, ip...)
		response = append(response, 0x00, 0x00)
		// nolint:errcheck // write errors are not critical
		conn.Write(response)
		return
	}

	// UDP ASSOCIATE
	if cmd == 0x03 {
		_, portStr, _ := net.SplitHostPort(s.addr)
		port, _ := strconv.Atoi(portStr)

		response := []byte{
			0x05, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
		binary.BigEndian.PutUint16(response[8:10], uint16(port))
		// nolint:errcheck // write errors are not critical
		conn.Write(response)

		<-s.ctx.Done()
		return
	}

	// CONNECT
	if cmd != 0x01 {
		errorLogger.Printf("Unsupported command: %x", cmd)
		return
	}

	var host string
	var port uint16
	addrType := buf[3]

	switch addrType {
	case 0x01:
		if n < 10 {
			return
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
	case 0x04:
		if n < 22 {
			return
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
	default:
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	target, err := s.vt.Tnet.Dial("tcp", targetAddr)
	if err != nil {
		errorLogger.Printf("Failed to connect: %v", err)
		// nolint:errcheck // write errors are not critical
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	// nolint:errcheck // close errors are not critical
	defer target.Close()

	// nolint:errcheck // write errors are not critical
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go func() {
		// nolint:errcheck // copy errors are not critical
		io.Copy(target, conn)
	}()
	// nolint:errcheck // copy errors are not critical
	io.Copy(conn, target)
}

func (s *socks5TCPServer) Shutdown() {
	s.cancel()
	if s.listener != nil {
		// nolint:errcheck // close errors are not critical
		s.listener.Close()
	}
	s.wg.Wait()
}

// ========== SOCKS5 СЕРВЕР (ОБЪЕДИНЕННЫЙ) ==========
type CustomSocks5Server struct {
	tcp *socks5TCPServer
	udp *socks5UDPServer
}

func NewCustomSocks5Server(addr string, vt *VirtualTun, username, password string) *CustomSocks5Server {
	return &CustomSocks5Server{
		tcp: newSocks5TCPServer(addr, vt, username, password),
		udp: newSocks5UDPServer(addr, vt),
	}
}

func (s *CustomSocks5Server) Start() error {
	if err := s.tcp.Start(); err != nil {
		return err
	}
	if err := s.udp.Start(); err != nil {
		s.tcp.Shutdown()
		return err
	}
	return nil
}

func (s *CustomSocks5Server) Shutdown() {
	s.tcp.Shutdown()
	s.udp.Shutdown()
}
