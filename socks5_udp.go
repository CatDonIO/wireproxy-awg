package wireproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ========== КОНСТАНТЫ ==========
const (
	udpBufferSize        = 1500             // Оптимально
	maxUDPConnections    = 1000             // Максимум соединений
	udpConnectionTimeout = 40 * time.Second // Время жизни соединений
	udpCleanupInterval   = 30 * time.Second // Интервал очистки
	dnsCacheTTL          = 5 * time.Second  // TTL DNS кэша
)

// ========== DNS КЭШ ==========
type DNSCache struct {
	cache map[string]*cacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

type cacheEntry struct {
	ip        net.IP
	timestamp time.Time
}

func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}

func (d *DNSCache) Resolve(host string) (net.IP, error) {
	// Проверяем кэш
	d.mu.RLock()
	if entry, exists := d.cache[host]; exists {
		if time.Since(entry.timestamp) < d.ttl {
			d.mu.RUnlock()
			return entry.ip, nil
		}
	}
	d.mu.RUnlock()

	// DNS запрос
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP found for %s", host)
	}

	// Предпочитаем IPv4
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

	// Сохраняем в кэш
	d.mu.Lock()
	d.cache[host] = &cacheEntry{
		ip:        ip,
		timestamp: time.Now(),
	}
	d.mu.Unlock()
	return ip, nil
}

// ========== ПУЛЫ БУФЕРОВ ==========
// Основной пул для пакетов
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, udpBufferSize)
		return &buf
	},
}

// Отдельный пул для reader'ов (уменьшает конкуренцию)
var readerBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, udpBufferSize)
		return &buf
	},
}

func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

func putBuffer(buf []byte) {
	if cap(buf) == udpBufferSize {
		buf = buf[:cap(buf)]
		bufferPool.Put(&buf)
	}
}

func getReaderBuffer() []byte {
	return *readerBufferPool.Get().(*[]byte)
}

func putReaderBuffer(buf []byte) {
	if cap(buf) == udpBufferSize {
		buf = buf[:cap(buf)]
		readerBufferPool.Put(&buf)
	}
}

// ========== UDP СОЕДИНЕНИЕ ==========
type UDPConnection struct {
	conn       net.Conn
	lastUsed   time.Time
	client     *net.UDPAddr
	targetAddr *net.UDPAddr
	resolvedIP net.IP
	closeChan  chan struct{}   // Сигнал для reader
	closed     atomic.Bool     // Защита от двойного закрытия
	closeOnce  sync.Once       // Гарантирует одно закрытие
	writeMutex sync.Mutex      // Защита записи
}

func NewUDPConnection(conn net.Conn, client *net.UDPAddr, targetAddr *net.UDPAddr, resolvedIP net.IP) *UDPConnection {
	return &UDPConnection{
		conn:       conn,
		lastUsed:   time.Now(),
		client:     client,
		targetAddr: targetAddr,
		resolvedIP: resolvedIP,
		closeChan:  make(chan struct{}),
	}
}

func (c *UDPConnection) Close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeChan)
		if err := c.conn.Close(); err != nil {
			errorLogger.Printf("Failed to close UDP connection: %v", err)
		}
	})
}

func (c *UDPConnection) IsClosed() bool {
	return c.closed.Load()
}

// ========== ПУЛ СОЕДИНЕНИЙ ==========
type UDPConnectionPool struct {
	connections  map[string]*UDPConnection
	mu           sync.RWMutex
	dnsCache     *DNSCache
	maxSize      int
	currentSize  int
	creationLock sync.Map // Защита от дублирования при создании
}

func NewUDPConnectionPool(maxSize int) *UDPConnectionPool {
	return &UDPConnectionPool{
		connections: make(map[string]*UDPConnection),
		dnsCache:    NewDNSCache(dnsCacheTTL),
		maxSize:     maxSize,
		currentSize: 0,
	}
}

func (p *UDPConnectionPool) Get(key string) (*UDPConnection, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	conn, exists := p.connections[key]
	if exists && !conn.IsClosed() {
		conn.lastUsed = time.Now()
		return conn, true
	}
	return nil, false
}

func (p *UDPConnectionPool) Set(key string, conn *UDPConnection) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Проверяем лимит
	if p.currentSize >= p.maxSize {
		p.cleanupOldestLocked(10)
		if p.currentSize >= p.maxSize {
			return false
		}
	}

	conn.lastUsed = time.Now()
	p.connections[key] = conn
	p.currentSize++
	return true
}

func (p *UDPConnectionPool) Delete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, exists := p.connections[key]; exists {
		conn.Close()
		delete(p.connections, key)
		p.currentSize--
	}
	p.creationLock.Delete(key)
}

func (p *UDPConnectionPool) Cleanup(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupOldLocked(maxAge)
}

func (p *UDPConnectionPool) cleanupOldLocked(maxAge time.Duration) {
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

func (p *UDPConnectionPool) cleanupOldestLocked(count int) {
	if p.currentSize <= count {
		return
	}

	type keyTime struct {
		key string
		t   time.Time
	}

	oldest := make([]keyTime, 0, count)
	for key, conn := range p.connections {
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

func (p *UDPConnectionPool) GetSize() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentSize
}

func (p *UDPConnectionPool) resolveTarget(host string, port uint16) (string, net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(host, strconv.Itoa(int(port))), ip, nil
	}
	ip, err := p.dnsCache.Resolve(host)
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), ip, nil
}

// ========== ПАРСИНГ SOCKS5 ЗАГОЛОВКА ==========
func parseSocks5HeaderFast(data []byte) (host string, port uint16, headerLen int, ok bool) {
	if len(data) < 10 || data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00 {
		return "", 0, 0, false
	}

	switch data[3] {
	case 0x01: // IPv4
		if len(data) < 10 {
			return "", 0, 0, false
		}
		host = net.IPv4(data[4], data[5], data[6], data[7]).String()
		port = binary.BigEndian.Uint16(data[8:10])
		headerLen = 10
		ok = true

	case 0x03: // Domain name
		domainLen := int(data[4])
		if len(data) < 7+domainLen {
			return "", 0, 0, false
		}
		host = string(data[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(data[5+domainLen : 5+domainLen+2])
		headerLen = 7 + domainLen
		ok = true

	case 0x04: // IPv6
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

// ========== ОТПРАВКА ОТВЕТОВ ==========
func sendUDPResponseFast(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetIP net.IP, targetPort int, data []byte) {
	var headerLen int
	if targetIP.To4() != nil {
		headerLen = 10
	} else {
		headerLen = 22
	}

	totalLen := headerLen + len(data)

	// Используем буфер из пула
	buf := getBuffer()
	defer putBuffer(buf)

	if len(buf) < totalLen {
		// Если не хватает места (редкий случай), создаем временный
		buf = make([]byte, totalLen)
	} else {
		buf = buf[:totalLen]
	}

	// Формируем заголовок
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

	// Отправляем (UDP - best effort)
	_, _ = serverConn.WriteToUDP(buf, clientAddr)
}

// ========== ОБРАБОТКА ЗАПРОСОВ ==========
func processUDPRequestSync(udpConn *UDPConnection, payload []byte) {
	if udpConn.IsClosed() {
		return
	}

	udpConn.writeMutex.Lock()
	defer udpConn.writeMutex.Unlock()

	if udpConn.IsClosed() {
		return
	}

	// Таймаут 5 секунд для защиты от зависаний
	if err := udpConn.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		errorLogger.Printf("Failed to set write deadline: %v", err)
	}
	_, err := udpConn.conn.Write(payload)
	if err != nil {
		errorLogger.Printf("UDP write error: %v", err)
	}
}

// ========== READER ГОРУТИНА ==========
func startUDPReader(udpConn *UDPConnection, serverConn *net.UDPConn, pool *UDPConnectionPool, connKey string) {
	// Гарантированная очистка
	defer func() {
		if r := recover(); r != nil {
			errorLogger.Printf("UDP reader panic recovered: %v", r)
		}
		udpConn.Close()
		pool.Delete(connKey)
	}()

	// Буфер для чтения - отдельный пул
	buf := getReaderBuffer()
	defer putReaderBuffer(buf)

	for {
		select {
		case <-udpConn.closeChan:
			return // Чистый выход
		default:
		}

		// Быстрый таймаут 50 мс для проверки closeChan
		if err := udpConn.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			errorLogger.Printf("Failed to set read deadline: %v", err)
		}

		n, err := udpConn.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Таймаут - проверяем closeChan
			}
			// Реальная ошибка - выходим
			return
		}

		if udpConn.IsClosed() {
			return
		}

		udpConn.lastUsed = time.Now()

		// Отправляем ответ клиенту
		sendUDPResponseFast(serverConn, udpConn.client, udpConn.resolvedIP, udpConn.targetAddr.Port, buf[:n])
	}
}

// ========== СОЗДАНИЕ СОЕДИНЕНИЯ ==========
func createUDPConnection(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetHost string, targetPort uint16, payload []byte, vt *VirtualTun, pool *UDPConnectionPool, connKey string) {
	// Разрешаем адрес
	targetAddr, resolvedIP, err := pool.resolveTarget(targetHost, targetPort)
	if err != nil {
		errorLogger.Printf("Failed to resolve target %s:%d: %v", targetHost, targetPort, err)
		return
	}

	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	targetUDPAddr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	// Создаем соединение через WireGuard
	udpConn, err := vt.Tnet.Dial("udp", targetAddr)
	if err != nil {
		errorLogger.Printf("Failed to dial target %s: %v", targetAddr, err)
		return
	}

	// Создаем структуру соединения
	conn := NewUDPConnection(udpConn, clientAddr, targetUDPAddr, resolvedIP)

	// Сохраняем в пул
	if !pool.Set(connKey, conn) {
		if closeErr := udpConn.Close(); closeErr != nil {
			errorLogger.Printf("Failed to close UDP connection: %v", closeErr)
		}
		errorLogger.Printf("UDP connection limit reached, dropping packet for %s", connKey)
		return
	}

	// Запускаем reader
	go startUDPReader(conn, serverConn, pool, connKey)

	// Отправляем начальный пакет
	processUDPRequestSync(conn, payload)
}

// ========== ОБРАБОТКА ПАКЕТА ==========
func handleSocks5UDPPacketSync(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, vt *VirtualTun, pool *UDPConnectionPool) {
	host, port, headerLen, ok := parseSocks5HeaderFast(data)
	if !ok {
		return
	}
	payload := data[headerLen:]

	// Ключ: один клиент -> одно соединение
	connKey := clientAddr.String()

	// Проверяем существующее соединение
	if udpConn, exists := pool.Get(connKey); exists {
		// Синхронная отправка - минимальная задержка
		processUDPRequestSync(udpConn, payload)
		return
	}

	// Блокируем создание дублирующих соединений
	if _, loaded := pool.creationLock.LoadOrStore(connKey, struct{}{}); loaded {
		return
	}

	// Создаем новое соединение (асинхронно, т.к. может быть DNS запрос)
	go func() {
		defer pool.creationLock.Delete(connKey)
		createUDPConnection(serverConn, clientAddr, host, port, payload, vt, pool, connKey)
	}()
}

// ========== ОСНОВНОЙ СЕРВЕР ==========
func StartSocks5UDPServer(bindAddress string, vt *VirtualTun) error {
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			errorLogger.Printf("Failed to close UDP listener: %v", closeErr)
		}
	}()

	// Оптимизация буферов сокета
	if err := conn.SetReadBuffer(32 * 1024); err != nil {
		errorLogger.Printf("Warning: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(32 * 1024); err != nil {
		errorLogger.Printf("Warning: failed to set write buffer: %v", err)
	}

	// Создаем пул соединений
	pool := NewUDPConnectionPool(maxUDPConnections)

	// Запускаем очистку старых соединений
	go func() {
		ticker := time.NewTicker(udpCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			pool.Cleanup(udpConnectionTimeout)
			if size := pool.GetSize(); size > maxUDPConnections/2 {
				errorLogger.Printf("UDP pool size: %d/%d", size, maxUDPConnections)
			}
		}
	}()

	// Основной цикл - СИНХРОННАЯ ОБРАБОТКА
	for {
		buf := getBuffer()

		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			putBuffer(buf)
			continue
		}

		// Синхронная обработка - минимальная задержка
		handleSocks5UDPPacketSync(conn, clientAddr, buf[:n], vt, pool)

		// Возвращаем буфер в пул
		putBuffer(buf)
	}
}
