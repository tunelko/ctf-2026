package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"inet.af/tcpproxy"
)

const (
	reqTimeout = 20 * time.Second
	tcpDialTimeout = 5 * time.Second
	backendWriteTimeout = 5 * time.Second
	backendReadTimeout = 10 * time.Second
)

var (
	cacheMu sync.RWMutex
	cache   = make(map[string][]byte)
)

func main() {
	listenAddr := getenv("LISTEN_ADDR", "localhost:3001")
	backendAddr := getenv("DOWNSTREAM_ADDR", "localhost:3002")

	log.SetPrefix("[proxy] ")

	var p tcpproxy.Proxy
	p.AddRoute(listenAddr, &ProxyHandler{
		backendAddr: backendAddr,
	})

	log.Println("listening on", listenAddr)
	log.Fatal(p.Run())
}

type ProxyHandler struct {
	backendAddr string
}

func (h *ProxyHandler) HandleConn(client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)

	for {
		client.SetReadDeadline(time.Now().Add(reqTimeout))

		req, err := ReadRequestHeaders(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				log.Println(err)
				client.Write(respError("400 Bad Request", "bad request"))
	    }
			return
		}

		log.Printf("REQUEST: %s %s cl=%d", req.Method, req.Path, req.ContentLen)

		cacheable := isCacheable(req)
		cacheKey := req.CacheKey()

		if cacheable {
			cacheMu.RLock()
			cached, exists := cache[cacheKey]
			cacheMu.RUnlock()

			if exists {
				log.Println("cache hit:", cacheKey)

				_, writeErr := client.Write(AddCacheHeaders(cached, cacheKey, true))
				if writeErr != nil {
					log.Printf("failed to write cached response: %v", writeErr)
					return
				}

				continue
			}
		}

		body, err := ReadRequestBody(reader, req.ContentLen)
		if err != nil {
			log.Printf("failed to read request body: %v", err)
			client.Write(respError("400 Bad Request", "bad request body"))
			return
		}

		rawReq := req.Raw(body)

		resp := h.HandleReq(rawReq, cacheable, cacheKey)

		_, err = client.Write(resp)
		if err != nil {
			log.Printf("failed to write to client: %v", err)
			return
		}
	}
}

func (h *ProxyHandler) HandleReq(rawReq []byte, cacheable bool, cacheKey string) []byte {
	backend, err := net.DialTimeout("tcp", h.backendAddr, tcpDialTimeout)
	if err != nil {
		log.Println("backend dial failed:", err)
		return respError("502 Bad Gateway", "backend unavailable")
	}
	defer backend.Close()

	backend.SetWriteDeadline(time.Now().Add(backendWriteTimeout))
	if _, err := backend.Write(rawReq); err != nil {
		log.Println("backend write failed:", err)
		return respError("502 Bad Gateway", "backend write error")
	}

	backend.SetReadDeadline(time.Now().Add(backendReadTimeout))

	resp, err := ReadResponse(backend)
	if err != nil {
		log.Println("backend read failed:", err)
		return respError("502 Bad Gateway", "backend read error")
	}

	respBytes := resp.Bytes()

	if cacheable && resp.Status == 200 {
		cacheMu.Lock()
		cache[cacheKey] = respBytes
		cacheMu.Unlock()
		log.Println("cached:", cacheKey)

		return AddCacheHeaders(respBytes, cacheKey, false)
	} else {
		return respBytes
	}
}

/* ---------------- helpers ---------------- */

func isCacheable(req *Request) bool {
	if req.Method != "GET" {
		return false
	}

	return strings.HasPrefix(req.Path, "/blogs/")
}

func respError(status string, body string) []byte {
	resp := fmt.Sprintf(
		"HTTP/1.1 %s\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		status, len(body), body,
	)

	return []byte(resp)
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
