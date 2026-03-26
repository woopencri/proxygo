package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
	"proxy-pool/config"
	"proxy-pool/storage"
)

type Server struct {
	storage *storage.Storage
	cfg     *config.Config
}

func New(s *storage.Storage, cfg *config.Config) *Server {
	return &Server{
		storage: s,
		cfg:     cfg,
	}
}

func (s *Server) Start() error {
	log.Printf("proxy server listening on %s", s.cfg.ProxyPort)
	return http.ListenAndServe(s.cfg.ProxyPort, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

// handleHTTP 处理普通 HTTP 请求（带自动重试）
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var tried []string
	for attempt := 0; attempt <= s.cfg.MaxRetry; attempt++ {
		p, err := s.storage.GetRandomExclude(tried)
		if err != nil {
			http.Error(w, "no available proxy", http.StatusServiceUnavailable)
			return
		}
		tried = append(tried, p.IdentityKey())

		client, err := s.buildClient(p)
		if err != nil {
			_ = s.storage.DeleteByID(p.ID)
			continue
		}

		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			continue
		}
		req.Header = r.Header.Clone()
		req.Header.Del("Proxy-Connection")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[proxy] %s via %s failed, removing", r.RequestURI, p.Address)
			_ = s.storage.DeleteByID(p.ID)
			continue
		}
		defer resp.Body.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		if resp.StatusCode == 429 {
			log.Printf("[proxy] ⚠️  429 %s via %s (protocol=%s)", r.RequestURI, p.Address, p.Protocol)
		} else {
			log.Printf("[proxy] %s via %s -> %d", r.RequestURI, p.Address, resp.StatusCode)
		}
		return
	}

	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

// handleTunnel 处理 HTTPS CONNECT 隧道（带自动重试）
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	var tried []string
	for attempt := 0; attempt <= s.cfg.MaxRetry; attempt++ {
		p, err := s.storage.GetRandomExclude(tried)
		if err != nil {
			http.Error(w, "no available proxy", http.StatusServiceUnavailable)
			return
		}
		tried = append(tried, p.IdentityKey())

		conn, err := s.dialViaProxy(p, r.Host)
		if err != nil {
			log.Printf("[tunnel] dial %s via %s failed, removing", r.Host, p.Address)
			_ = s.storage.DeleteByID(p.ID)
			continue
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			conn.Close()
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			conn.Close()
			return
		}

		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		log.Printf("[tunnel] %s via %s established", r.Host, p.Address)

		go transfer(conn, clientConn)
		go transfer(clientConn, conn)
		return
	}

	http.Error(w, "all proxies failed", http.StatusBadGateway)
}

func (s *Server) dialViaProxy(p *storage.Proxy, host string) (net.Conn, error) {
	timeout := time.Duration(s.cfg.ValidateTimeout) * time.Second
	switch p.Protocol {
	case "http":
		conn, err := net.DialTimeout("tcp", p.Address, timeout)
		if err != nil {
			return nil, err
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", host, host); err != nil {
			conn.Close()
			return nil, err
		}
		if header := proxyAuthorizationHeader(p); header != "" {
			if _, err := fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", header); err != nil {
				conn.Close()
				return nil, err
			}
		}
		if _, err := fmt.Fprintf(conn, "\r\n"); err != nil {
			conn.Close()
			return nil, err
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy connect failed: %s", resp.Status)
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	case "socks5":
		var auth *proxy.Auth
		if p.Username != "" || p.Password != "" {
			auth = &proxy.Auth{User: p.Username, Password: p.Password}
		}
		dialer, err := proxy.SOCKS5("tcp", p.Address, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", host)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
}

func (s *Server) buildClient(p *storage.Proxy) (*http.Client, error) {
	timeout := time.Duration(s.cfg.ValidateTimeout) * time.Second
	switch p.Protocol {
	case "http":
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", p.Address))
		if err != nil {
			return nil, err
		}
		if p.Username != "" || p.Password != "" {
			proxyURL.User = url.UserPassword(p.Username, p.Password)
		}
		return &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   timeout,
		}, nil
	case "socks5":
		var auth *proxy.Auth
		if p.Username != "" || p.Password != "" {
			auth = &proxy.Auth{User: p.Username, Password: p.Password}
		}
		dialer, err := proxy.SOCKS5("tcp", p.Address, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Transport: &http.Transport{Dial: dialer.Dial},
			Timeout:   timeout,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
}

func proxyAuthorizationHeader(p *storage.Proxy) string {
	if p.Username == "" && p.Password == "" {
		return ""
	}
	creds := p.Username + ":" + p.Password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}
