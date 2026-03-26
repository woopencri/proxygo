package fetcher

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"proxy-pool/storage"
)

// 代理来源定义
type Source struct {
	URL      string
	Protocol string // http 或 socks5
}

// 内置多个免费代理来源
var defaultSources = []Source{
	{"https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt", "http"},
	{"https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/socks5.txt", "socks5"},
	{"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt", ""},
}

type Fetcher struct {
	sources []Source
	client  *http.Client
}

func New(httpURL, socks5URL string) *Fetcher {
	sources := make([]Source, 0, len(defaultSources))
	if strings.TrimSpace(httpURL) != "" {
		sources = append(sources, Source{URL: strings.TrimSpace(httpURL), Protocol: "http"})
	} else {
		sources = append(sources, defaultSources[0])
	}
	if strings.TrimSpace(socks5URL) != "" {
		sources = append(sources, Source{URL: strings.TrimSpace(socks5URL), Protocol: "socks5"})
	} else {
		sources = append(sources, defaultSources[1])
	}
	if len(defaultSources) > 2 {
		sources = append(sources, defaultSources[2:]...)
	}

	return &Fetcher{
		sources: sources,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Fetch 从所有来源并发抓取代理
func (f *Fetcher) Fetch() ([]storage.Proxy, error) {
	type result struct {
		proxies []storage.Proxy
		source  Source
		err     error
	}

	ch := make(chan result, len(f.sources))
	for _, src := range f.sources {
		go func(s Source) {
			proxies, err := f.fetchFromSource(s.URL, s.Protocol)
			ch <- result{proxies: proxies, source: s, err: err}
		}(src)
	}

	var all []storage.Proxy
	seen := make(map[string]bool)
	for range f.sources {
		r := <-ch
		if r.err != nil {
			log.Printf("fetch %s error: %v", r.source.URL, r.err)
			continue
		}
		var deduped []storage.Proxy
		for _, p := range r.proxies {
			key := p.IdentityKey()
			if !seen[key] {
				seen[key] = true
				deduped = append(deduped, p)
			}
		}
		log.Printf("fetched %d %s proxies from %s", len(deduped), r.source.Protocol, r.source.URL)
		all = append(all, deduped...)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no proxies fetched")
	}
	log.Printf("total fetched: %d proxies (deduped)", len(all))
	return all, nil
}

func (f *Fetcher) fetchFromSource(source, protocol string) ([]storage.Proxy, error) {
	reader, closeFn, err := f.openSource(source)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	return parseProxyList(reader, protocol)
}

func (f *Fetcher) openSource(source string) (io.Reader, func(), error) {
	source = strings.TrimSpace(source)
	switch {
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		resp, err := f.client.Get(source)
		if err != nil {
			return nil, nil, fmt.Errorf("get %s: %w", source, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, source)
		}
		return resp.Body, func() { _ = resp.Body.Close() }, nil
	case strings.HasPrefix(source, "file://"):
		path := strings.TrimPrefix(source, "file://")
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s: %w", path, err)
		}
		return file, func() { _ = file.Close() }, nil
	default:
		file, err := os.Open(source)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s: %w", source, err)
		}
		return file, func() { _ = file.Close() }, nil
	}
}

func parseProxyList(r io.Reader, protocol string) ([]storage.Proxy, error) {
	var proxies []storage.Proxy
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		p, ok := parseProxyLine(line, protocol)
		if !ok {
			continue
		}
		proxies = append(proxies, p)
	}
	return proxies, scanner.Err()
}

func parseProxyLine(line, defaultProtocol string) (storage.Proxy, bool) {
	addr := line
	proto := strings.ToLower(strings.TrimSpace(defaultProtocol))
	if idx := strings.Index(line, "://"); idx != -1 {
		proto = strings.ToLower(strings.TrimSpace(line[:idx]))
		addr = strings.TrimSpace(line[idx+3:])
	}
	if proto == "socks4" {
		proto = "socks5"
	}

	parts := strings.Split(addr, ":")
	switch len(parts) {
	case 2:
		return storage.Proxy{
			Address:  parts[0] + ":" + parts[1],
			Protocol: proto,
		}, true
	case 4:
		return storage.Proxy{
			Address:  parts[0] + ":" + parts[1],
			Protocol: proto,
			Username: parts[2],
			Password: parts[3],
		}, true
	default:
		return storage.Proxy{}, false
	}
}
