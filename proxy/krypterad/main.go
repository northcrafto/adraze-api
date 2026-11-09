//go:build js && wasm

// AdRaze Proxy, krypterade läget: en HTTP-klient som körs i webbläsaren (wasm) och gör TLS-handskakningen
// precis som Chrome (uTLS), över TCP-strömmar genom Wisp. Servern ser bara krypterade bytes och värdnamnet,
// men sajterna ser en vanlig Chrome i stället för curl. Byggs med ./bygg.sh till ../transport/krypterad.wasm.
//
// JS-sidan (transport/krypterad.mjs) lägger globalThis.adrazeNat = { dial(host, port, ondata, onclose) -> Promise<{send(u8), close()}> }
// och får tillbaka globalThis.adrazeTls = { fetch, read, cancel, abort }.
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	_ "golang.org/x/crypto/x509roots/fallback" // rotcertifikat (wasm har inga egna)
)

// ---------- en TCP-ström genom Wisp ----------

type wispConn struct {
	mu      sync.Mutex
	ko      [][]byte      // det som kommit men inte lästs; växer fritt, för ett återanrop från JS får aldrig blockera
	signal  chan struct{} // kapacitet 1: "det finns nytt i kön"
	rest    []byte
	stangd  chan struct{}
	once    sync.Once
	send    js.Value
	closeFn js.Value
	funcs   []js.Func
	host    string
}

func (c *wispConn) Read(p []byte) (int, error) {
	for {
		if len(c.rest) == 0 {
			c.mu.Lock()
			if len(c.ko) > 0 {
				c.rest = c.ko[0]
				c.ko[0] = nil
				c.ko = c.ko[1:]
			}
			c.mu.Unlock()
		}
		if len(c.rest) > 0 {
			n := copy(p, c.rest)
			c.rest = c.rest[n:]
			return n, nil
		}
		select {
		case <-c.signal:
		case <-c.stangd:
			c.mu.Lock()
			tom := len(c.ko) == 0
			c.mu.Unlock()
			if tom {
				return 0, io.EOF
			}
		}
	}
}

func (c *wispConn) Write(p []byte) (int, error) {
	select {
	case <-c.stangd:
		return 0, net.ErrClosed
	default:
	}
	u := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(u, p)
	c.send.Invoke(u)
	return len(p), nil
}

func (c *wispConn) markeraStangd() { c.once.Do(func() { close(c.stangd) }) }

func (c *wispConn) Close() error {
	c.markeraStangd()
	c.closeFn.Invoke()
	return nil
}

type adr string

func (a adr) Network() string                       { return "wisp" }
func (a adr) String() string                        { return string(a) }
func (c *wispConn) LocalAddr() net.Addr              { return adr("wasm") }
func (c *wispConn) RemoteAddr() net.Addr             { return adr(c.host) }
func (c *wispConn) SetDeadline(time.Time) error      { return nil }
func (c *wispConn) SetReadDeadline(time.Time) error  { return nil }
func (c *wispConn) SetWriteDeadline(time.Time) error { return nil }

// vanta väntar ut ett JS-löfte
func vanta(p js.Value) (js.Value, error) {
	res := make(chan js.Value, 1)
	fel := make(chan error, 1)
	var ok, nej js.Func
	ok = js.FuncOf(func(_ js.Value, a []js.Value) any { res <- a[0]; return nil })
	nej = js.FuncOf(func(_ js.Value, a []js.Value) any { fel <- errors.New(a[0].Call("toString").String()); return nil })
	defer ok.Release()
	defer nej.Release()
	p.Call("then", ok, nej)
	select {
	case v := <-res:
		return v, nil
	case e := <-fel:
		return js.Undefined(), e
	}
}

func ring(ctx context.Context, host string, port int) (*wispConn, error) {
	c := &wispConn{signal: make(chan struct{}, 1), stangd: make(chan struct{}), host: host + ":" + strconv.Itoa(port)}
	ondata := js.FuncOf(func(_ js.Value, a []js.Value) any {
		b := make([]byte, a[0].Get("byteLength").Int())
		js.CopyBytesToGo(b, a[0])
		c.mu.Lock()
		c.ko = append(c.ko, b)
		c.mu.Unlock()
		select {
		case c.signal <- struct{}{}:
		default:
		}
		return nil
	})
	onclose := js.FuncOf(func(_ js.Value, _ []js.Value) any { c.markeraStangd(); return nil })
	c.funcs = []js.Func{ondata, onclose}
	v, err := vanta(js.Global().Get("adrazeNat").Call("dial", host, port, ondata, onclose))
	if err != nil {
		return nil, err
	}
	c.send = v.Get("send")
	c.closeFn = v.Get("close")
	go func() {
		<-c.stangd
		time.Sleep(30 * time.Second) // sena återanrop från JS ska inte hamna i en släppt funktion
		for _, f := range c.funcs {
			f.Release()
		}
	}()
	return c, nil
}

// ---------- TLS som Chrome ----------

func ringTLS(ctx context.Context, host string, port int, alpn []string) (*utls.UConn, error) {
	c, err := ring(ctx, host, port)
	if err != nil {
		return nil, err
	}
	u := utls.UClient(c, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
	if alpn != nil {
		// Bara http/1.1 (för värdar som redan valt det): byt ALPN i Chromes hello men behåll resten
		if err := u.BuildHandshakeState(); err != nil {
			c.Close()
			return nil, err
		}
		for _, e := range u.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
			}
		}
	}
	hctx, avbryt := context.WithTimeout(ctx, 30*time.Second)
	defer avbryt()
	if err := u.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return u, nil
}

// ---------- anslutningspoolen ----------

type pool struct {
	mu     sync.Mutex
	h2     map[string]*http2.ClientConn
	ringer map[string]chan struct{} // pågående uppkoppling per värd: andra väntar in den i stället för att ringa själva
	bara1  map[string]bool
	h2t   *http2.Transport
	h1t   *http.Transport
}

var p = &pool{h2: map[string]*http2.ClientConn{}, ringer: map[string]chan struct{}{}, bara1: map[string]bool{}}

func init() {
	p.h2t = &http2.Transport{DisableCompression: true, ReadIdleTimeout: 30 * time.Second, PingTimeout: 15 * time.Second}
	p.h1t = &http.Transport{
		DisableCompression:  true,
		MaxIdleConnsPerHost: 6,
		IdleConnTimeout:     60 * time.Second,
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, ps, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(ps)
			return ringTLS(ctx, host, port, []string{"http/1.1"})
		},
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, ps, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(ps)
			return ring(ctx, host, port)
		},
	}
}

// h2Conn ger en användbar HTTP/2-anslutning till värden. Samtidiga anrop delar på en enda uppkoppling.
// ok=false betyder att värden bara kan HTTP/1.1.
func (p *pool) h2Conn(ctx context.Context, nyckel, host string, port int) (*http2.ClientConn, bool, error) {
	for {
		p.mu.Lock()
		if p.bara1[nyckel] {
			p.mu.Unlock()
			return nil, false, nil
		}
		if cc := p.h2[nyckel]; cc != nil && cc.CanTakeNewRequest() {
			p.mu.Unlock()
			return cc, true, nil
		}
		if v, finns := p.ringer[nyckel]; finns {
			p.mu.Unlock()
			select {
			case <-v:
				continue
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
		}
		klar := make(chan struct{})
		p.ringer[nyckel] = klar
		gammal := p.h2[nyckel]
		p.mu.Unlock()
		if gammal != nil {
			go gammal.Shutdown(context.Background()) // stängs när dess pågående strömmar är klara
		}
		u, err := ringTLS(ctx, host, port, nil)
		var cc *http2.ClientConn
		h1 := false
		if err == nil {
			if u.ConnectionState().NegotiatedProtocol != "h2" {
				u.Close()
				h1 = true
			} else {
				cc, err = p.h2t.NewClientConn(u)
			}
		}
		p.mu.Lock()
		delete(p.ringer, nyckel)
		if h1 {
			p.bara1[nyckel] = true
		}
		if cc != nil {
			p.h2[nyckel] = cc
		} else if !h1 {
			delete(p.h2, nyckel)
		}
		p.mu.Unlock()
		close(klar)
		if err != nil {
			return nil, false, err
		}
		return cc, !h1, nil
	}
}

func (p *pool) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return p.h1t.RoundTrip(req)
	}
	host := req.URL.Hostname()
	port := 443
	if ps := req.URL.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	}
	nyckel := host + ":" + strconv.Itoa(port)
	var senaste error
	for forsok := 0; forsok < 2; forsok++ {
		cc, h2, err := p.h2Conn(req.Context(), nyckel, host, port)
		if err != nil {
			return nil, err
		}
		if !h2 {
			return p.h1t.RoundTrip(req)
		}
		res, err := cc.RoundTrip(req)
		if err == nil {
			return res, nil
		}
		senaste = err
		// Anslutningen dog under tiden: släng den och försök en gång till (om kroppen går att skicka igen)
		p.mu.Lock()
		if p.h2[nyckel] == cc {
			delete(p.h2, nyckel)
		}
		p.mu.Unlock()
		cc.Close()
		if req.Context().Err() != nil || (req.Body != nil && req.GetBody == nil) {
			return nil, err
		}
		if req.GetBody != nil {
			req.Body, _ = req.GetBody()
		}
	}
	return nil, senaste
}

// ---------- JS-gränssnittet ----------

var (
	mu       sync.Mutex
	kroppar  = map[int]io.ReadCloser{}
	avbrott  = map[int]context.CancelFunc{}
	nastaId  = 1
	forbjudna = map[string]bool{"host": true, "connection": true, "keep-alive": true, "proxy-connection": true, "transfer-encoding": true,
		"upgrade": true, "content-length": true, "te": true, "trailer": true, "expect": true}
)

func lofte(f func() (any, error)) js.Value {
	var exek js.Func
	exek = js.FuncOf(func(_ js.Value, a []js.Value) any {
		ok, nej := a[0], a[1]
		go func() {
			v, err := f()
			if err != nil {
				nej.Invoke(js.Global().Get("Error").New(err.Error()))
			} else {
				ok.Invoke(v)
			}
		}()
		return nil
	})
	defer exek.Release()
	return js.Global().Get("Promise").New(exek)
}

type dubbelStang struct {
	io.Reader
	stang []io.Closer
}

func (d *dubbelStang) Close() error {
	for _, c := range d.stang {
		c.Close()
	}
	return nil
}

// avkoda packar upp kroppen själv (webbläsaren gör det inte åt ett svar som service workern bygger)
func avkoda(res *http.Response) (io.ReadCloser, bool, error) {
	ce := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	b := res.Body
	switch ce {
	case "", "identity":
		return b, false, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(b)
		if err != nil {
			return nil, false, err
		}
		return &dubbelStang{r, []io.Closer{r, b}}, true, nil
	case "deflate":
		// "deflate" är oftast zlib, ibland rå deflate
		br := &kikare{r: b}
		if br.arZlib() {
			r, err := zlib.NewReader(br)
			if err != nil {
				return nil, false, err
			}
			return &dubbelStang{r, []io.Closer{r, b}}, true, nil
		}
		r := flate.NewReader(br)
		return &dubbelStang{r, []io.Closer{r, b}}, true, nil
	case "br":
		return &dubbelStang{brotli.NewReader(b), []io.Closer{b}}, true, nil
	case "zstd":
		r, err := zstd.NewReader(b)
		if err != nil {
			return nil, false, err
		}
		return &dubbelStang{r, []io.Closer{zstdStang{r}, b}}, true, nil
	}
	return b, false, nil
}

type zstdStang struct{ d *zstd.Decoder }

func (z zstdStang) Close() error { z.d.Close(); return nil }

type kikare struct {
	r    io.Reader
	forst []byte
}

func (k *kikare) arZlib() bool {
	buf := make([]byte, 2)
	n, _ := io.ReadFull(k.r, buf)
	k.forst = buf[:n]
	return n == 2 && buf[0]&0x0f == 8 && (int(buf[0])<<8|int(buf[1]))%31 == 0
}
func (k *kikare) Read(p []byte) (int, error) {
	if len(k.forst) > 0 {
		n := copy(p, k.forst)
		k.forst = k.forst[n:]
		return n, nil
	}
	return k.r.Read(p)
}

// fetch(url, method, headers [[k, v]...], body Uint8Array|null, reqId) -> {status, statusText, headers, body: id}
func jsFetch(_ js.Value, a []js.Value) any {
	adress, metod, hv, kv, rid := a[0].String(), a[1].String(), a[2], a[3], a[4].Int()
	var kropp []byte
	if kv.Truthy() {
		kropp = make([]byte, kv.Get("byteLength").Int())
		js.CopyBytesToGo(kropp, kv)
	}
	huvuden := [][2]string{}
	for i := 0; i < hv.Length(); i++ {
		huvuden = append(huvuden, [2]string{hv.Index(i).Index(0).String(), hv.Index(i).Index(1).String()})
	}
	return lofte(func() (any, error) {
		u, err := url.Parse(adress)
		if err != nil {
			return nil, err
		}
		ctx, avbryt := context.WithCancel(context.Background())
		mu.Lock()
		avbrott[rid] = avbryt
		mu.Unlock()
		var body io.Reader
		if len(kropp) > 0 {
			body = bytes.NewReader(kropp)
		}
		req, err := http.NewRequestWithContext(ctx, metod, u.String(), body)
		if err != nil {
			avbryt()
			return nil, err
		}
		if len(kropp) > 0 {
			k := kropp
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(k)), nil }
		}
		for _, h := range huvuden {
			n := strings.ToLower(h[0])
			if forbjudna[n] || strings.HasPrefix(n, ":") {
				continue
			}
			req.Header.Add(h[0], h[1])
		}
		vakt := time.AfterFunc(45*time.Second, avbryt) // inga svarshuvuden på 45 s: ge upp
		res, err := p.RoundTrip(req)
		vakt.Stop()
		if err != nil {
			mu.Lock()
			delete(avbrott, rid)
			mu.Unlock()
			avbryt()
			return nil, err
		}
		rc, avkodad, err := avkoda(res)
		if err != nil {
			res.Body.Close()
			avbryt()
			return nil, err
		}
		ut := js.Global().Get("Array").New()
		for k, vs := range res.Header {
			n := strings.ToLower(k)
			if avkodad && (n == "content-encoding" || n == "content-length") {
				continue
			}
			if n == "transfer-encoding" || n == "connection" || n == "keep-alive" {
				continue
			}
			for _, v := range vs {
				ut.Call("push", js.ValueOf([]any{n, v}))
			}
		}
		mu.Lock()
		id := nastaId
		nastaId++
		kroppar[id] = rc
		mu.Unlock()
		o := js.Global().Get("Object").New()
		o.Set("status", res.StatusCode)
		o.Set("statusText", strings.TrimSpace(strings.TrimPrefix(res.Status, strconv.Itoa(res.StatusCode))))
		o.Set("headers", ut)
		o.Set("body", id)
		o.Set("protokoll", res.Proto)
		return o, nil
	})
}

// read(id) -> Uint8Array | null (slut)
func jsRead(_ js.Value, a []js.Value) any {
	id := a[0].Int()
	return lofte(func() (any, error) {
		mu.Lock()
		rc := kroppar[id]
		mu.Unlock()
		if rc == nil {
			return js.Null(), nil
		}
		buf := make([]byte, 64<<10)
		n, err := rc.Read(buf)
		if n > 0 {
			u := js.Global().Get("Uint8Array").New(n)
			js.CopyBytesToJS(u, buf[:n])
			return u, nil
		}
		if err == nil {
			// tom läsning: försök igen nästa gång
			return js.Global().Get("Uint8Array").New(0), nil
		}
		rc.Close()
		mu.Lock()
		delete(kroppar, id)
		mu.Unlock()
		if err == io.EOF {
			return js.Null(), nil
		}
		return nil, err
	})
}

func jsCancel(_ js.Value, a []js.Value) any {
	id := a[0].Int()
	mu.Lock()
	rc := kroppar[id]
	delete(kroppar, id)
	mu.Unlock()
	if rc != nil {
		go rc.Close()
	}
	return nil
}

// abort(reqId): avbryt förfrågan och allt den läser (anropas också när svaret är klart, för att städa)
func jsAbort(_ js.Value, a []js.Value) any {
	rid := a[0].Int()
	mu.Lock()
	f := avbrott[rid]
	delete(avbrott, rid)
	mu.Unlock()
	if f != nil {
		f()
	}
	return nil
}

func main() {
	o := js.Global().Get("Object").New()
	o.Set("fetch", js.FuncOf(jsFetch))
	o.Set("read", js.FuncOf(jsRead))
	o.Set("cancel", js.FuncOf(jsCancel))
	o.Set("abort", js.FuncOf(jsAbort))
	js.Global().Set("adrazeTls", o)
	if k := js.Global().Get("adrazeTlsKlar"); k.Type() == js.TypeFunction {
		k.Invoke()
	}
	select {}
}
