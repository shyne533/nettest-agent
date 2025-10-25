package main

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "os/exec"
    "runtime"
    "strconv"
    "strings"
    "time"
)

type TLSInfo struct {
    Ok          bool   `json:"ok"`
    HandshakeMs int64  `json:"ms"`
    Protocol    string `json:"protocol,omitempty"`
    CipherSuite string `json:"cipherSuite,omitempty"`
    Error       string `json:"error,omitempty"`
}

type ICMPInfo struct {
    Attempted bool   `json:"attempted"`
    Reachable bool   `json:"reachable"`
    AvgRttMs  int64  `json:"avgRttMs,omitempty"`
    Method    string `json:"method,omitempty"`
    Error     string `json:"error,omitempty"`
}

type TcpInfo struct {
    Ok    bool   `json:"ok"`
    Ms    int64  `json:"ms"`
    Error string `json:"error,omitempty"`
}

type Resp struct {
    Ok          bool      `json:"ok"`
    Host        string    `json:"host"`
    Port        int       `json:"port"`
    TimeoutMs   int       `json:"timeoutMs"`
    StartedAt   string    `json:"startedAt"`
    FinishedAt  string    `json:"finishedAt"`
    ResolveMs   int64     `json:"resolveMs"`
    ResolvedIPs []string  `json:"resolvedIPs,omitempty"`
    TcpConnect  TcpInfo   `json:"tcpConnect"`
    TLS         *TLSInfo  `json:"tls,omitempty"`
    ICMP        *ICMPInfo `json:"icmp,omitempty"`
    Error       string    `json:"error,omitempty"`
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", handleRoot)
    mux.HandleFunc("/api/test", handleTest)

    srv := &http.Server{
        Addr:              "127.0.0.1:3035",
        Handler:           withCORS(mux),
        ReadHeaderTimeout: 5 * time.Second,
    }

    fmt.Println("NetTest Agent on http://127.0.0.1:3035")
    if err := srv.ListenAndServe(); err != nil {
        panic(err)
    }
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, http.StatusOK, map[string]any{
        "ok":      true,
        "agent":   "nettest-go",
        "version": "1.0",
    })
}

func handleTest(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    host := strings.TrimSpace(q.Get("host"))
    portS := strings.TrimSpace(q.Get("port"))
    timeoutS := strings.TrimSpace(q.Get("timeoutMs"))
    doTLS := strings.EqualFold(q.Get("tls"), "1") || strings.EqualFold(q.Get("tls"), "true")
    doICMP := strings.EqualFold(q.Get("icmp"), "1") || strings.EqualFold(q.Get("icmp"), "true")

    if host == "" || portS == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Missing host or port"})
        return
    }
    port, err := strconv.Atoi(portS)
    if err != nil || port < 1 || port > 65535 {
        writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid port"})
        return
    }
    timeout := 3000
    if timeoutS != "" {
        if t, e := strconv.Atoi(timeoutS); e == nil && t >= 200 && t <= 60000 {
            timeout = t
        }
    }

    resp := &Resp{
        Host:      host,
        Port:      port,
        TimeoutMs: timeout,
        StartedAt: time.Now().Format(time.RFC3339),
    }

    // DNS resolve
    resStart := time.Now()
    ips, resErr := net.LookupIP(host)
    resp.ResolveMs = msSince(resStart)
    if resErr == nil {
        for _, ip := range ips {
            resp.ResolvedIPs = append(resp.ResolvedIPs, ip.String())
        }
    }

    // TCP connect with timeout
    ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Millisecond)
    defer cancel()
    dialer := &net.Dialer{}
    connStart := time.Now()
    raw, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
    resp.TcpConnect.Ms = msSince(connStart)
    if err != nil {
        resp.TcpConnect.Ok = false
        resp.TcpConnect.Error = err.Error()
        resp.Ok = false
        resp.Error = resp.TcpConnect.Error
        // ICMP for diagnostics
        if doICMP {
            info := icmpProbe(host, timeout)
            resp.ICMP = &info
        }
        resp.FinishedAt = time.Now().Format(time.RFC3339)
        writeJSON(w, http.StatusOK, resp)
        return
    }
    resp.TcpConnect.Ok = true
    defer raw.Close()

    // Optional TLS handshake
    if doTLS {
        tlsStart := time.Now()
        cfg := &tls.Config{
            ServerName:         host, // SNI
            InsecureSkipVerify: true, // we only measure handshake; not verifying here
        }
        tconn := tls.Client(raw, cfg)
        err := tconn.Handshake()
        info := &TLSInfo{HandshakeMs: msSince(tlsStart)}
        if err != nil {
            info.Ok = false
            info.Error = err.Error()
        } else {
            st := tconn.ConnectionState()
            info.Ok = true
            info.Protocol = tlsVersionToStr(st.Version)
            info.CipherSuite = cipherToStr(st.CipherSuite)
        }
        resp.TLS = info
    }

    // Optional ICMP
    if doICMP {
        info := icmpProbe(host, timeout)
        resp.ICMP = &info
    }

    resp.Ok = true
    resp.FinishedAt = time.Now().Format(time.RFC3339)
    writeJSON(w, http.StatusOK, resp)
}

func icmpProbe(host string, timeoutMs int) ICMPInfo {
    info := ICMPInfo{Attempted: true, Method: "ping"}
    var args []string
    if runtime.GOOS == "windows" {
        args = []string{"-n", "1", "-w", strconv.Itoa(timeoutMs), host}
    } else {
        sec := timeoutMs / 1000
        if sec < 1 {
            sec = 1
        }
        args = []string{"-c", "1", "-W", strconv.Itoa(sec), host}
    }
    out, err := exec.Command("ping", args...).CombinedOutput()
    txt := strings.ToLower(string(out))
    if err != nil {
        info.Reachable = false
        info.Error = err.Error()
        return info
    }
    if strings.Contains(txt, "ttl=") || strings.Contains(txt, "bytes from") || strings.Contains(txt, "reply from") {
        info.Reachable = true
    }
    if m := find(txt, "average = ", "ms"); m != "" {
        if v, e := strconv.Atoi(m); e == nil {
            info.AvgRttMs = int64(v)
        }
    } else if m := find(txt, "time=", " ms"); m != "" {
        if f, e := strconv.ParseFloat(strings.Trim(m, "<= "), 64); e == nil {
            info.AvgRttMs = int64(f + 0.5)
        }
    }
    return info
}

func find(s, start, end string) string {
    i := strings.Index(s, start)
    if i < 0 {
        return ""
    }
    t := s[i+len(start):]
    j := strings.Index(t, end)
    if j < 0 {
        return ""
    }
    return strings.TrimSpace(t[:j])
}

func tlsVersionToStr(v uint16) string {
    switch v {
    case tls.VersionTLS10:
        return "TLS1.0"
    case tls.VersionTLS11:
        return "TLS1.1"
    case tls.VersionTLS12:
        return "TLS1.2"
    case tls.VersionTLS13:
        return "TLS1.3"
    default:
        return fmt.Sprintf("0x%x", v)
    }
}
func cipherToStr(c uint16) string { return fmt.Sprintf("0x%x", c) }

func withCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Keep * for dev; restrict to your origin in production.
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func writeJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("Cache-Control", "no-store")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(v)
}

func msSince(t0 time.Time) int64 { return int64(time.Since(t0) / time.Millisecond) }
