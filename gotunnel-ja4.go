package main

import (
    "bufio"
    "io"
    "log"
    "net"
    "os"
    "strings"
    "time"

    ja4fp "github.com/wi1dcard/fingerproxy/pkg/ja4"
    pflag "github.com/spf13/pflag"
)

var (
    listenAddr = pflag.StringP("listen", "l", ":9000", "Local listen address (ip:port)")
    targetAddr = pflag.StringP("target", "t", "example.com:443", "Upstream address (ip:port)")
    timeout    = pflag.DurationP("timeout", "o", 10*time.Second, "Dial/idle timeout")
    allowJA4Flag = pflag.StringSlice(
        "allow-ja4", 
        []string{}, 
        "Comma-separated JA4 fingerprints to allow, e.g. fp1,fp2,fp3",
    )
)

func main() {
    pflag.Parse()

    // Read from ENV: ALLOW_JA4="fp1,fp2,fp3"
    envList := os.Getenv("ALLOW_JA4")
    var allowJA4Env []string
    if envList != "" {
        allowJA4Env = strings.Split(envList, ",")
    }

    // Merge into map
    allowed := make(map[string]struct{}, len(*allowJA4Flag)+len(allowJA4Env))
    for _, fp := range *allowJA4Flag {
        allowed[fp] = struct{}{}
    }
    for _, fp := range allowJA4Env {
        allowed[fp] = struct{}{}
    }

    ln, err := net.Listen("tcp", *listenAddr)
    if err != nil {
        log.Fatalf("listen: %v", err)
    }
    log.Printf("forwarding %s → %s", *listenAddr, *targetAddr)

    for {
        client, err := ln.Accept()
        if err != nil {
            log.Printf("accept: %v", err)
            continue
        }
        go handleConn(client, allowed)
    }
}

func handleConn(client net.Conn, allowed map[string]struct{}) {
    defer client.Close()

    upstream, err := net.DialTimeout("tcp", *targetAddr, *timeout)
    if err != nil {
        log.Printf("dial upstream: %v", err)
        return
    }
    defer upstream.Close()

    br := bufio.NewReader(client)
    header, err := br.Peek(5)
    if err == nil && header[0] == 0x16 { // TLS Record
        recLen := int(header[3])<<8 | int(header[4])
        chBytes, _ := br.Peek(5 + recLen)
        if len(chBytes) >= 6 && chBytes[5] == 0x01 { // ClientHello
            var j ja4fp.JA4Fingerprint
            if err := j.UnmarshalBytes(chBytes, 't'); err == nil {
                fp := j.String()
                log.Printf("[JA4] %s", fp)
                if _, ok := allowed[fp]; !ok {
                    log.Printf("blocked TLS JA4: %s", fp)
                    return // drop connection if not allowed
                }
            } else {
                log.Printf("JA4 parse error: %v", err)
                return
            }
        }
    }

    go io.Copy(upstream, br)
    io.Copy(client, upstream)
}
