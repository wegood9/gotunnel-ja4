# GoTunnel-JA4

## Overview

GoTunnel-JA4 is a lightweight TCP tunneling application that filters incoming connections based on JA4 TLS fingerprints. It provides a security layer by only allowing connections with approved TLS client fingerprints to reach upstream target servers, effectively functioning as a simple TLS firewall.

## Usage
GoTunnel-JA4 can be configured through command-line flags and environment variables:

|Parameter|Flag|Default|Description|
|---|---|---|---|
|Listen Port|--listen, -l|:9000|Local port to listen on|
|Target Address|--target, -t|example.com:443|Upstream target address|
|Timeout|--timeout, -o|10s|Connection timeout|
|JA4 Allowlist|--allow-ja4|none|Comma-separated list of allowed fingerprints|

Additionally, the ALLOW_JA4 environment variable can be used to specify allowed fingerprints.

## Key Features
* Log JA4 fingerprints based on their ClientHello messages.
* Block unapproved TLS client fingerprints.
* Non-TLS traffic is unfiltered.
* Hide your TLS/HTTPS server from active probing.

Check the straightforward source code for further details.
