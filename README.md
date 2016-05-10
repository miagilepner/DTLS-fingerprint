# DTLS-fingerprint

Uses bro to return a fingerprint of DTLS traffic in the file dtls.log.

```
bro -C -b -r trace.pcap dtlsfingerprint.bro
bro -C -b -i eth0 dtlsfingerprint.bro
```
