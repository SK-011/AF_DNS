# AF_DNS
Alternative Facts DNS. He's not lying, he's just giving you alternative DNS resolutions.

Simple DNS server that will resolve some FQDNs with custom responses.
It handle A, SRV, MX, and SPF records.

Example:

```
---- config.yaml ----

A:
        www.facebook.com: "127.0.0.1"
        google.fr: "127.0.0.1"

SRV:
        any: "127.0.0.1"

MX:
        google.com: "127.0.0.1"

SPF:
        any: "v=spf1 +all"
 
 ------- END -------
```
This configuration describe how to handle each kind of DNS query.

  A queries:
    If the client ask for "www.facebook.com" of any domain name belonging to "google.fr", AF_DNS will reply with "127.0.0.1"
    
  SRV queries:
    For any SRV request, AF_DNS will reply with "127.0.0.1"

  MX queries:
    MX queries for "google.com" will receive "127.0.0.1" as a response

  SPF queries:
    Any SPF query will receive "v=spf1 +all"
    Wich means "I don't really give a fuck about SPF, leave me alone"
    So any MX can send/receive mail on the behalf of the domain
