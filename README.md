# AF_DNS
Alternative Facts DNS. He's not lying, he's just giving you alternative DNS resolution.

Simple DNS server that will resolve some FQDNs with custom responses.

Example:

---- input.yaml ----

192.168.1.18:
 - www.google.com
 - .facebook.com

192.168.1.42:
 - .twitter.com
 
 -------------------

This configuration file tells AF_DNS to resolve www.google.com and any request for the facebook.com domain
with the IP address 192.168.1.18
And any request for twitter.com with the IP address 192.168.1.42
