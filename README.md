# Natter (v2)

Expose your port behind full-cone NAT to the Internet.
  
[中文文档](docs/README.md)


## Quick start

```bash
python3 natter.py
```

Or, using Docker:

```bash
docker run --net=host nattertool/natter
```

```
2023-11-01 01:00:08 [I] Natter v2.0.0-rc1
2023-11-01 01:00:08 [I] Tips: Use `--help` to see help messages
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] tcp://192.168.1.100:13483 <--Natter--> tcp://203.0.113.10:14500
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] Test mode in on.
2023-11-01 01:00:12 [I] Please check [ http://203.0.113.10:14500 ]
2023-11-01 01:00:12 [I]
2023-11-01 01:00:12 [I] LAN > 192.168.1.100:13483   [ OPEN ]
2023-11-01 01:00:12 [I] LAN > 192.168.1.100:13483   [ OPEN ]
2023-11-01 01:00:12 [I] LAN > 203.0.113.10:14500    [ OPEN ]
2023-11-01 01:00:13 [I] WAN > 203.0.113.10:14500    [ OPEN ]
2023-11-01 01:00:13 [I]
```

In the example above, `203.0.113.10` is your public IP address outside the full-cone NAT. Natter opened TCP port `203.0.113.10:14500` for testing.

Visit `http://203.0.113.10:14500` outside your LAN, you will see the web page:

```
It works!

--------
Natter
```


## Usage

```
usage: natter.py [--version] [--help] [-v] [-q] [-u] [-k <interval>]
                 [-s <address>] [-h <address>] [-e <path>] [-i <interface>]
                 [-b <port>] [-m <method>] [-t <address>] [-p <port>] [-r]

Expose your port behind full-cone NAT to the Internet.

options:
  --version, -V   show the version of Natter and exit
  --help          show this help message and exit
  -v              verbose mode, printing debug messages
  -q              exit when mapped address is changed
  -u              UDP mode
  -k <interval>   seconds between each keep-alive
  -s <address>    hostname or address to STUN server
  -h <address>    hostname or address to keep-alive server
  -e <path>       script path for notifying mapped address

bind options:
  -i <interface>  network interface name or IP to bind
  -b <port>       port number to bind

forward options:
  -m <method>     forward method, common values are 'iptables', 'nftables',
                  'socat', 'gost' and 'socket'
  -t <address>    IP address of forward target
  -p <port>       port number of forward target
  -r              keep retrying until the port of forward target is open
```


## Usage for Docker

Read [natter-docker](natter-docker) for details.


## Use cases

Expose local port 80 to the Internet, using built-in forward method:

```bash
python3 natter.py -p 80
```

Expose local port 80 to the Internet, using iptables kernel forward method (requires root permission):

```bash
sudo python3 natter.py -m iptables -p 80
```


## Dependencies

- Python 2.7 (minimum), >= 3.6 (recommended)
- No third-party modules are required.


## License

GNU General Public License v3.0
