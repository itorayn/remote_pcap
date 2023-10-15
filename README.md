# remote_pcap

Утилита для удобного удаленного захвата трафика и отображения его в одном из анализаторов (wireshark, sngrep).

## install
```
pip3 install .
```


## usage
```
usage: remote_pcap [-h] -i REMOTE_IFACE -u USERNAME (-p PASSWORD | -k) [-a {wireshark,sngrep}] remote

Videos to images

positional arguments:
  remote                Capture in host address

options:
  -h, --help            show this help message and exit
  -i REMOTE_IFACE, --interface REMOTE_IFACE
                        Capture in interface
  -u USERNAME, --username USERNAME
                        Username for login
  -p PASSWORD, --password PASSWORD
                        Password for login
  -k, --use-key         Use public key
  -a {wireshark,sngrep}, --analyzer {wireshark,sngrep}
                        Packet analyzer
```


## Пример запуска
```
remote_pcap -i lo -u user -k -a sngrep 127.0.0.1:5022
```
