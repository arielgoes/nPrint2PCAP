# nPrint2PCAP

This tool aims to resolve a segmentation fault behavior generated by nPrint (present until version 1.2.1) when nPrint files are converted back to PCAP.


**Requirements**
- [nPrint 1.2.1](https://github.com/nprint/nprint/releases/tag/v1.2.1) (at least)
- Scapy (tested on Scapy 2.5)
- Python 3 (tested on Python 3.11.7)
- Pandas (tested on Pandas 2.1.4)

This error may (or may not) occur with different nprint files.

For instance, it does happens with [`port80.pcap`](https://github.com/arielgoes/nprint_to_pcap/tree/main/examples/port80.pcap) file if we try to rebuild it into a PCAP file, but it does not happen to [`port443.pcap`](https://github.com/arielgoes/nprint_to_pcap/blob/main/examples/port443.pcap).

We assume all nPrint files are being generated as follows:
```
nprint -F -1 -P <filename>.pcap -i -u -t -4 -6 -p 0 -O 4 -W <filename>.npt -S
```



