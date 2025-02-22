from scapy.all import sniff
sniff(iface="enp0s3", count=5, prn=lambda x: x.summary())
