import dpkt


class L4:
    def __init__(self, src_port, dst_port):
        self.src_port = src_port
        self.dst_port = dst_port

    def mqtt(self):
        # print("mqtt") # USED for TCP
        if self.src_port == 1883 or self.dst_port == 1883:
            return 1
        else:
            return 0

    def coap(self):  # USED for both TCP and UDP
        # print("coap")
        if self.src_port ==5683 or self.dst_port == 5683:
            return 1
        else:
            return 0

    def http(self): # USED for TCP
        # print("http")
        if self.src_port == 80 or self.dst_port == 80:
            return 1
        else:
            return 0

    def https(self):  # USED for TCP
        # print("https")
        if self.src_port == 443 or self.dst_port == 443:
            return 1
        else:
            return 0

    def dns(self): # USED for UDP
        # print("dns")
        if self.dst_port == 53 or self.src_port == 53:
            return 1
        else:
            return 0

    def telnet(self): # USED for TCP
        # print("telnet")
        if self.src_port == 23 or self.dst_port == 23:
            return 1
        else:
            return 0

    def smtp(self): # both of TCP and UDP
        # print("smtp")
        if self.dst_port == 25 or self.src_port == 25:
            return 1
        else:
            return 0

    def ssh(self): # USED for TCP
        # print("ssh")
        if self.dst_port == 22 or self.src_port == 22:
            return 1
        else:
            return 0

    def IRC(self): # USED for TCP
        # print("IRC")
        if self.dst_port == 21 or self.src_port == 21:
            return 1
        else:
            return 0


class L3:
    def __init__(self, packet):
        self.packet = packet

    def tcp(self):
        # print("tcp")
        if type(self.packet) == dpkt.tcp.TCP:
            return 1
        else:
            return 0

    def udp(self):
        # print("udp")
        if type(self.packet) == dpkt.udp.UDP:
            return 1
        else:
            return 0

class L2:
    def __init__(self,src_port, dst_port):
        self.src_port = src_port
        self.dst_port = dst_port

    def dhcp(self):  # USED for UDP
        if self.src_port == 67 or self.dst_port == 68:
            return 1
        else:
            return 0

class L1:
    def __init__(self, packet):
        self.packet = packet

    def LLC(self):
        if type(self.packet == dpkt.llc):
            return 1
        else:
            return 0
    def MAC(self):
        return dpkt.ethernet.Ethernet.__flags__