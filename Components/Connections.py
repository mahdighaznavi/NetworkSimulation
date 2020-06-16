class Link:
    def __init__(self, right, left, mtu):
        """
        :param right: Interface. One side of the link
        :param left: Interface. Other side of the link
        :param mtu: Maximum Transmission Unit
        """
        self.right = right
        self.left = left
        self.is_working = True
        self.mtu = int(mtu)

    def send(self, pkt, ip):
        """
        sends a packet to the other side of the link.
        :param pkt: packet to be sent
        :param ip: the sender ip
        """
        if self.is_working:
            # if self.mtu < len(pkt.body):
            #     return
            if ip == self.right.ip:
                self.left.receive_pkt(pkt)
            else:
                self.right.receive_pkt(pkt)


class Hub:
    def __init__(self):
        self.connections = []
        self.mtu = 10000

    def connect(self, connection):
        """
        Connects a client or interface
        :param connection: client or interface
        """
        self.connections.append(connection)

    def send(self, pkt, ip):
        """
        Sends a message to all its connections except the sender itself.
        :param pkt: the packet
        :param ip: sender's ip
        """
        for c in self.connections:
            if c.ip != ip:
                c.receive_pkt(pkt)
