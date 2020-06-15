from Components.Packet import Packet


class Client:
    def __init__(self, ip):
        self.ip = ip
        self.link = None

    def connect(self, link):
        """
        :param link: A Hub
        """
        self.link = link

    def receive_pkt(self, pkt):
        """
        Show received packet
        :param pkt: received Packet
        """
        if pkt.type == 'msg':
            if pkt.receiver == self.ip:
                print(self.ip + ": msg from " + pkt.sender + " " + pkt.body)

    def send_msg(self, msg, sndr_port, rcvr, rcvr_port, ttl, df):
        """
        Sends a packet containing a message to another client
        :param msg: the message
        :param sndr_port: sender port
        :param rcvr: receiver ip
        :param rcvr_port: receiver port
        :param ttl: time-to-live
        """
        pkt = Packet(self.ip, sndr_port, rcvr, rcvr_port, 'msg', ttl, False, df, 0, msg)
        if self.link:
            self.link.send(pkt, self.ip)

    def trace_rout(self, ip):
        """
        trace rout to ip
        :param ip: destination
        """
        # TODO
        pass
