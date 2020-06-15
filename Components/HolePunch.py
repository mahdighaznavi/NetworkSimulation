from Components.Client import Client


class Server:
    def __init__(self, ip):
        self.ip = ip
        self.link = None

    def connect(self, link):
        """
        :param link: A Hub
        """
        self.link = link

    def receive_pkt(self, pkt):
        # TODO handle received packet
        print(pkt)
        pass


def peer_to_peer(server_ip, client1, client2):
    """
    make peer-to-peer connection via UDP hole punching
    :param server_ip: ip of server used in hole punch
    :param client1: first client
    :param client2: second client
    :return:
    """
    pass
