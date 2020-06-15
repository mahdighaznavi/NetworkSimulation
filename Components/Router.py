class Router:
    def __init__(self, id):
        self.id = id
        self.interfaces = dict()

    def receive_pkt(self, pkt):
        """
        If the packet should be dropped, drop it. O.W. forward it to the proper interface
        :param pkt: received packet
        """
        # TODO handle received packet
        pass

    def connected(self, ip, is_router):
        """
        to add ip to routing list
        :param ip:
        :return:
        """
        # TODO add ip to routing list
        pass

    def config(self):
        while True:
            cmd = input().split()
            if cmd[0] == 'exit':
                return
            elif cmd[0] == 'add_interface':
                self.interfaces[cmd[1]] = Interface(cmd[1], self)
            elif cmd[0] == 'access_list':
                # TODO access-list command
                pass
            elif cmd[0] == 'nat':
                if cmd[1] == 'inside':
                    # TODO set nat inside
                    pass
                elif cmd[1] == 'outside':
                    # TODO set nat outside
                    pass
                elif cmd[1] == 'pool':
                    # TODO set a nat pool
                    pass
                elif cmd[1] == 'set':
                    # TODO set and start nat
                    pass


class Interface:
    def __init__(self, ip, router):
        """
        :param ip: the ip of the interface
        :param router: the router it is connected to
        """
        self.ip = ip
        self.link = None
        self.router = router

    def connect(self, link):
        """
        :param link: Link or Hub
        """
        self.link = link

    def connected(self, ip, is_router):
        """
        notify the router a new connection
        :param ip: other side ip
        """
        self.router.connected(ip, is_router)
        pass

    def send_pkt(self, pkt):
        if self.link:
            self.link.send(pkt)

    def receive_pkt(self, pkt):
        self.router.receive_pkt(pkt)
