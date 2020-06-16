from Components.Packet import Packet
import HP


def get_dict_from_string(string):
    dest_and_dist = string.split("|")
    ret = dict()
    for s in dest_and_dist:
        tmp = s.split(",")
        ret[tmp[0]] = int(tmp[1])
    return ret


def copy_pkt(pkt):
    return Packet(pkt.sender, pkt.sender_port, pkt.receiver, pkt.receiver_port, pkt.type, pkt.ttl, pkt.mf, pkt.df,
                  pkt.fo, (pkt.body + ".")[:-1])


class Router:
    """
    table elements -> [interface ip, distance, is router?, hold down timer, neighbor number]
    neighbors elements -> [neighbor ip, validity, interface, invalid timer]
    """

    def __init__(self, identifier):
        self.id = identifier
        self.interfaces = dict()
        self.table = dict()
        self.neighbors = []
        self.ad_time = None
        self.reset_add_timer()
        self.buffer = ""

    def receive_pkt(self, interface, pkt):
        """
        If the packet should be dropped, drop it. O.W. forward it to the proper interface
        :param interface: interface message received from
        :param pkt: received packet
        """
        pkt.ttl -= 1
        if pkt.ttl == 0:
            interface = self.find_interface(pkt.sender)
            if interface is not None:
                self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, -1,
                          HP.ICMP_TTL_ENDED_CODE)
        elif pkt.type == "ad":
            if pkt.mf:
                self.buffer = self.buffer + pkt.body
                return
            if len(self.buffer) > 0:
                pkt.body = self.buffer + pkt.body
            ad_table = get_dict_from_string(pkt.body)
            self.buffer = ""
            for n in self.neighbors:
                if n.interface.ip == interface.ip:
                    n.reset_timer()
            # print(ad_table)
            # print(interface.ip)
            for ip, distance in ad_table.items():
                if self.table.__contains__(ip):
                    if self.table[ip].len > distance + 1:
                        # print("Just check" + str(self.table[ip]))
                        self.table[ip].update(distance + 1, interface)
                    elif self.table[ip].interface == interface:
                        self.table[ip].parent_change(distance + 1)
                else:
                    self.table[ip] = TableNode(interface, distance + 1)
            for ip, node in self.table.items():
                if node.interface == interface and (not ad_table.__contains__(ip)):
                    node.parent_change(HP.MAX_PATH_LEN)
                # print(ip + " " + str(self.table[ip]))
            # print()
        else:
            interface = self.find_interface(pkt.receiver)
            if interface is not None:
                self.send_pkt(interface, pkt)
            else:
                self.no_route_message(interface, pkt)

    def connected(self, interface, ip, is_router):
        """
        to add ip to routing list
        :param is_router:
        :param interface:
        :param ip:
        :return:
        """
        if is_router:
            self.neighbors.append(Neighbor(interface, ip))
        else:
            self.table[ip] = TableNode(interface, 1)

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

    @staticmethod
    def send(interface, sender_port, receiver, rcvr_port, msg_type, ttl, more_fragments, dont_fragment,
             fragmentation_offset, body):
        pkt = Packet(interface.ip, sender_port, receiver, rcvr_port, msg_type, ttl, more_fragments, dont_fragment,
                     fragmentation_offset, body)
        Router.send_pkt(interface, pkt)

    @staticmethod
    def send_pkt(interface, pkt):
        if interface.link is not None:
            if len(pkt.body) > interface.link.mtu:
                if pkt.df:
                    Router.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, 0,
                                HP.ICMP_FRAGMENTATION_NEEDED)
                else:
                    cur = 0
                    new_pkt = copy_pkt(pkt)
                    while cur < len(pkt.body):
                        new_pkt.fo = cur
                        # print(new_pkt)
                        # print(cur)
                        # print(type(interface.link.mtu))
                        new_pkt.body = new_pkt.body[cur: min(len(pkt.body), cur + interface.link.mtu)]
                        if cur + interface.link.mtu >= len(pkt.body):
                            new_pkt.mf = pkt.mf
                        else:
                            new_pkt.mf = True
                        new_pkt.df = False
                        # if pkt.body == "salamm":
                        #     print("in path: " + str(new_pkt))
                        interface.send_pkt(new_pkt)
                        new_pkt = copy_pkt(pkt)
                        cur += interface.link.mtu
            else:
                interface.send_pkt(pkt)

    def find_interface(self, ip):
        if self.table.__contains__(ip) and self.table[ip].valid:
            return self.table[ip].interface
        return None

    def next_sec(self):
        self.ad_time -= 1
        if self.ad_time == 0:
            self.reset_add_timer()
            self.send_ad()
        for ip, node in self.table.items():
            node.try_inc_hold_down()
        for n in self.neighbors:
            if n.is_valid() and n.decrease_time():
                for ip, node in self.table.items():
                    if node.interface == n.interface:
                        node.invalid()
                        node.hold_down_timer = 0
                        # print("Invalidation:" + ip + " " + str(node))

    def reset_add_timer(self):
        self.ad_time = HP.AD_TIME

    def send_ad(self):
        for n in self.neighbors:
            send_table = ""
            for ip, node in self.table.items():
                if node.valid:
                    if node.interface != n.interface:
                        send_table = self.add_to_str(send_table, ip, node.len)
                    else:
                        send_table = self.add_to_str(send_table, ip, HP.MAX_PATH_LEN)
            if len(send_table) > 0:
                send_table = send_table[1:]
            # print(n.interface.ip + " " + n.ip + " " + send_table)
            self.send(n.interface, 1, n.ip, 1, "ad", 2, False, False, 0, send_table)

    @staticmethod
    def add_to_str(send_table, destination, distance):
        send_table = send_table + "|" + str(destination) + "," + str(distance)
        return send_table

    def no_route_message(self, interface, pkt):
        interface = self.find_interface(pkt.sender)
        if interface is not None:
            self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, 0,
                      HP.ICMP_NO_ROUTE_CODE)


class Neighbor:
    def __init__(self, interface, ip):
        self.interface = interface
        self.ip = ip
        self.invalid_timer = HP.INVALID_TIMER_BASE
        self.validity = True

    def decrease_time(self):
        self.invalid_timer -= 1
        if self.invalid_timer == 0:
            self.validity = False
            return True
        return False

    def is_valid(self):
        return self.validity

    def reset_timer(self):
        self.invalid_timer = HP.INVALID_TIMER_BASE


class TableNode:
    def __init__(self, interface, path_length):
        self.interface = interface
        self.len = path_length
        self.hold_down_timer = HP.HOLD_DOWN_TIMER
        self.valid = True

    def invalid(self):
        self.len = HP.MAX_PATH_LEN
        self.valid = False

    def try_inc_hold_down(self):
        if self.hold_down_timer < HP.HOLD_DOWN_TIMER:
            self.hold_down_timer += 1
            if self.hold_down_timer == HP.HOLD_DOWN_TIMER:
                self.invalid()

    def update(self, new_len, new_interface):
        if self.hold_down_timer == HP.HOLD_DOWN_TIMER:
            self.valid = True
            self.len = min(new_len, HP.MAX_PATH_LEN)
            self.interface = new_interface

    def parent_change(self, new_len):
        not_inf = (self.len < HP.MAX_PATH_LEN)
        self.update(new_len, self.interface)
        if not_inf and self.len == HP.MAX_PATH_LEN:
            self.hold_down_timer = 0

    def __str__(self):
        return str(self.interface.ip) + " " + str(self.len) + " " + str(self.valid) + " " + str(self.hold_down_timer)


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
        self.router.connected(self, ip, is_router)
        pass

    def send_pkt(self, pkt):
        if self.link:
            self.link.send(pkt, self.ip)

    def receive_pkt(self, pkt):
        self.router.receive_pkt(self, pkt)
