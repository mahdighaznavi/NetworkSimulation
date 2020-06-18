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
        self.ACLs = dict()
        self.pools = dict()
        self.nat_inside = None
        self.nat_outside = None
        self.nat = None
        self.before_hub = dict()

    def receive_pkt(self, interface, pkt):
        """
        If the packet should be dropped, drop it. O.W. forward it to the proper interface
        :param interface: interface message received from
        :param pkt: received packet
        """
        # print(pkt)
        if self.before_hub.__contains__(pkt.sender) and self.before_hub.__contains__(pkt.receiver) and self.before_hub[
            pkt.sender] == self.before_hub[pkt.receiver]:
            return
        pkt.ttl -= 1
        if pkt.ttl == 0:
            interface = self.find_interface(pkt.sender)
            if interface is not None:
                self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, -1,
                          HP.ICMP_TTL_ENDED_CODE, False)
        elif pkt.type == "ad":
            if pkt.mf:
                self.buffer = self.buffer + pkt.body
                return
            if len(self.buffer) > 0:
                pkt.body = self.buffer + pkt.body
            if len(pkt.body) > 0:
                ad_table = get_dict_from_string(pkt.body)
            else:
                ad_table = dict()
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
                    elif self.table[ip].interface.ip == interface.ip:
                        self.table[ip].parent_change(distance + 1)
                else:
                    self.table[ip] = TableNode(interface, distance + 1)
            for ip, node in self.table.items():
                if node.interface.ip == interface.ip and (not ad_table.__contains__(ip)):
                    node.parent_change(HP.MAX_PATH_LEN)
                # print(ip + " " + str(self.table[ip]))
            # print()
        else:
            # print("Hora")
            # if self.nat is not None:
            #     print(self.nat_outside.ip)
            #     print(interface.ip)
            #     print(self.nat.pool_range)
            #     t.receiver)
            if self.nat is not None and self.nat_outside.ip == interface.ip:
                if ip_to_int(
                        self.nat.pool_range[0]) <= ip_to_int(pkt.receiver) <= ip_to_int(self.nat.pool_range[1]):
                    # print("EEEEE")
                    self.nat.receive_pkt(interface, pkt)
                    return
                elif ip_to_int(self.nat.acl[0]) <= ip_to_int(pkt.receiver) <= ip_to_int(self.nat.acl[1]):
                    self.nat_dropped_message(interface, pkt)
                    return
            interface_ = self.find_interface(pkt.receiver)
            if interface_ is not None:
                self.send_pkt(interface_, pkt, (
                        self.nat is not None and interface_.ip == self.nat_outside.ip and interface.ip == self.nat_inside.ip))
            else:
                self.no_route_message(interface, pkt)

    def nat_subst_cnt(self, interface, pkt):
        interface_ = self.find_interface(pkt.receiver)
        if interface_ is not None:
            self.send_pkt(interface_, pkt, False)
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
            self.before_hub[ip] = interface.ip

    def config(self):
        while True:
            cmd = input().split()
            if cmd[0] == 'exit':
                return
            elif cmd[0] == 'add_interface':
                self.interfaces[cmd[1]] = Interface(cmd[1], self)
            elif cmd[0] == 'access_list':
                if not self.ACLs.__contains__(cmd[1]):
                    self.ACLs[cmd[1]] = [cmd[3], cmd[4]]
            elif cmd[0] == 'nat':
                if cmd[1] == 'inside':
                    self.nat_inside = self.interfaces[cmd[2]]
                    # self.interfaces[cmd[2]] = self.nat_inside
                    pass
                elif cmd[1] == 'outside':
                    self.nat_outside = self.interfaces[cmd[2]]
                    pass
                elif cmd[1] == 'pool':
                    if not self.pools.__contains__(cmd[2]):
                        self.pools[cmd[2]] = [cmd[3], cmd[4]]
                elif cmd[1] == 'set':
                    is_restricted = ((len(cmd) > 4 and cmd[4] == "res") or (len(cmd) > 5 and cmd[5] == "res"))
                    has_port_forwarding = (
                            (len(cmd) > 4 and cmd[4] == "overload") or (len(cmd) > 5 and cmd[5] == "overload"))
                    self.nat = Nat(self, self.ACLs[cmd[2]], self.pools[cmd[3]], has_port_forwarding, is_restricted,
                                   self.nat_inside, self.nat_outside)

    def send(self, interface, sender_port, receiver, rcvr_port, msg_type, ttl, more_fragments, dont_fragment,
             fragmentation_offset, body, inside_nat):
        pkt = Packet(interface.ip, sender_port, receiver, rcvr_port, msg_type, ttl, more_fragments, dont_fragment,
                     fragmentation_offset, body)
        self.send_pkt(interface, pkt, inside_nat)

    def send_pkt(self, interface, pkt, inside_nat):
        # print(pkt)
        if inside_nat and (self.nat is not None) and interface.ip == self.nat_outside.ip:
            self.nat.send_pkt(pkt)
        elif interface.link is not None:
            if len(pkt.body) > interface.link.mtu:
                if pkt.df:
                    self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, 0,
                              HP.ICMP_FRAGMENTATION_NEEDED, False)
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
        min_dis = 17
        ret = None
        for ip_, node in self.table.items():
            if node.is_valid() and ip_ == ip and min_dis > node.len:
                min_dis = node.len
                ret = node.interface
            if ":" in ip_:
                tmp = ip_.split(":")
                assert len(tmp) == 2
                if ip_to_int(tmp[0]) <= ip_to_int(ip) <= ip_to_int(tmp[1]) and min_dis > node.len:
                    min_dis = node.len
                    ret = node.interface
        return ret

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
                    if node.interface.ip == n.interface.ip:
                        node.invalid()
                        node.hold_down_timer = 0
                        # print("Invalidation:" + ip + " " + str(node))
        if self.nat:
            self.nat.next_sec()

    def reset_add_timer(self):
        self.ad_time = HP.AD_TIME

    def send_ad(self):
        for n in self.neighbors:
            if self.nat is not None and n.interface.ip == self.nat_outside.ip:
                continue
            send_table = ""
            for ip, node in self.table.items():
                if node.valid:  # and not (b and node.interface.ip == self.nat_inside):
                    if node.interface.ip != n.interface.ip:
                        send_table = self.add_to_str(send_table, ip, node.len)
                    else:
                        send_table = self.add_to_str(send_table, ip, HP.MAX_PATH_LEN)
            if len(send_table) > 0:
                send_table = send_table[1:]
            # print(n.interface.ip + " " + n.ip + " " + send_table)
            self.send(n.interface, 1, n.ip, 1, "ad", 2, False, False, 0, send_table, False)
        if self.nat is not None:
            self.nat.send_ad()

    @staticmethod
    def add_to_str(send_table, destination, distance):
        send_table = send_table + "|" + str(destination) + "," + str(distance)
        return send_table

    def no_route_message(self, interface, pkt):
        if interface is not None:
            self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, 0,
                      HP.ICMP_NO_ROUTE_CODE, False)

    def nat_dropped_message(self, interface, pkt):
        self.send(interface, 1, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL, pkt.mf, False, 0,
                  HP.ICMP_NAT_DROPPED_CODE, False)


def get_next_ip(ip):
    print("ip:" + ip)
    num = ip_to_int(ip)
    num += 1
    ret = int_to_ip(num)
    print("next ip:" + ret)
    return ret


def ip_to_int(ip):
    parts = ip.split(".")
    assert len(parts) == 4
    num = int(parts[0]) * (256 * 256 * 256) + int(parts[1]) * (256 * 256) + int(parts[2]) * 256 + int(parts[3])
    return num


def int_to_ip(num):
    return str((num // (256 * 256 * 256)) % 256) + "." + str((num // (256 * 256)) % 256) + "." + str(
        (num // 256) % 256) + "." + str(num % 256)


class Nat:

    def __init__(self, router, acl, pool, has_port_forwarding, is_restricted, inside_interface, outside_interface):
        self.acl = acl
        self.assignment = dict()
        self.assigned_out_ip_ports = dict()
        self.pool_range = pool
        self.has_port_forwarding = has_port_forwarding
        self.is_restricted = is_restricted
        self.inside = inside_interface
        self.outside = outside_interface
        self.router = router

    def receive_pkt(self, interface, pkt):
        if self.has_port_forwarding:
            if self.assigned_out_ip_ports.__contains__((pkt.receiver, pkt.receiver_port)):
                a = self.assigned_out_ip_ports[(pkt.receiver, pkt.receiver_port)]
                tmp = (a[0], a[1])
                if pkt.type == "icmp" or not self.is_restricted or self.assignment[tmp].has_connection(
                        [pkt.sender, pkt.sender_port]):
                    pkt.receiver = tmp[0]
                    pkt.receiver_port = tmp[1]
                    self.assignment[tmp].reset_timer()
                    self.router.nat_subst_cnt(interface, pkt)
                    return
        else:
            if self.assigned_out_ip_ports.__contains__(pkt.receiver):
                a = self.assigned_out_ip_ports[pkt.receiver]
                tmp = (a[0], a[1])
                if pkt.type == "icmp" or not self.is_restricted or self.assignment[tmp].has_connection(
                        [pkt.sender, pkt.sender_port]):
                    pkt.receiver = tmp[0]
                    self.assignment[tmp].reset_timer()
                    self.router.nat_subst_cnt(interface, pkt)
                    return
        self.router.nat_dropped_message(interface, pkt)

    def send_pkt(self, pkt):
        if not self.assignment.__contains__((pkt.sender, pkt.sender_port)):
            if ip_to_int(self.acl[0]) <= ip_to_int(pkt.sender) <= ip_to_int(self.acl[1]):
                idx = self.get_free_out_ip()
                if idx is None:
                    self.router.nat_dropped_message(self.router.nat_inside, pkt)
                if self.has_port_forwarding:
                    self.assignment[(pkt.sender, pkt.sender_port)] = NatObject(idx[0], idx[1])
                    self.assigned_out_ip_ports[(idx[0], idx[1])] = [pkt.sender, pkt.sender_port]
                else:
                    self.assignment[(pkt.sender, pkt.sender_port)] = NatObject(idx)
                    self.assigned_out_ip_ports[idx] = [pkt.sender, pkt.sender_port]
            else:
                self.router.nat_dropped_message(self.router.nat_inside, pkt)
        self.assignment[(pkt.sender, pkt.sender_port)].reset_timer()
        self.assignment[(pkt.sender, pkt.sender_port)].add_receiver([pkt.receiver, pkt.receiver_port])
        tmp = pkt.sender
        pkt.sender = self.assignment[(pkt.sender, pkt.sender_port)].ip
        if self.has_port_forwarding:
            pkt.sender_port = self.assignment[(tmp, pkt.sender_port)].port
        self.router.send_pkt(self.outside, pkt, False)

    def get_free_out_ip(self):
        for i in range(ip_to_int(self.pool_range[0]), ip_to_int(self.pool_range[1]) + 1):
            if self.has_port_forwarding:
                for port in ["1111", "2222", "3333", "4444"]:
                    if not self.assigned_out_ip_ports.__contains__((int_to_ip(i), port)):
                        return [int_to_ip(i), port]
            else:
                if not self.assigned_out_ip_ports.__contains__(int_to_ip(i)):
                    return int_to_ip(i)
        return None

    def send_ad(self):
        ad = self.pool_range[0] + ":" + self.pool_range[1] + ",1"
        for ip, node in self.router.table.items():
            if node.interface.ip != self.inside and node.interface.ip != self.outside:
                Router.add_to_str(ad, ip, node.len)
        O = None
        for n in self.router.neighbors:
            if n.interface.ip == self.outside:
                O = n.ip
                break
        self.router.send(self.outside, 1, O, 1, "ad", 2, False, False, 0, ad, False)

    def next_sec(self):
        check = True
        while check:
            check = False
            for key, o in self.assignment.items():
                o.timer -= 1
                if o.timer == 0:
                    if self.has_port_forwarding:
                        self.assigned_out_ip_ports.pop((o.ip, o.port))
                    else:
                        self.assigned_out_ip_ports.pop(o.ip)
                    self.assignment.pop(key)
                    check = True
                    break


class NatObject:
    def __init__(self, ip, port=None):
        self.timer = HP.INVALID_NAT_TIME
        self.ip = ip
        self.port = port
        self.connections = []

    def reset_timer(self):
        self.timer = HP.INVALID_NAT_TIME

    def has_connection(self, ip):
        for c in self.connections:
            if c == ip:
                return True
        return False

    def add_receiver(self, receiver):
        self.connections.append(receiver)


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

    def is_valid(self):
        return self.valid and self.len < HP.MAX_PATH_LEN

    def invalid(self):
        self.len = HP.MAX_PATH_LEN
        self.valid = False

    def try_inc_hold_down(self):
        if self.hold_down_timer < HP.HOLD_DOWN_TIMER:
            self.hold_down_timer += 1
            if self.hold_down_timer == HP.HOLD_DOWN_TIMER:
                # print(str(self.interface.ip) + " invalidate " + str(self.len))
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
