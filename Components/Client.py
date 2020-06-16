from Components.Packet import Packet
import HP


def copy_pkt(pkt):
    return Packet(pkt.sender, pkt.sender_port, pkt.receiver, pkt.receiver_port, pkt.type, pkt.ttl, pkt.mf, pkt.df,
                  pkt.fo, (pkt.body + ".")[:-1])


class Client:
    def __init__(self, ip):
        self.ip = ip
        self.link = None
        self.tracing_routes = []
        self.buffer = ""

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
        if pkt.mf:
            if pkt.type == "msg":
                self.buffer = self.buffer + pkt.body
            # print("Client: " + self.buffer)
            return
        if len(self.buffer) > 0:
            pkt.body = (self.buffer + pkt.body + ".")[:-1]
            self.buffer = ""
        if pkt.type == 'msg':
            if pkt.receiver == self.ip:
                print(self.ip + ": msg from " + pkt.sender + " " + pkt.body)
        elif pkt.type == "icmp":
            if pkt.body == HP.ICMP_PING_CODE:
                ping_resp_packet = Packet(self.ip, pkt.receiver_port, pkt.sender, pkt.sender_port, "icmp", HP.INF_TTL,
                                          False, False, 0, HP.ICMP_PING_RESPONSE_CODE)
                self.send_pkt(ping_resp_packet)
            elif pkt.body == HP.ICMP_PING_RESPONSE_CODE:
                self.finish_trace_rout(pkt.sender, pkt.receiver_port)
            elif pkt.body == HP.ICMP_TTL_ENDED_CODE:
                is_routed = False
                for t in self.tracing_routes:
                    if t.port == pkt.receiver_port:
                        t.rout(pkt.sender)
                        is_routed = True
                        break
                if not is_routed:
                    self.print("ttl timeout")
            elif pkt.body == HP.ICMP_NO_ROUTE_CODE:
                is_traced = self.finish_trace_rout("unreachable", pkt.receiver_port)
                if not is_traced:
                    self.print("unreachable")
            elif pkt.body == HP.ICMP_FRAGMENTATION_NEEDED:
                self.fragmentation_error()

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
        self.send_pkt(pkt)

    def trace_rout(self, ip):
        """
        trace rout to ip
        :param ip: destination
        """
        self.tracing_routes.append(TraceRouteObject(ip, self.get_free_port(), self))
        self.tracing_routes[-1].send()
        pass

    def send_pkt(self, pkt):
        if self.link:
            if len(pkt.body) > self.link.mtu:
                if pkt.df:
                    self.fragmentation_error()
                else:
                    cur = 0
                    new_pkt = copy_pkt(pkt)
                    while cur < len(pkt.body):
                        new_pkt.fo = cur
                        new_pkt.body = new_pkt.body[cur:min(len(pkt.body), cur + self.link.mtu)]
                        if cur + self.link.mtu >= len(pkt.body):
                            new_pkt.mf = False
                        else:
                            new_pkt.mf = True
                        new_pkt.df = False
                        # print(new_pkt)
                        self.link.send(new_pkt, self.ip)
                        new_pkt = copy_pkt(pkt)
                        cur += self.link.mtu
            else:
                # print(pkt)
                self.link.send(pkt, self.ip)

    def finish_trace_rout(self, routed, port):
        for t in self.tracing_routes:
            if t.port == port:
                s = t.print_routing()
                s = s + " " + routed
                print(s)
                self.tracing_routes.remove(t)
                return True
        return False

    def get_free_port(self):
        cnt = 43000
        if len(self.tracing_routes) > 0:
            cnt = max(self.tracing_routes) + 1
        return cnt

    def next_sec(self):
        for i in range(len(self.tracing_routes)):
            self.tracing_routes[i].remain -= 1
            if self.tracing_routes[i].remain == 0:
                self.finish_trace_rout("timeout", self.tracing_routes[i].port)
                i -= 1

    def print(self, text):
        print(self.ip + ": " + text)

    def fragmentation_error(self):
        self.print("fragmentation needed")


class TraceRouteObject:
    def __init__(self, ip, port, client):
        self.ip = ip
        self.port = port
        self.client = client
        self.ttl = 0
        self.remain = -1
        self.routing = []

    def send(self):
        self.remain = HP.TRACE_ROUTE_TIMEOUT
        self.ttl += 1
        pkt = Packet(self.client.ip, self.port, self.ip, 1, "icmp", self.ttl, False, False, 0, HP.ICMP_PING_CODE)
        self.client.send_pkt(pkt)

    def print_routing(self):
        ret = ""
        ret = ret + self.client.ip
        for r in self.routing:
            ret = ret + " " + r
        return ret

    def rout(self, node):
        self.routing.append(node)
        self.send()
