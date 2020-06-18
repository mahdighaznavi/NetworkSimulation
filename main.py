from Components.Connections import Hub, Link
from Components.Router import Router
from Components.Client import Client
from Components.HolePunch import Server, peer_to_peer


def get_interface(ip, routers):
    for r in routers:
        if ip in r.interfaces.keys():
            return r.interfaces[ip]
    raise Exception('Invalid Interface IP')


def get_client(ip, clients):
    for c in clients:
        if c.ip == ip:
            return c
    raise Exception('Invalid Client IP')


def get_client_or_server(ip, clients, servers):
    try:
        return get_client(ip, clients)
    except:
        for s in servers:
            if s.ip == ip:
                return s
        raise Exception('Invalid Client or Server IP')


def get_link(ip1, ip2, links):
    for l in links:
        if (l.right.ip == ip1 and l.left.ip == ip2) or (l.right.ip == ip2 and l.left.ip == ip1):
            return l
    raise Exception('Link Does Not Exists')


def get_router(id, routers):
    for r in routers:
        if r.id == id:
            return r
    raise Exception('Invalid Router ID')


if __name__ == '__main__':

    routers = []
    clients = []
    links = []
    servers = []

    while True:
        cmd = input().split()
        if cmd[0] == 'sec':
            # TODO notify routers here.
            for i in range(int(cmd[1])):
                for r in routers:
                    r.next_sec()
                for c in clients:
                    c.next_sec()
            pass
        elif cmd[0] == 'add_client':
            clients.append(Client(cmd[1]))
        elif cmd[0] == 'add_router':
            routers.append(Router(cmd[1]))
        elif cmd[0] == 'connect_routers':
            try:
                int1 = get_interface(cmd[1], routers)
                int2 = get_interface(cmd[2], routers)
                link = Link(int1, int2, int(cmd[3]))
                links.append(link)
                int1.connect(link)
                int2.connect(link)
                int1.connected(int2.ip, True)
                int2.connected(int1.ip, True)
            except Exception as e:
                print(e)
        elif cmd[0] == 'add_server':
            servers.append(Server(cmd[1]))

        elif cmd[0] == 'connect_hub':
            try:
                interface = get_interface(cmd[1], routers)
                h = Hub()
                h.connect(interface)
                interface.connect(h)
                for i in range(2, len(cmd)):
                    c = get_client_or_server(cmd[i], clients, servers)
                    h.connect(c)
                    c.connect(h)
                    interface.connected(c.ip, False)
            except Exception as e:
                print(e)
        elif cmd[0] == 'peer_to_peer':
            try:
                peer_to_peer(cmd[1], get_client(cmd[2], clients), get_client(cmd[3], clients))
            except Exception as e:
                print(e)
        elif cmd[0] == 'trace_rout':
            try:
                c = get_client(cmd[1], clients)
                c.trace_rout(cmd[2])
            except Exception as e:
                print(e)

        elif cmd[0] == 'link':
            try:
                l = get_link(cmd[2], cmd[3], links)
                if cmd[1] == 'e':
                    l.is_working = True
                elif cmd[1] == 'd':
                    l.is_working = False
            except Exception as e:
                print(e)
        elif cmd[0] == 'config':
            try:
                interface = get_router(cmd[1], routers)
                interface.config()
            except Exception as e:
                print(e)
        elif cmd[0] == 'send_msg':
            msg = input('Enter msg:\n')
            try:
                c = get_client(cmd[1], clients)
                c.send_msg(msg, cmd[2], cmd[3], cmd[4], cmd[5], bool(int(cmd[6])))
            except Exception as e:
                print(e)

        elif cmd[0] == 'end':
            break
