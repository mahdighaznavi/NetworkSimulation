
class Packet:
    def __init__(self, sender, sender_port, receiver, rcvr_port, type, ttl, more_fragments, dont_fragment,
                 fragmentation_offset, body):
        """
        :param sender: ip of sender
        :param sender_port: sender port
        :param receiver: ip of receiver
        :param rcvr_port: receiver port
        :param type: type of packet. Possible: msg, icmp, ad
        :param ttl: time to live
        :param more_fragments: more fragment flag
        :param dont_fragment: don't fragment flag
        :param fragmentation_offset: fragmentation offset. calculated from  begining of body string
        :param body: body of message
        """
        self.sender = sender
        self.sender_port = sender_port
        self.receiver = receiver
        self.receiver_port = rcvr_port
        self.type = type
        self.ttl = int(ttl)
        self.mf = bool(more_fragments)
        self.df = bool(dont_fragment)
        self.fo = int(fragmentation_offset)
        self.body = body

    def __str__(self):
        s = '----------------------------------------\n'
        s += 'Sndr:' + self.sender + str(self.sender_port) + ' Rcvr:' + str(self.receiver) + str(
            self.receiver_port) + ' type: '+ self.type + '\n'
        s += 'TTL:' + str(self.ttl) + ' DF:' + str(self.df) + ' MF:' + str(self.mf) + ' FO: ' + str(self.fo) + '\n'
        s += 'Body:' + self.body + '\n'
        s += '----------------------------------------'
        return s