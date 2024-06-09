import base64


class RouteRequest:
    def __init__(self,
                 hop_addr: int, prev_hop_addr: int, req_id: int, dest_addr: int, dest_seq: int, hops: int,
                 orig_addr: int, orig_seq: int):
        self.type = 0
        
        # not implemented
        self.flags = 0

        self.hop_addr = hop_addr
        self.prev_hop_addr = prev_hop_addr
        self.req_id = req_id
        self.dest_addr = dest_addr
        self.dest_seq = dest_seq
        self.hops = hops
        self.orig_addr = orig_addr
        self.orig_seq = orig_seq

    def construct_routeRequest(incoming: bytes):
        return RouteRequest(incoming[1], incoming[2], incoming[3], incoming[4], incoming[5], incoming[6], incoming[7],
                    incoming[8])

    def __str__(self) -> str:
        return \
            f'RouteRequest: [ ' \
            f'hop_addr: {self.hop_addr}' \
            f'; prev_hop_addr: {self.prev_hop_addr}' \
            f'; req_id: {self.req_id}' \
            f'; dest_addr: {self.dest_addr}' \
            f'; dest_seq: {self.dest_seq}' \
            f'; hops: {self.hops}' \
            f'; orig_addr: {self.orig_addr}' \
            f'; orig_seq: {self.orig_seq}]'


class RouteReply:
    def __init__(self, hop_addr: int, prev_hop_addr: int, req_id: int, dest_addr: int, dest_seq: int,
                 hops: int, orig_addr: int):
        self.type = 1
        self.flags = 0
        self.hop_addr = hop_addr
        self.prev_hop_addr = prev_hop_addr
        self.req_id = req_id
        self.dest_addr = dest_addr
        self.dest_seq = dest_seq
        self.hops = hops
        self.orig_addr = orig_addr
        self.padding = 0

    def construct_routeReply(incoming: bytes):
        return RouteReply(incoming[1], incoming[2], incoming[3], incoming[4], incoming[5], incoming[6], incoming[7])

    def __str__(self) -> str:
        return \
            f'RouteReply: [ ' \
            f'hop_addr: {self.hop_addr}' \
            f'; prev_hop_addr: {self.prev_hop_addr}' \
            f'; req_id: {self.req_id}' \
            f'; dest_addr: {self.dest_addr}' \
            f'; dest_seq: {self.dest_seq}' \
            f'; hops: {self.hops}' \
            f'; orig_addr: {self.orig_addr}]'


class RouteError:
    def __init__(self, hop_addr: int, prev_hop_addr: int, path_count: int, dest_dict: {}):
        self.type = 2
        self.flags = 0
        self.hop_addr = hop_addr
        self.prev_hop_addr = prev_hop_addr
        self.path_count = path_count
        self.dest_dict = dest_dict

    def construct_routeError(incoming: bytes):
        dest_dict = {}
        for entry in range(4, len(incoming) - 1, 2):
            dest_dict[incoming[entry + 1]] = incoming[entry]
        return RouteError(incoming[1], incoming[2], incoming[3], dest_dict)

    def __str__(self) -> str:
        return \
            f'RouteError: [ ' \
            f'hop_addr: {self.hop_addr}' \
            f'; prev_hop_addr: {self.prev_hop_addr}' \
            f'; path_count: {self.path_count}]'


class Message:
    def __init__(self, hop_addr: int, prev_hop_addr: int, dest_addr: int, orig_seq: int, msg_id: int,
                 payload: str):
        self.type = 3
        self.flags = 0
        self.hop_addr = hop_addr
        self.prev_hop_addr = prev_hop_addr
        self.dest_addr = dest_addr
        self.orig_seq = orig_seq
        self.msg_id = msg_id
        self.payload = payload

    def construct_message(incoming: bytes, payload: str):
        return Message(incoming[1], incoming[2], incoming[3], incoming[4], incoming[5], payload)

    def __str__(self) -> str:
        return \
            f'Message: [ ' \
            f'hop_addr: {self.hop_addr}' \
            f'; prev_hop_addr: {self.prev_hop_addr}' \
            f'; dest_addr: {self.dest_addr}' \
            f'; orig_seq: {self.orig_seq}' \
            f'; msg_id: {self.msg_id}' \
            f'; payload: {self.payload}]'


class Acknowledge:
    def __init__(self, hop_addr: int, prev_hop_addr: int):
        self.type = 4
        self.flags = 0
        self.hop_addr = hop_addr
        self.prev_hop_addr = prev_hop_addr

    def construct_acknowledge(incoming: bytes):
        return Acknowledge(incoming[1], incoming[2])

    def __str__(self) -> str:
        return \
            f'Acknowledge: [' \
            f'hop_addr: {self.hop_addr}' \
            f'; prev_hop_addr: {self.prev_hop_addr}]'


def to_base64(packet):
    packet_vars = [value for value in vars(packet).values()]
    # RouteError
    if packet.type == 2:
        result = b'\x20'
        for i, (key, value) in packet_vars[2:-1]:
            result += int.to_bytes(value, 1, 'big', signed=False)
        for key, value in packet.dest_dict.items():
            result += int.to_bytes(value, 1, 'big', signed=False)
            result += int.to_bytes(key, 1, 'big', signed=False)

        return base64.standard_b64encode(result)

    # Message
    elif packet.type == 3:
        result = b'\x30'
        for value in packet_vars[2:-1]:
            # encode header(base64) and payload(ascii)
            result += int.to_bytes(value, 1, 'big', signed=False)

        mixed_result = base64.standard_b64encode(result)
        mixed_result += packet.payload.encode('ascii')
        return mixed_result

    # type + flag
    # RouteRequest
    if packet.type == 0:
        result = b'\x00'
    # RouteReply
    elif packet.type == 1:
        result = b'\x10'
    # RouteError
    elif packet.type == 4:
        result = b'\x40'

    for value in packet_vars[2:]:
        result += int.to_bytes(value, 1, 'big', signed=False)

    return base64.standard_b64encode(result)
