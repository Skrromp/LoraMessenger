class RouteTableEntry:
    def __init__(self,
                 dest_addr: int, next_hop: int, precursors: set[int], seq_num: int,
                 hops: int):
        self.dest_addr = dest_addr
        self.next_hop = next_hop
        self.precursors = precursors
        self.seq_num = seq_num
        self.hops = hops

    def __str__(self) -> str:
        return \
            f'dest_addr: {self.dest_addr}' \
            f'; next_hop: {self.next_hop}' \
            f'; hops: {self.hops}' \
            f'; dest_seq_num: {self.seq_num}' \
            f'; precursors: {self.precursors}'


class RevRouteTableEntry:
    def __init__(self, dest_addr: int, orig_addr: int, req_id: int, hops: int, prev_hop_addr: int):
        self.dest_addr = dest_addr
        self.orig_addr = orig_addr
        self.req_id = req_id
        self.hops = hops
        self.prev_hop_addr = prev_hop_addr

    def __str__(self) -> str:
        return \
            f'dest_addr: {self.dest_addr}' \
            f'; orig_addr: {self.orig_addr}' \
            f'; req_id: {self.req_id}' \
            f'; hops: {self.hops}' \
            f'; prev_hop_addr: {self.prev_hop_addr}'
