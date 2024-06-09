#!/usr/bin/env python
import binascii
import os
import threading
import serial
import sys
import random
import queue
import time

from util import RouteTableEntry, RevRouteTableEntry
from packets import *

class LoraController:
    def __init__(self, kivy_app):
        self.os_name2serial_port = {
            'nt': 'COM3',
            'posix': '/dev/ttyS0',
        }
        self.serial = serial.Serial(
            port=self.os_name2serial_port[os.name],
            baudrate=115200,
            bytesize=8,
            parity="N",
            timeout=30,
        )
        self.app = kivy_app
        self.serial_lock = threading.Lock()
        self.queue_lock_sending = threading.Lock()
        self.queue_sending_threads = queue.Queue(0)
        self.active_messages = {}
        self.exitFlag = 0
        self.deviceID = 5
        self.has_launched = False
        self.routes = [RouteTableEntry(5, 5, set(), 0, 1)]
        self.reverse_routes = []
        self.msg_id = 0
        self.req_id = 0
        self.BROADCAST_ADDR = 255

    def setup(self):
        # Reset baseline parameters of device.
        self.__try_send_command("AT+RST", "Vendor:Himalaya")

        # Set baseline parameters for transmission.
        # Baud rate, transmission output, bandwidth, spreading Faktor
        self.__try_send_command("AT+CFG=433000000,5,6,12,4,1,0,0,0,0,3000,8,8", "AT,OK")
        
        # Set device address.
        self.__try_send_command("AT+ADDR=" + str(self.deviceID), "AT,OK")

        # Set device destination to broadcast.
        self.__try_send_command("AT+DEST=FFFF", "AT,OK")

        # Enable communcation receiver.
        self.__try_send_command("AT+RX", "AT,OK")

        # Save settings.
        self.__try_send_command("AT+SAVE", "AT,OK")
        self.has_launched = True


    def __try_send_command(self, config: str, confirm: str):
        """Send command to Lora module and confirm correct response.

        Parameters
        ------------ 
        config: command for the Lora module
        confirm: expected response
        """
        received = []
        wait_counter = 0
        self.serial_lock.acquire()
        self.app.write_to_debug_log("< " + str(config)) if self.has_launched else print(config)
        self.serial.write((str(config) + "\r\n").encode('UTF-8'))
        while not (confirm + "\r\n" in received):
            print(*received)
            received.append(self.serial.readline().decode('UTF-8'))
            if "ERR" in received:
                if self.has_launched:
                    self.app.write_to_debug_log("Received err from LoRa, going to sleep")
                    time.sleep(3)
                wait_counter += 3
                if wait_counter == 15:
                    sys.exit()
        self.serial_lock.release()
        if self.has_launched:
            self.app.write_to_debug_log("Received confirmation")

    
    def send_message(self, user_input: str):
        
        input_spliced = user_input.split(",", 1)
        dest_addr = int(input_spliced[1])
        message = input_spliced[0]

        self.app.write_to_console_log("Sending message: \"" + message + "\" to " + str(dest_addr))
        entry = self.__get_entry_by_dest_addr(dest_addr)
        if entry:
            msg = Message(entry.next_hop, self.deviceID, dest_addr, self.routes[0].seq_num, self.msg_id, message)
            tmp_id = self.msg_id + 1
            self.msg_id = tmp_id
            self.active_messages[self.msg_id] = msg
            tmp_seq = self.routes[0].seq_num + 1
            self.routes[0].seq_num = tmp_seq

            for times in range(2):
                if self.msg_id in self.active_messages:
                    self.__add_thread_to_queue(msg)
                else:
                    return
                time.sleep(120)
            self.__send_routeErrors(entry)
        else:
            self.app.write_to_console_log("no route found, starting RREQ, please try again later")
            rreq = RouteRequest(self.BROADCAST_ADDR, self.deviceID, self.req_id, dest_addr, 0, 0, self.deviceID,
                        self.routes[0].seq_num)
            self.__add_thread_to_queue(rreq)
            tmp = self.routes[0].seq_num + 1
            self.routes[0].seq_num = tmp
            self.req_id += 1
            return

    def __send_routeErrors(self, entry):
        affected_routes = self.__get_entries_by_next_hop(entry.next_hop)
        dest_dict = {}
        prec_set = set()
        for route in affected_routes:
            dest_dict[route.dest_addr] = route.seq_num
            prec_set.union(route.precursors)
            self.routes.remove(route)
        for precursor in prec_set:
            route_to_current_prec = self.__get_entry_by_dest_addr(precursor)
            rerr = RouteError(route_to_current_prec.next_hop, self.deviceID, len(affected_routes), dest_dict)
            self.__add_thread_to_queue(rerr)

    def __send_packet(self, packet_str: str):
        time.sleep(random.randint(0, 4))
        command = "AT+SEND=" + str(len(packet_str))
        self.__try_send_command(command, "AT,OK")
        self.__try_send_command(packet_str, "AT,SENDED")

    def receiving_loop(self):
        while True:
            self.serial_lock.acquire()
            while self.serial.in_waiting > 0:
                incoming_raw = self.serial.readline()

                try:
                    first_byte = base64.b64decode(incoming_raw[:4])[0]
                    packet_type = format(first_byte, '#010b')[2:6]

                    # Message
                    if packet_type == '0011':
                        incoming = base64.b64decode(incoming_raw[:8])
                        self.__handle_message(Message.construct_message(incoming, incoming_raw[8:-2].decode('ascii')))

                    else:
                        incoming = base64.b64decode(incoming_raw)

                        # RouteRequest
                        if packet_type == '0000':
                            self.__handle_routeRequest(RouteRequest.construct_routeRequest(incoming))

                        # RouteReply
                        elif packet_type == '0001':
                            self.__handle_routeReply(RouteReply.construct_routeReply(incoming))

                        # RouteError
                        elif packet_type == '0010':
                            self.__handle_routeError(RouteError.construct_routeError(incoming))

                        # Acknowledge
                        elif packet_type == '0100':
                            self.__handle_acknowledge(Acknowledge.construct_acknowledge(incoming))

                        # unknown message type
                        else:
                            self.app.write_to_console_log("Error: Packet couldn't be interpreted")

                except binascii.Error as err:
                    self.app.write_to_debug_log("Packet couldn't be decoded")

            self.serial_lock.release()

    def __handle_routeRequest(self, packet: RouteRequest):
        self.app.write_to_input_log("> " + str(packet))
        if packet.orig_addr == self.deviceID:
            return

        if packet.dest_addr == self.deviceID:
            rrep = RouteReply(packet.prev_hop_addr, self.deviceID, packet.req_id, packet.orig_addr, self.routes[0].seq_num, 0,
                        self.deviceID)
            tmp = self.routes[0].seq_num + 1
            self.routes[0].seq_num = tmp
            self.__add_thread_to_queue(rrep)
            return

        rev_entry = self.__get_rev_entry_by_orig_addr_and_req_id(packet)
        if rev_entry:
            if packet.hops < rev_entry.hops:
                self.reverse_routes.remove(rev_entry)
                self.reverse_routes.append(
                    RevRouteTableEntry(packet.dest_addr, packet.orig_addr, packet.req_id, packet.hops,
                                       packet.prev_hop_addr))
        else:
            # reverse Route is missing -> forward RouteRequest and add to RevRouteTable
            self.reverse_routes.append(
                RevRouteTableEntry(packet.dest_addr, packet.orig_addr, packet.req_id, packet.hops,
                                   packet.prev_hop_addr))
            self.__forward_packet(packet)
            return

        entry = self.__get_entry_by_dest_addr(packet.dest_addr)
        if entry:
            if entry.hops > packet.hops or entry.seq_num < packet.dest_seq:
                self.routes.remove(entry)
                self.routes.insert(0, RouteTableEntry(packet.dest_addr, packet.hop_addr, {packet.prev_hop_addr},
                                                      packet.hops,
                                                      packet.dest_seq))
                self.__forward_packet(packet)
        # if Route is missing -> add to RouteTable
        else:
            self.routes.append(RouteTableEntry(packet.dest_addr, packet.hop_addr, {packet.prev_hop_addr},
                                               packet.hops,
                                               packet.dest_seq))

    def __handle_routeReply(self, packet: RouteReply):
        self.app.write_to_input_log("> " + str(packet))
        # RouteReply to our RouteRequest
        if packet.dest_addr == self.deviceID:
            self.routes.append(
                RouteTableEntry(packet.orig_addr, packet.prev_hop_addr, {packet.prev_hop_addr}, packet.dest_seq,
                                packet.hops))
            return

        # check if a reverse route exist
        route_to_dest = self.__get_rev_entry_by_orig_addr(packet.dest_addr)
        if route_to_dest:
            forward_rrep = packet
            forward_rrep.hop_addr = route_to_dest.prev_hop_addr
            self.__forward_packet(forward_rrep)

            # check if a regular route exist
            route_table_entry = self.__get_entry_by_dest_addr(packet.dest_addr)
            if route_table_entry:
                if route_table_entry.hops > packet.hops or route_table_entry.seq_num < packet.dest_seq:
                    self.routes.remove(route_table_entry)
                    self.routes.append(RouteTableEntry(packet.orig_addr, packet.prev_hop_addr,
                                                       {packet.prev_hop_addr, route_to_dest.prev_hop_addr}.union(
                                                           route_table_entry.precursors),
                                                       packet.dest_seq, packet.hops))

            # no route found
            else:
                self.routes.append(RouteTableEntry(packet.orig_addr, packet.prev_hop_addr,
                                                   {packet.prev_hop_addr, route_to_dest.prev_hop_addr},
                                                   packet.dest_seq, packet.hops))

    def __handle_routeError(self, packet: RouteError):
        self.app.write_to_input_log("> " + str(packet))
        if packet.hop_addr == self.deviceID:
            ack = Acknowledge(packet.prev_hop_addr, packet.hop_addr)
            self.__add_thread_to_queue(ack)
            for packet_index, (key, value) in packet.dest_dict:
                for index, route in self.routes:
                    if route.dest_addr == key:
                        self.routes.remove(index)
                        for prec_addr in route.precursors:
                            rerr = RouteError(prec_addr, self.deviceID, packet.path_count, packet.dest_dict)
                            self.__add_thread_to_queue(rerr)

    def __handle_message(self, packet: Message):
        self.app.write_to_input_log("> " + str(packet))
        self.__add_thread_to_queue(Acknowledge(packet.prev_hop_addr, packet.hop_addr))
        if packet.dest_addr == self.deviceID:
            self.app.write_to_console_log("> " + packet.payload)

        else:
            entry = self.__get_entry_by_dest_addr(packet.dest_addr)
            msg = packet
            msg.hop_addr = entry.next_hop
            self.__forward_packet(msg)

    def __handle_acknowledge(self, packet: Acknowledge):
        self.app.write_to_input_log("> " + str(packet))
        for msg_id, msg in self.active_messages.items():
            if msg.hop_addr == packet.prev_hop_addr:
                self.active_messages.pop(msg_id)
                return

    
    def __get_entry_by_dest_addr(self, dest_addr: int):
        for entry in self.routes:
            if entry.dest_addr == dest_addr:
                return entry
        return None

    
    def __get_rev_entry_by_orig_addr_and_req_id(self, packet) -> RouteTableEntry:
        for rev_entry in self.reverse_routes:
            if packet.orig_addr == rev_entry.orig_addr & \
                    packet.req_id == rev_entry.req_id:
                return rev_entry
        return None

    def __get_rev_entry_by_orig_addr(self, orig_addr) -> RevRouteTableEntry:
        for rev_entry in self.reverse_routes:
            if rev_entry.orig_addr == orig_addr:
                return rev_entry
        return None

    def __forward_packet(self, packet):
        forwarded_packet = packet
        forwarded_packet.prev_hop_addr = self.deviceID
        if packet.type != 3:
            forwarded_packet.hops += 1
        self.__add_thread_to_queue(forwarded_packet)

    def process_sendings(self):
        while not self.exitFlag:
            self.queue_lock_sending.acquire()
            if not self.queue_sending_threads.empty():
                thread = self.queue_sending_threads.get()
                thread.start()
                thread.join()
                self.queue_lock_sending.release()
            else:
                self.queue_lock_sending.release()
            time.sleep(1)

    def __add_thread_to_queue(self, packet):
        self.queue_lock_sending.acquire()
        self.queue_sending_threads.put(threading.Thread(target=self.__send_packet, args=(to_base64(packet),)))
        self.queue_lock_sending.release()

    def __get_entries_by_next_hop(self, next_hop):
        entries = []
        for entry in self.routes:
            if entry.next_hop == next_hop:
                entries.append(entry)
        return entries