#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

own_bridge_id = -1
root_bridge_id = -1
root_path_cost = -1
root_port_id = -1
interfaces_states = {} # key = interface, value = state

# reading config from the file
def parse_vlan_from_config(file_config):
    vlan_config = {} # key = interface, value = vlan_id
    with open(file_config, 'r') as f:
        # first line = switch_priority
        switch_priority = int(f.readline().strip())

        #read every port + vlan_id / if it is trunk
        for line in f:
            line = line.strip()
            both_values = line.split()

            # for both trunk and acces, the first value is the interface
            interface_name = both_values[0]

            # for trunk, set the vlan id to -2; for access, read the vlan_id
            # if trunk:
            if both_values[1] == 'T':
                vlan_config[interface_name] = -2
            else: #if access
                vlan_config[interface_name] = int(both_values[1])

    return vlan_config, switch_priority

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def parse_bpdu(data):
    # bpdu config starts from bit 22
    received_root_bridge_id = int.from_bytes(data[22:30], byteorder='big')
    sender_path_cost = int.from_bytes(data[30:34], byteorder='big')
    received_sender_bridge_id = int.from_bytes(data[34:42], byteorder='big')

    return received_root_bridge_id, sender_path_cost, received_sender_bridge_id

def initialize(interfaces, vlan_config, switch_priority):
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global interfaces_states

    # set each trunk port to blocking
    for i in interfaces:
        interface_name = get_interface_name(i)
        vlan_id = vlan_config[interface_name]
        if vlan_id == -2:
            interfaces_states[i] = 'BLOCKING'
        
    # initialize bridge ID and cost
    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0

    # if the switch becomes root bridge, set each port
    # on the bridge to designated
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            interfaces_states[i] = 'DESIGNATED_PORT'

def make_bpdu(root_bridge_id, sender_bridge_id, sender_path_cost, root_port_id):
    # IEEE 802.3 Ethernet
    # Cadrele BPDU sunt identificate prin adresa multicast MAC destinatie
    # 01:80:C2:00:00:00.
    bpdu_mac_dest = struct.pack("!6B", 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00)
    bpdu_mac_src = get_switch_mac()
    length = struct.pack('!H', 38)

    # Logical-Link Control
    dsap = struct.pack('!B', 42)
    ssap = struct.pack('!B', 42)
    control_field = struct.pack('!B', 3)

    # Spanning Tree Protocol
    protocol_id = struct.pack('!H', 0)
    protocol_version_id = struct.pack('!B', 0)
    bpdu_type = struct.pack('!B', 0)
    bpdu_flags = struct.pack('!B', 0) 
    root_bridge_id = struct.pack('!Q', root_bridge_id)
    sender_path_cost = struct.pack('!L', sender_path_cost)
    sender_bridge_id = struct.pack('!Q', sender_bridge_id)
    root_port_id = struct.pack('!H', root_port_id)
    message_age = struct.pack('!H', 1)
    max_age = struct.pack('!H', 20)
    hello_time = struct.pack('!H', 2)
    forward_delay = struct.pack('!H', 15)

    bpdu_frame = (bpdu_mac_dest + bpdu_mac_src + length + dsap + ssap +
                 control_field + protocol_id + protocol_version_id +
                 bpdu_type + bpdu_flags + root_bridge_id + sender_path_cost +
                 sender_bridge_id + root_port_id + message_age + max_age +
                 hello_time + forward_delay)

    return bpdu_frame

def send_bpdu_every_sec(interfaces, vlan_config):
    global own_bridge_id
    global root_bridge_id
    global root_path_cost

    while True:
        if own_bridge_id == root_bridge_id: # if switch is root
            for i in interfaces:
                interface_name = get_interface_name(i)
                vlan_id = vlan_config[interface_name]
                if vlan_id == -2: # send bpdu on trunk ports
                    root_bridge_id = own_bridge_id
                    sender_bridge_id = own_bridge_id
                    sender_path_cost = 0
                    bpdu_frame = make_bpdu(root_bridge_id, sender_bridge_id, sender_path_cost, i)
                    send_to_link(i, len(bpdu_frame), bpdu_frame)
        time.sleep(1)

def after_receive_bpdu(interfaces, vlan_config, received_root_bridge_id, sender_path_cost, received_sender_bridge_id, received_port_id):
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global root_port_id
    global interfaces_states

    # received a better root bridge
    if received_root_bridge_id < root_bridge_id:
        # if we were the root bridge, block the trunk ports
        if root_bridge_id == own_bridge_id:
            for i in interfaces:
                interface_name = get_interface_name(i)
                vlan_id = vlan_config[interface_name]
                if vlan_id == -2:
                    if i != root_port_id:
                        interfaces_states[i] = 'BLOCKING'

        root_bridge_id = received_root_bridge_id
        root_path_cost = sender_path_cost + 10
        root_port_id = received_port_id

        if interfaces_states[root_port_id] == 'BLOCKING':
            interfaces_states[root_port_id] = 'DESIGNATED_PORT'
        
        # send the updated BPDU to all the other trunk ports
        for i in interfaces:
            interface_name = get_interface_name(i)
            vlan_id = vlan_config[interface_name]
            if vlan_id == -2:
                bpdu_frame = make_bpdu(root_bridge_id, own_bridge_id, root_path_cost, i)
                send_to_link(i, len(bpdu_frame), bpdu_frame)

    elif received_root_bridge_id == root_bridge_id:
        if received_port_id == root_port_id and (sender_path_cost + 10) < root_path_cost:
            root_path_cost = sender_path_cost + 10
        elif received_port_id != root_port_id:
            # Verifica daca portul ar trebui trecut pe designated
            if sender_path_cost > root_path_cost:
                if interfaces_states[received_port_id] != 'DESIGNATED_PORT':
                    interfaces_states[received_port_id] = 'DESIGNATED_PORT'

    elif received_sender_bridge_id == own_bridge_id:
        interfaces_states[received_port_id] = 'BLOCKING'
    else:
        # discard bpdu
        return
    
    # if the switch becomes root bridge, set each port
    # on the bridge to designated
    if own_bridge_id == root_bridge_id:
        for i in interfaces:
            interfaces_states[i] = 'DESIGNATED_PORT'

def is_unicast(mac):
    # least significant bit of the first byte should be 0
    first_byte = int(mac.split(':')[0], 16)
    return (first_byte & 1) == 0

def has_vlan_tag(data):
    # find 0x8200 in the TPID field (12:14) => VLAN tag
    ether_type = int.from_bytes(data[12:14], byteorder='big')
    return ether_type == 0x8200

def main():
    # MAC table: key = MAC address, value = interface
    Mac_table = {}

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # parse the right config file
    switch_config_file = f"configs/switch{switch_id}.cfg"
    vlan_config, switch_priority = parse_vlan_from_config(switch_config_file)

    # initialize the switch
    initialize(interfaces, vlan_config, switch_priority)

    # Create and start a new thread that deals with sending bpdu
    t = threading.Thread(target=send_bpdu_every_sec, args=(interfaces, vlan_config))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # if it's a BPDU (meant for the multicast MAC address)
        if dest_mac == '01:80:c2:00:00:00':
            received_root_bridge_id, sender_path_cost, received_sender_bridge_id = parse_bpdu(data)
            received_port_id = interface
            after_receive_bpdu(interfaces, vlan_config, received_root_bridge_id, sender_path_cost, received_sender_bridge_id, received_port_id)
            continue

        # name of this interface
        interface_name = get_interface_name(interface)
        # if interface not trunk, set vlan_id to the vlan id of the source host
        if vlan_config[interface_name] != -2:
            vlan_id = int(vlan_config[interface_name])

        Mac_table[src_mac] = interface

        if is_unicast(dest_mac):
            if dest_mac in Mac_table:
                # get the vlan id of the destination
                dest_interface_name = get_interface_name(Mac_table[dest_mac])
                dest_vlan = vlan_config[dest_interface_name]

                # if the destination is a trunk and not blocking
                if dest_vlan == -2 and interfaces_states[Mac_table[dest_mac]] != 'BLOCKING':
                    # send the tagged frame
                    # if it doesn't have a vlan tag, add one
                    if not has_vlan_tag(data):
                        new_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                        send_to_link(Mac_table[dest_mac], len(new_data), new_data)
                    else: #if it's coming from a trunk => already has vlan tag
                        send_to_link(Mac_table[dest_mac], length, data)
                # if the destination is access in the same vlan and not blocking
                elif vlan_id == dest_vlan and interfaces_states[Mac_table[dest_mac]] != 'BLOCKING':
                    # get rid of vlan tag, if it has one
                    if has_vlan_tag(data):
                        new_data = data[0:12] + data[16:]
                        send_to_link(Mac_table[dest_mac], len(new_data), new_data)
                    else: #doesn't have vlan tag
                        send_to_link(Mac_table[dest_mac], length, data)
            else: # if dest isn't in MAC table
                for i in interfaces:
                    if i != interface:
                        # get the vlan id of the destination
                        dest_interface_name = get_interface_name(i)
                        dest_vlan = vlan_config[dest_interface_name] 

                        # if the destination is a trunk and not blocking
                        if dest_vlan == -2 and interfaces_states[i] != 'BLOCKING':
                            # send the tagged frame
                            # if it doesn't have a vlan tag, add one
                            if not has_vlan_tag(data):
                                new_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                                send_to_link(i, len(new_data), new_data)
                            else: #if it's coming from a trunk => already has vlan tag
                                send_to_link(i, length, data)
                        # if the destination is access in the same vlan and not blocking
                        elif vlan_id == dest_vlan and interfaces_states[i] != 'BLOCKING':
                            # get rid of vlan tag, if it has one
                            if has_vlan_tag(data):
                                new_data = data[0:12] + data[16:]
                                send_to_link(i, len(new_data), new_data)
                            else: #doesn't have vlan tag
                                send_to_link(i, length, data)
        else:
            for i in interfaces:
                if i != interface:
                    # get the vlan id of the destination
                    dest_interface_name = get_interface_name(i)
                    dest_vlan = vlan_config[dest_interface_name]

                    # if the destination is a trunk and not blocking
                    if dest_vlan == -2 and interfaces_states[i] != 'BLOCKING':
                        # send the tagged frame
                        # if it doesn't have a vlan tag, add one
                        if not has_vlan_tag(data):
                            new_data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                            send_to_link(i, len(new_data), new_data)
                        else: #if it's coming from a trunk => already has vlan tag
                            send_to_link(i, length, data)
                    # if the destination is access in the same vlan and not blocking
                    elif vlan_id == dest_vlan and interfaces_states[i] != 'BLOCKING':
                        # get rid of vlan tag if it has one
                        if has_vlan_tag(data):
                            new_data = data[0:12] + data[16:]
                            send_to_link(i, len(new_data), new_data)
                        else: #doesn't have vlan tag
                            send_to_link(i, length, data)

if __name__ == "__main__":
    main()
