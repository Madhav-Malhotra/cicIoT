import socket # safe
import struct # safe
from functools import reduce # installable
import numpy as np # unsafe - must be replaced with ulab

def ip_to_str(ip):
    """
     converts and source or destination ip to string values
    """
    ip = socket.inet_ntoa(ip)

    return ip

def get_protocol_name(protocol_val):
    """
    returns the name of Protocol
    """
    if protocol_val == 0:
        return "IP"
    elif protocol_val == 6:
        return "TCP"

    elif protocol_val == 17:
        return "UDP"

    elif protocol_val == 2:
        return "IGMP"

    elif protocol_val == 1:
        return "ICMP"

    else:
        return "Unknown for now"

def get_flow_info(flows, flow):
    """
    generating flow features
    """

    bytes = reduce(lambda x, y: x+y,
                   map(lambda e: e['byte_count'], flows[flow]))
    duration = sorted(map(lambda e: e['ts'], flows[flow]))
    if len(duration)>1:
        idle_time = duration[len(duration)-1] - duration[len(duration) - 2]
    else:
        idle_time = duration[len(duration)-1]

    max_duration = max(duration)
    min_duration = min(duration)
    sum_duration = sum(duration)
    average_duration = sum(duration) / len(duration)
    std_duration = np.std(duration)
    duration = duration[-1] - duration[0]
    active_time = duration

    return bytes,duration,max_duration,min_duration,sum_duration,average_duration,std_duration,idle_time,active_time

def get_flag_values(tcp):
    """
    getting the numerical values of flags
    """
    fin_flag = (tcp.flags & 0x01) != 0
    syn_flag = (tcp.flags & 0x02) != 0
    rst_flag = (tcp.flags & 0x04) != 0
    psh_flag = (tcp.flags & 0x08) != 0
    ack_flag = (tcp.flags & 0x10) != 0
    urg_flag = (tcp.flags & 0x20) != 0
    ece_flag = (tcp.flags & 0x40) != 0
    cwr_flag = (tcp.flags & 0x80) != 0
    outputs = []
    outputs.append(fin_flag)
    outputs.append(syn_flag)
    outputs.append(rst_flag)
    outputs.append(psh_flag)
    outputs.append(ack_flag)
    outputs.append(urg_flag)
    outputs.append(ece_flag)
    outputs.append(cwr_flag)
    for k in range(0,len(outputs)):
        if outputs[k] == True:
            outputs[k] = 1
        else:
            outputs[k] = 0

    return outputs

def compare_flow_flags(flag_valus,ack_count,syn_count,fin_count,urg_count,rst_count):
    """
    comparing the flags to see how many times are they set
    """
    if flag_valus[0] == 1:
        ack_count = ack_count + 1
    if flag_valus[1] == 1:
        syn_count = syn_count + 1
    if flag_valus[2] == 1:
        fin_count = fin_count + 1
    if flag_valus[3] == 1:
        urg_count = urg_count + 1
    if flag_valus[4] == 1:
        rst_count = rst_count + 1

    return ack_count,syn_count,fin_count,urg_count,rst_count

def get_src_dst_packets(flows,flow):
    """
    calculating the number of packets from source_destination and vice-versa
    :param flows:
    :param flow:
    :return: src_to_dst_pkt,dst_to_src_pkt,src_to_dst_byte, dst_to_src_byte
    """
    src_to_dst_pkt = 0
    dst_to_src_pkt = 0
    src_to_dst_byte = 0
    dst_to_src_byte = 0
    if flows.get(flow):
        packets = flows[flow]
        src_to_dst_pkt = len(packets)
        for i in range(0,len(packets)):
            src_to_dst_byte = src_to_dst_byte + packets[i]['byte_count']


    newflow = (flow[1], flow[0])
    if flows.get(newflow):
        packets = flows[newflow]
        dst_to_src_pkt = len(packets)
        for i in range(0, len(packets)):
            dst_to_src_byte = dst_to_src_byte + packets[i]['byte_count']


    return src_to_dst_pkt, dst_to_src_pkt, src_to_dst_byte, dst_to_src_byte

def calculate_incoming_connections(src_pkt, dst_pkt, src_port,dst_port,src_ip,dst_ip):
    """
    caculate the number of incoming connections per src_ip and dst_ip
    :param src_pkt:
    :param dst_pkt:
    :param src_port:
    :param dst_port:
    :param src_ip:
    :param dst_ip:
    :return:
    """

    if (src_port < 1024 and src_port > 0) or (dst_port < 1024 and dst_port > 0):
        if src_pkt.get(src_ip):
            src_pkt[src_ip] = src_pkt[src_ip] + 1
        else:
            src_pkt[src_ip] = 1

        if dst_pkt.get(dst_ip):
            dst_pkt[dst_ip] = dst_pkt[dst_ip] + 1
        else:
            dst_pkt[dst_ip] = 1

def calculate_packets_counts_per_ips_proto(average_per_proto_src,protocol_name, src_ip,average_per_proto_dst, dst_ip):
    """
    Calculates the count of packets per protocol and src_ip (Also for per protocol and dst_ip)
    :param average_per_proto_src:
    :param protocol_name:
    :param src_ip:
    :param average_per_proto_dst:
    :param dst_ip:
    :return:
    """
    if average_per_proto_src.get(str((protocol_name, src_ip))):
        average_per_proto_src[str((protocol_name, src_ip))] = average_per_proto_src[str((protocol_name, src_ip))] + 1
    else:
        average_per_proto_src[str((protocol_name, src_ip))] = 1

    if average_per_proto_dst.get(str((protocol_name, dst_ip))):
        average_per_proto_dst[str((protocol_name, dst_ip))] = average_per_proto_dst[str((protocol_name, dst_ip))] + 1
    else:
        average_per_proto_dst[str((protocol_name, dst_ip))] = 1

def calculate_packets_count_per_ports_proto(average_per_proto_src_port,average_per_proto_dst_port,protocol_name,src_port,dst_port):
    """
    calculates the count of packets per protocol and src_port (Also, per protocol and dst_port)
    :param average_per_proto_src_port:
    :param average_per_proto_dst_port:
    :param protocol_name:
    :param src_port:
    :param dst_port:
    :return:
    """
    if average_per_proto_src_port.get(str((protocol_name, src_port))):
        average_per_proto_src_port[str((protocol_name, src_port))] = average_per_proto_src_port[
                                                                         str((protocol_name, src_port))] + 1
    else:
        average_per_proto_src_port[str((protocol_name, src_port))] = 1

    if average_per_proto_dst_port.get(str((protocol_name, dst_port))):
        average_per_proto_dst_port[str((protocol_name, dst_port))] = average_per_proto_dst_port[
            str((protocol_name, dst_port))]

    else:
        average_per_proto_dst_port[str((protocol_name, dst_port))] = 1


