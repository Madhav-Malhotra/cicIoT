import binascii

import dpkt


class Communication_wifi:
    def __init__(self,data):
        self.data = data

    def calculating(self):
        pack = dpkt.ieee80211.IEEE80211(self.data)
        type_info = pack.type
        sub_type_info = pack.subtype
        ds_status = pack.DataFromDS().bssid
        src_mac = pack.mgmt.src
        dst_mac = pack.mgmt.dst
        sequence = pack.Data.frag_seq
        pack_id = pack.version
        fragments = pack.more_frag
        duration = pack.duration

        return type_info, sub_type_info, ds_status, src_mac, dst_mac, sequence, pack_id, fragments, duration



class Communication_ble:
    def __init__(self,pack):
        self.pack = pack

    def ble_features(self):
        pass

class Communication_zigbee:
    def __init__(self,pack):
        self.pack = pack

    def zigbee_features(self):
        dst_add = self.pack.destination_address
        src_add = self.pack.originator_address
        pan_id = self.pack.new_PAN_ID
        packets_len = len(self.pack)

        pass
