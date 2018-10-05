import serial, time

def create_packet(send_data, data_type):
    packet = []
    packet.append(0xAB)
    packet.append(data_type)
    packet.append(len(send_data) & 0xFF)
    packet.append((len(send_data) >> 8) & 0xFF)
    packet.append((256 - ((sum(packet) & 0xFF))) & 0xFF)
    packet.extend(send_data)
    packet.append((256 - ((sum(packet) & 0xFF))) & 0xFF)
    packet.append(0xBA)
    return packet

def parse_data(data):
    state = "idle"
    packet = []
    data_len = 0
    data_bytes_received = 0

    for val in data:
        #val = ord(val)
            
        #print("Got val: {}".format(val))
        if state == "idle":
            data_len = 0
            data_bytes_received = 0
            packet = []
            if val == 0xAB:
                state = "got_start"
                packet.append(val)
            else:
                print(val)
                state = "idle"
        elif state == "got_start":
            packet.append(val)
            state = "got_type"
        elif state == "got_type":
            packet.append(val)
            state = "got_length_l"        
        elif state == "got_length_l":
            data_len = (val * 256) + packet[-1]
            packet.append(val)
            state = "got_length_h"
            
        elif state == "got_length_h":
            packet.append(val)
            if sum(packet) & 0xFF != 0x00:
                print("Packet Header is invalid!")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
            else:
                state = "got_header_checksum"
        elif state == "got_header_checksum":
            packet.append(val)
            data_bytes_received += 1
            if data_bytes_received >= data_len:
                state = "got_payload"
        elif state == "got_payload":
            packet.append(val)
            if sum(packet) & 0xFF != 0x00:
                print("Packet is invalid!")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
            else:
                state = "got_checksum"
        elif state == "got_checksum":
            packet.append(val)
            if val == 0xBA:
                #print("Got full packet!")
                #print(" ".join(["{:X}".format(val) for val in packet]))
                handle_packet(packet)
                state = "idle"
            else:
                print("Well, this is weird...")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
        else:
            state = "idle"


def receive_data(ser):
    state = "idle"
    packet = []
    data_len = 0
    data_bytes_received = 0
    while True:
        val = ser.read()
        if len(val) == 0:
            continue
        val = ord(val)

            
        #print("Got val: {}".format(val))
        if state == "idle":
            data_len = 0
            data_bytes_received = 0
            packet = []
            if val == 0xAB:
                state = "got_start"
                packet.append(val)
            else:
                state = "idle"
        elif state == "got_start":
            packet.append(val)
            state = "got_type"
        elif state == "got_type":
            packet.append(val)
            state = "got_length_l"        
        elif state == "got_length_l":
            data_len = (val * 256) + packet[-1]
            packet.append(val)
            state = "got_length_h"
            
        elif state == "got_length_h":
            packet.append(val)
            if sum(packet) & 0xFF != 0x00:
                print("Packet Header is invalid!")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
            else:
                state = "got_header_checksum"
        elif state == "got_header_checksum":
            packet.append(val)
            data_bytes_received += 1
            if data_bytes_received >= data_len:
                state = "got_payload"
        elif state == "got_payload":
            packet.append(val)
            if sum(packet) & 0xFF != 0x00:
                print("Packet is invalid!")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
            else:
                state = "got_checksum"
        elif state == "got_checksum":
            packet.append(val)
            if val == 0xBA:
                #print("Got full packet!")
                #print(" ".join(["{:X}".format(val) for val in packet]))
                handle_packet(packet)
                state = "idle"
            else:
                print("Well, this is weird...")
                print(" ".join(["{:X}".format(val) for val in packet]))
                state = "idle"
        else:
            state = "idle"


#TODO: update this, look into payload for temp and level data
def handle_packet(packet):
    if packet[1] == 0x00: #temperature packet
        temperature = packet[8] * 256 + packet[7]
        print("Temp:  {}".format(temperature))
    elif packet[1] == 0x01: #Level packet
        level = packet[8] * 256 + packet[7]
        print("Level: {}".format(level))

PACKET_TYPE_ECHO = 0
PACKET_TYPE_SETTINGS = 1
PACKET_TYPE_STATUS = 2

SETTINGS_OP_LOAD = 0
SETTINGS_OP_SAVE = 1
SETTINGS_OP_WRITE = 2
SETTINGS_OP_READ = 3

SETTINGS_LOAD_ALL = 0
SETTINGS_LOAD_ONE = 1

SETTINGS_SAVE_ALL = 0
SETTINGS_SAVE_ONE = 1

SETTINGS_TANK_PUMP_TURN_ON_LEVEL = 0
SETTINGS_TANK_PUMP_TURN_OFF_LEVEL = 1

STATUS_OP_READ = 0

STATUS_TEMP_F = 0
STATUS_TANK_LEVEL = 1

def get_pump_turn_on_level(ser):
    pkt = create_packet([SETTINGS_OP_READ,SETTINGS_TANK_PUMP_TURN_ON_LEVEL,3,3], PACKET_TYPE_SETTINGS)

def clear_input_buffer(ser):
    ser.flushInput()

def send_packet(ser, pkt):
    clear_input_buffer(ser)
    ser.write(pkt)
    resp_arr = ser.read(1000)
    return resp_arr
    
def read_settings(ser, setting):
    pkt = create_packet([SETTINGS_OP_READ, setting, 3, 3], PACKET_TYPE_SETTINGS)
    return parse_data(send_packet(ser, pkt))

def write_settings(ser, setting, val):
    pkt = create_packet([SETTINGS_OP_WRITE, setting, val & 0xFF, (val >> 8) & 0xFF], PACKET_TYPE_SETTINGS)
    return send_packet(ser, pkt)


def save_settings_to_eeprom(ser, setting=None):
    if setting == None:
        # saving all settings
        pkt = create_packet([SETTINGS_OP_SAVE, SETTINGS_SAVE_ALL, 0, 0], PACKET_TYPE_SETTINGS)
        return send_packet(ser, pkt)
    else:
        pkt = create_packet([SETTINGS_OP_SAVE, SETTINGS_SAVE_ONE, setting & 0xFF, (setting >> 8) & 0xFF], PACKET_TYPE_SETTINGS)
        return send_packet(ser, pkt)

def load_settings_from_eeprom(ser, setting=None):
    if setting == None:
        # load all settings
        pkt = create_packet([SETTINGS_OP_LOAD, SETTINGS_LOAD_ALL, 0, 0], PACKET_TYPE_SETTINGS)
        return send_packet(ser, pkt)
    else:
        pkt = create_packet([SETTINGS_OP_LOAD, SETTINGS_LOAD_ONE, setting & 0xFF, (setting >> 8) & 0xFF], PACKET_TYPE_SETTINGS)
        return send_packet(ser, pkt)
        

def echo_packet(ser, arr):
    pkt = create_packet(arr, PACKET_TYPE_ECHO)
    return send_packet(ser, pkt)


def get_status(ser, status):
    pkt = create_packet([STATUS_OP_READ, status, 2, 3], PACKET_TYPE_STATUS)
    return parse_data(send_packet(ser, pkt)) 

class Pump(object):
    def __init__(self, ser=None):
        self.ser = ser
        if not ser:
            self.ser = serial.Serial("COM3", baudrate=57600, timeout=0.1)

    def load_settings_from_eeprom(self, setting=None):
        if setting == None:
            # load all settings
            pkt = self.create_packet([SETTINGS_OP_LOAD, SETTINGS_LOAD_ALL, 0, 0], PACKET_TYPE_SETTINGS)
            return self.send_packet(ser, pkt)
        else:
            pkt = self.create_packet([SETTINGS_OP_LOAD, SETTINGS_LOAD_ONE, setting & 0xFF, (setting >> 8) & 0xFF], PACKET_TYPE_SETTINGS)
            return self.send_packet(ser, pkt)

    def create_packet(self, send_data, data_type):
        packet = []
        packet.append(0xAB)
        packet.append(data_type)
        packet.append(len(send_data) & 0xFF)
        packet.append((len(send_data) >> 8) & 0xFF)
        packet.append((256 - ((sum(packet) & 0xFF))) & 0xFF)
        packet.extend(send_data)
        packet.append((256 - ((sum(packet) & 0xFF))) & 0xFF)
        packet.append(0xBA)
        return packet

    def send_packet(self, pkt):
        self.clear_input_buffer(self.ser)
        self.ser.write(pkt)
        resp_arr = self.ser.read(1000)
        return resp_arr

    def clear_input_buffer(self):
        self.ser.flushInput()


class Pump_old():
    def __init__(self, com = None, ser = None):
        if not com:
            com = "COM4"
        if not ser:
            self.ser = serial.Serial(com, 9600, timeout=0.1)
        else:
            self.ser = ser

    def read_dump(self):
        print(self.ser.read(1000))

    def get_data_wait(self, wait_time = 5, retry_time = 1):
        for i in range(wait_time):
            if self.get_data() != -1:
                return
            time.sleep(retry_time)
            

    def write_data(self):
        #printval = '|'.join(self.valse['val01']
        print('writing: ', '|'.join(self.data_split))
        self.ser.write('|'.join(self.data_split))

    def get_data(self):
        self.data = self.ser.read(1000)
        if len(self.data) == 0:
            print("No Data!")
            return -1
        self.data_line = self.data.split("\r\n")
        if len(self.data_line) > 1:
            self.data_line = self.data_line[-2]
        else:
            self.data_line = self.data_line[0]
        self.data_split = self.data_line.split('|')
        if len(self.data_split) != 16:
            print("Bad Data!")
            return
        self.vals = {}
        self.vals['val01'] = self.data_split[0]
        self.vals['val02'] = self.data_split[1]
        self.vals['val03'] = self.data_split[2]
        self.vals['val04'] = self.data_split[3]
        self.vals['val05'] = self.data_split[4]
        self.vals['val06'] = self.data_split[5]
        self.vals['val07'] = self.data_split[6]
        self.vals['val08'] = self.data_split[7]
        self.vals['val09'] = self.data_split[8]
        self.vals['val10'] = self.data_split[9]
        self.vals['val11'] = self.data_split[10]
        self.vals['val12'] = self.data_split[11]
        self.vals['val13'] = self.data_split[12]
        self.vals['val14'] = self.data_split[13]
        self.vals['val15'] = self.data_split[14]
        self.vals['val16'] = self.data_split[15]
            
        
