import logging

log_level = logging.DEBUG
logging.basicConfig(level=log_level, format = '%(asctime)s  %(levelname)-10s %(name)s %(message)s', datefmt =  "%Y-%m-%d-%H-%M-%S")

log = logging.getLogger(__name__)


import serial, time, struct

PAYLOAD_TYPE_ECHO = 0
PAYLOAD_TYPE_SETTINGS = 1
PAYLOAD_TYPE_STATUS = 2

class Payload(object):
    """
    Payload class

    Class for handling the payload section of a packet
    """
    def __init__(self,
                 payload_len,
                 payload_type,
                 payload_opcode=None,
                 payload_command=None,
                 payload_value=None,
                 payload_byte_arr=None):
        self.length = payload_len
        self.pl_type = payload_type
        self.opcode = payload_opcode
        self.command = payload_command
        self.value = payload_value
        self.byte_arr = payload_byte_arr
        self.valid = False

        # got opcode, command, and value.  Create byte_array
        if self.opcode != None and self.command != None and self.value != None:
            self.byte_arr = bytes(struct.pack('<BBH', self.opcode, self.command, self.value), 'UTF-8')
            self.valid = True

        # got byte_array.  If a settings or status packet, populate opcode, command, and value
        elif self.byte_arr != None:
            if self.length != len(self.byte_arr):
                log.error("Length given ({}) and length of array ({}) do not match!".format(self.length, len(self.byte_arr)))
                return
            if self.pl_type == PAYLOAD_TYPE_SETTINGS or self.pl_type == PAYLOAD_TYPE_STATUS:
                if self.length != 4:
                    log.error("Incorrect array length ({}) for payload type ({})".format(self.length, self.pl_type))
                    return
                (self.opcode, self.command, self.value) = struct.unpack('<BBH', self.byte_arr)
            self.valid = True

        # compute checksum
        self.checksum = (256 - (sum(self.byte_arr) & 0xFF)) & 0xFF
        

class Packet(object):
    """
    Packet class

    Class for handling packets sent to, and received from, the water controller
    """
    PACKET_START_FLAG_OFFSET = 0
    PACKET_PAYLOAD_TYPE_OFFSET = 1
    PACKET_PAYLOAD_LEN_OFFSET = 2
    PACKET_HEADER_CHECKSUM_OFFSET = 4
    PACKET_PAYLOAD_OFFSET = 5
    
    def __init__(self, payload_type=None, payload=None, payload_data=None, byte_arr=None):
        self.payload_type = payload_type # this is a byte containing the type of payload
        self.payload_data = payload_data # this is a byte array of all payload data (4 bytes)
        self.byte_arr = byte_arr # this is a byte array of an entire packet
        self.valid = False
        self.payload = payload #this is a Payload object

        # we have type and data, construct a Payload object, and populate the byte_array
        if self.payload_type != None and self.payload_data != None:
            self.payload = Payload(len(self.payload_data), self.payload_type, payload_byte_arr=self.payload_data)
            if not self.payload.valid:
                log.error("Payload error: {}".format(self.payload.byte_arr))
                return
            self.byte_arr = self._create_byte_arr(self.payload_type, self.payload)
            #self.byte_arr = self._create_packet(self.payload_type, self.payload_data)

            self.valid = True

        # Got payload type, and a payload object. Populate the byte_array
        elif self.payload_type != None and self.payload != None:
            if type(self.payload) != Payload:
                return
            if not self.payload.valid:
                return
                            
            self.byte_arr = self._create_byte_arr(self.payload_type, self.payload)

        # Got a byte_array.  validate the byte_array, and create a packet and data from it.
        elif self.byte_arr != None:
            self.valid = self.create_from_byte_arr(self.byte_arr)

    def _create_byte_arr(self, payload_type, payload):

        header = struct.pack('<BBH',
                             0xAB,
                             payload_type,
                             payload.length)

        header_cksm = bytes([(256 - (sum(header) & 0xFF)) & 0xFF])
        packet = header + header_cksm + payload.byte_arr + bytes([payload.checksum, 0xBA])

        return packet

    def create_from_byte_arr(self, byte_arr):
        self.byte_arr = byte_arr
        valid = self.validate_byte_arr(self.byte_arr)

        if not valid:
            return False
        
        self.payload_type = self.byte_arr[self.PACKET_PAYLOAD_TYPE_OFFSET]

        self.payload_len = struct.unpack_from('<H', self.byte_arr, self.PACKET_PAYLOAD_LEN_OFFSET)[0]
        self.payload_data = self.byte_arr[self.PACKET_PAYLOAD_OFFSET:self.PACKET_PAYLOAD_OFFSET+self.payload_len]
        self.payload = Payload(self.payload_len, self.payload_type, payload_byte_arr=self.payload_data)
        if not self.payload.valid:
            log.error("Payload error: {}".format(self.payload.byte_arr))
            return False
        return True
        

    def validate_byte_arr(self, byte_arr):
        state = "idle"
        packet = []
        data_len = 0
        data_bytes_received = 0
        
        for val in byte_arr:

            log.debug("Got val: {}".format(val))
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
                    log.error("Packet is invalid!")
                    log.error(" ".join(["{:X}".format(val) for val in packet]))
                    state = "idle"
                else:
                    state = "got_checksum"
            elif state == "got_checksum":
                packet.append(val)
                if val == 0xBA:
                    log.debug("Got full packet!")
                    log.debug(" ".join(["{:X}".format(val) for val in packet]))
                    state = "idle"
                    return True
                else:
                    log.error("Well, this is weird...")
                    log.error(" ".join(["{:X}".format(val) for val in packet]))
                    state = "idle"
                    return False
            else:
                state = "idle"
        return False


# TODO: move this functionality into the Pump class
def handle_packet(packet):
    if packet[1] == 0x00: #temperature packet
        temperature = packet[8] * 256 + packet[7]
        print("Temp:  {}".format(temperature))
    elif packet[1] == 0x01: #Level packet
        level = packet[8] * 256 + packet[7]
        print("Level: {}".format(level))

def get_pump_turn_on_level(ser):
    pkt = create_packet([SETTINGS_OP_READ,SETTINGS_TANK_PUMP_TURN_ON_LEVEL,3,3], PACKET_TYPE_SETTINGS)

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

STATUS_OP_READ = 3

STATUS_TEMP_F = 0
STATUS_TANK_LEVEL = 1

# TODO: Add conversions for temp (deg f) and level (in inches)
# TODO: Clean up each of the functions to not repeat so much code.
class Pump(object):
    def __init__(self, ser=None):
        self.ser = ser
        if not ser:
            self.ser = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=0.1)

    def echo(self, data_arr=b'abc'):
        pkt = Packet(payload_type=PAYLOAD_TYPE_ECHO, payload_data=data_arr)
        if not pkt.valid:
            log.error("Packet error: {}".format(pkt.byte_arr))
            return
        self.send_packet(pkt.byte_arr)
        resp_pkt = Packet(byte_arr=self.read_response())
        return resp_pkt.payload_data


    def read_setting(self, setting):
        pkt = Packet(payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_READ, setting, 3, 3]))
        if not pkt.valid:
            log.error("Packet error: {}".format(pkt.byte_arr))
            return
        self.send_packet(pkt.byte_arr)
        resp_pkt = Packet(byte_arr=self.read_response())
        return resp_pkt.payload.value

    def write_setting(self, setting, val):
        pkt = Packet(payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_WRITE, setting, val & 0xFF, (val >> 8) & 0xFF]))
        if not pkt.valid:
            log.error("Packet error: {}".format(pkt.byte_arr))
            return
        self.send_packet(pkt.byte_arr)
        resp_pkt = Packet(byte_arr=self.read_response())
        return resp_pkt.payload.value

    def save_settings_to_eeprom(self, setting=None):
        if setting == None:
            # saving all settings
            pkt = Packet(payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_SAVE, SETTINGS_SAVE_ALL, 0, 0]))
            if not pkt.valid:
                log.error("Packet error: {}".format(pkt.byte_arr))
                return
            self.send_packet(pkt.byte_arr)
            resp_pkt = Packet(byte_arr=self.read_response())
            return resp_pkt.payload.value

        else:
            pkt = Packet(payload_type=PYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_SAVE, SETTINGS_SAVE_ONE, setting & 0xFF, (setting >> 8) & 0xFF]))
            if not pkt.valid:
                log.error("Packet error: {}".format(pkt.byte_arr))
                return
            self.send_packet(pkt.byte_arr)
            resp_pkt = Packet(byte_arr=self.read_response())
            return resp_pkt.payload.value
        
    def load_settings_from_eeprom(self, setting=None):
        if setting == None:
            # load all settings
            pkt = Packet(payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_LOAD, SETTINGS_LOAD_ALL, 0, 0]))
            if not pkt.valid:
                log.error("Packet error: {}".format(pkt.byte_arr))
                return
            self.send_packet(pkt.byte_arr)
            resp_pkt = Packet(byte_arr=self.read_response())
            return resp_pkt.payload.value

        else:
            pkt = Packet(payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_LOAD, SETTINGS_LOAD_ONE, setting & 0xFF, (setting >> 8) & 0xFF]))
            if not pkt.valid:
                log.error("Packet error: {}".format(pkt.byte_arr))
                return
            self.send_packet(pkt.byte_arr)
            resp_pkt = Packet(byte_arr=self.read_response())
            return resp_pkt.payload.value

    def get_status(self, status):
        pkt = Packet(payload_type=PAYLOAD_TYPE_STATUS, payload_data=bytes([STATUS_OP_READ, status, 2, 3]))
        if not pkt.valid:
            log.error("Packet error: {}".format(pkt.byte_arr))
            return
        self.send_packet(pkt.byte_arr)
        resp_pkt = Packet(byte_arr=self.read_response())
        return resp_pkt.payload.value


    def send_packet(self, pkt):
        self.clear_input_buffer()
        self.ser.write(pkt)

    def read_response(self):
        resp_arr = self.ser.read(1000)
        return resp_arr

    def clear_input_buffer(self):
        self.ser.flushInput()


# class Pump_old():
#     def __init__(self, com = None, ser = None):
#         if not com:
#             com = "COM4"
#         if not ser:
#             self.ser = serial.Serial(com, 9600, timeout=0.1)
#         else:
#             self.ser = ser

#     def read_dump(self):
#         print(self.ser.read(1000))

#     def get_data_wait(self, wait_time = 5, retry_time = 1):
#         for i in range(wait_time):
#             if self.get_data() != -1:
#                 return
#             time.sleep(retry_time)
            

#     def write_data(self):
#         #printval = '|'.join(self.valse['val01']
#         print('writing: ', '|'.join(self.data_split))
#         self.ser.write('|'.join(self.data_split))

#     def get_data(self):
#         self.data = self.ser.read(1000)
#         if len(self.data) == 0:
#             print("No Data!")
#             return -1
#         self.data_line = self.data.split("\r\n")
#         if len(self.data_line) > 1:
#             self.data_line = self.data_line[-2]
#         else:
#             self.data_line = self.data_line[0]
#         self.data_split = self.data_line.split('|')
#         if len(self.data_split) != 16:
#             print("Bad Data!")
#             return
#         self.vals = {}
#         self.vals['val01'] = self.data_split[0]
#         self.vals['val02'] = self.data_split[1]
#         self.vals['val03'] = self.data_split[2]
#         self.vals['val04'] = self.data_split[3]
#         self.vals['val05'] = self.data_split[4]
#         self.vals['val06'] = self.data_split[5]
#         self.vals['val07'] = self.data_split[6]
#         self.vals['val08'] = self.data_split[7]
#         self.vals['val09'] = self.data_split[8]
#         self.vals['val10'] = self.data_split[9]
#         self.vals['val11'] = self.data_split[10]
#         self.vals['val12'] = self.data_split[11]
#         self.vals['val13'] = self.data_split[12]
#         self.vals['val14'] = self.data_split[13]
#         self.vals['val15'] = self.data_split[14]
#         self.vals['val16'] = self.data_split[15]
            
        
