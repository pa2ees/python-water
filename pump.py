import logging

log_level = logging.INFO
logging.basicConfig(level=log_level, format = '%(asctime)s  %(levelname)-10s %(name)s %(message)s', datefmt =  "%Y-%m-%d-%H-%M-%S")

log = logging.getLogger(__name__)


import serial, time, struct, math

# TODO: Put these in the proper class instead of global

PAYLOAD_TYPE_ECHO = 0
PAYLOAD_TYPE_SETTINGS = 1
PAYLOAD_TYPE_STATUS = 2

SETTINGS_OP_LOAD = 0
SETTINGS_OP_SAVE = 1
SETTINGS_OP_WRITE = 2
SETTINGS_OP_READ = 3

SETTINGS_LOAD_ALL = 0
SETTINGS_LOAD_ONE = 1

SETTINGS_SAVE_ALL = 0
SETTINGS_SAVE_ONE = 1

SETTINGS_ADDRESS = 0
SETTINGS_TANK_PUMP_TURN_ON_LEVEL = 1
SETTINGS_TANK_PUMP_TURN_OFF_LEVEL = 2

STATUS_OP_WRITE = 2
STATUS_OP_READ = 3


STATUS_TEMP = 0
STATUS_TANK_LEVEL = 1
STATUS_FILLING = 2
STATUS_PUMPING = 3
STATUS_FILLING_VALVE_CURRENT = 4
STATUS_PUMP_CURRENT = 5
STATUS_NUM_OF_STATUSES = 6

STATUS_ERROR = 255

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
            log.debug("Got byte arr")
            if self.length != len(self.byte_arr):
                log.error("Length given ({}) and length of array ({}) do not match!".format(self.length, len(self.byte_arr)))
                return
            if self.pl_type == PAYLOAD_TYPE_SETTINGS or self.pl_type == PAYLOAD_TYPE_STATUS:
                log.debug("Got settings or status payload of length: {}".format(self.length))
                if self.length != 4:
                    log.error("Incorrect array length ({}) for payload type ({})".format(self.length, self.pl_type))
                    return
                self.opcode, self.command, self.value = struct.unpack('<BBH', self.byte_arr)
            self.valid = True

        # compute checksum
        self.checksum = (256 - (sum(self.byte_arr) & 0xFF)) & 0xFF
        

class Packet(object):
    """
    Packet class

    Class for handling packets sent to, and received from, the water controller
    """
    PACKET_START_FLAG_OFFSET = 0
    PACKET_DEST_ADDR_OFFSET = 1
    PACKET_SRC_ADDR_OFFSET = 2
    PACKET_PAYLOAD_LEN_OFFSET = 3
    PACKET_PAYLOAD_TYPE_OFFSET = 5
    PACKET_HEADER_CHECKSUM_OFFSET = 6
    PACKET_PAYLOAD_OFFSET = 7
    
    def __init__(self, dest_addr=None, src_addr=None, payload_type=None, payload=None, payload_data=None, byte_arr=None):
        self.dest_addr = dest_addr
        self.src_addr = src_addr
        self.payload_type = payload_type # this is a byte containing the type of payload
        self.payload_data = payload_data # this is a byte array of all payload data (4 bytes)
        self.byte_arr = byte_arr # this is a byte array of an entire packet
        self.valid = False
        self.payload = payload #this is a Payload object

        #if self.dest_addr != 0x01: # it's not for us!
        #    log.info("This is not for us! It was addressed to {} from {}".format(self.dest_addr, self.src_addr))
        #    return
        
        # we have type and data, construct a Payload object, and populate the byte_array
        if self.payload_type != None and self.payload_data != None:
            self.payload = Payload(len(self.payload_data), self.payload_type, payload_byte_arr=self.payload_data)
            if not self.payload.valid:
                log.error("Payload error: {}".format(self.payload.byte_arr))
                return
            self.byte_arr = self._create_byte_arr(self.dest_addr, self.src_addr, self.payload_type, self.payload)
            #self.byte_arr = self._create_packet(self.payload_type, self.payload_data)

            self.valid = True

        # Got payload type, and a payload object. Populate the byte_array
        elif self.payload_type != None and self.payload != None:
            if type(self.payload) != Payload:
                return
            if not self.payload.valid:
                return
                            
            self.byte_arr = self._create_byte_arr(self.dest_addr, self.src_addr, self.payload_type, self.payload)

        # Got a byte_array.  validate the byte_array, and create a packet and data from it.
        elif self.byte_arr != None:
            self.valid = self.create_from_byte_arr(self.byte_arr)

    def _create_byte_arr(self, dest_addr, src_addr, payload_type, payload):

        header = struct.pack('<BBBHB',
                             0xAB,
                             dest_addr,
                             src_addr,
                             payload.length,
                             payload_type)

        header_cksm = bytes([(256 - (sum(header) & 0xFF)) & 0xFF])
        packet = header + header_cksm + payload.byte_arr + bytes([payload.checksum, 0xBA])

        return packet

    def create_from_byte_arr(self, byte_arr):
        self.byte_arr = byte_arr
        valid = self.validate_byte_arr(self.byte_arr)

        if not valid:
            return False
        
        self.dest_addr = struct.unpack_from('<B', self.byte_arr, self.PACKET_DEST_ADDR_OFFSET)[0]
        self.src_addr = struct.unpack_from('<B', self.byte_arr, self.PACKET_SRC_ADDR_OFFSET)[0]
        self.payload_len = struct.unpack_from('<H', self.byte_arr, self.PACKET_PAYLOAD_LEN_OFFSET)[0]
        self.payload_type = struct.unpack_from('<B', self.byte_arr, self.PACKET_PAYLOAD_TYPE_OFFSET)[0]
        log.debug("Payload Type: {}".format(self.payload_type))
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
                packet.append(val) # appended destination address
                state = "got_dest_addr"
            elif state == "got_dest_addr":
                packet.append(val) # appended source address
                state = "got_src_addr"
            elif state == "got_src_addr":
                packet.append(val) # appended length low byte
                state = "got_length_l"        
            elif state == "got_length_l":
                data_len = (val * 256) + packet[-1]
                packet.append(val) # appended length high byte
                state = "got_length_h"

            elif state == "got_length_h":
                packet.append(val) # appended payload type
                state = "got_payload_type"

            elif state == "got_payload_type":
                packet.append(val) # appended header checksum
                if sum(packet) & 0xFF != 0x00:
                    print("Packet Header is invalid!")
                    print(" ".join(["{:X}".format(val) for val in packet]))
                    state = "idle"
                else:
                    state = "got_header_checksum"
            elif state == "got_header_checksum":
                packet.append(val) # appended payload byte
                data_bytes_received += 1
                if data_bytes_received >= data_len:
                    state = "got_payload"
            elif state == "got_payload":
                packet.append(val) # appended checksum
                if sum(packet) & 0xFF != 0x00:
                    log.error("Packet is invalid!")
                    log.error(" ".join(["{:X}".format(val) for val in packet]))
                    state = "idle"
                else:
                    state = "got_checksum"
            elif state == "got_checksum":
                packet.append(val) # appended end byte
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


# TODO: Clean up each of the functions to not repeat so much code.
class Pump(object):

    TANK_MIN_LEVEL_OFFSET=200 # level value offset with atmospheric pressure (ie no water)
    VTEMP_OFFSET=500 # temperature value offset at 0 degrees
    
    def __init__(self, addr=0x01, src_addr=0x00, ser=None):
        self.ser = ser
        self.addr = addr
        self.src_addr = src_addr
        if not ser:
            self.ser = serial.Serial("/dev/ttyUSB0", baudrate=57600, timeout=0.1)

    def echo(self, src_addr=0x00, data_arr=b'abc'):
        if src_addr == 0x00:
            src_addr = self.src_addr
        pkt = Packet(dest_addr=self.addr, src_addr=src_addr, payload_type=PAYLOAD_TYPE_ECHO, payload_data=data_arr)
        resp_pkt = self._send_and_receive_packet(pkt)
        return resp_pkt.payload_data

    #### Helper functions ####

    def read_curr_temp(self):
        resp_pkt = self.read_status(STATUS_TEMP)
        return self._conv_temp_to_f(resp_pkt.payload.value)

    def read_tank_level(self):
        resp_pkt = self.read_status(STATUS_TANK_LEVEL)
        return self._conv_tank_level_to_inches(resp_pkt.payload.value)

    def read_filling(self):
        resp_pkt = self.read_status(STATUS_FILLING)
        return resp_pkt.payload.value

    def read_pumping(self):
        resp_pkt = self.read_status(STATUS_PUMPING)
        return resp_pkt.payload.value

    def read_filling_valve_current(self):
        resp_pkt = self.read_status(STATUS_FILLING_VALVE_CURRENT)
        return resp_pkt.payload.value

    def read_pump_current(self):
        resp_pkt = self.read_status(STATUS_PUMP_CURRENT)
        return resp_pkt.payload.value

    def filling_tanks_on(self):
        resp_pkt = self.write_status(STATUS_FILLING, 1)
        if resp_pkt.payload.value == 1:
            print("Tanks are now filling")
        else:
            print("Failed to start filling tanks, response was: {}".format(resp_pkt.payload.value))

    def filling_tanks_off(self):
        resp_pkt = self.write_status(STATUS_FILLING, 0)
        if resp_pkt.payload.value == 0:
            print("Tanks are now NOT filling")
        else:
            print("Failed to stop filling, response was: {}".format(resp_pkt.payload.value))
            
    def pumping_on(self):
        resp_pkt = self.write_status(STATUS_PUMPING, 1)
        if resp_pkt.payload.value == 1:
            print("Pump is now on")
        else:
            print("Failed to turn on pump, response was: {}".format(resp_pkt.payload.value))

    def pumping_off(self):
        resp_pkt = self.write_status(STATUS_PUMPING, 0)
        if resp_pkt.payload.value == 0:
            print("Pump is now off")
        else:
            print("Failed to turn off pump, response was: {}".format(resp_pkt.payload.value))


    def read_setting_address(self):
        resp_pkt = self.read_setting(SETTINGS_ADDRESS)
        return resp_pkt.payload.value

    def read_setting_tank_pump_turn_on_level(self):
        resp_pkt = self.read_setting(SETTINGS_TANK_PUMP_TURN_ON_LEVEL)
        return self._conv_tank_level_to_inches(resp_pkt.payload.value)

    def read_setting_tank_pump_turn_off_level(self):
        resp_pkt = self.read_setting(SETTINGS_TANK_PUMP_TURN_OFF_LEVEL)
        return self._conv_tank_level_to_inches(resp_pkt.payload.value)

    def write_setting_address(self, address):
        log.warning("Setting new address! Further communication with this node must use new address!")
        resp_pkt = self.write_setting(SETTINGS_ADDRESS, address)
        if resp_pkt.payload.value == address:
            print("Setting address succesful! Remember to save to eeprom!")
        else:
            print("Setting address failed!")

    def write_setting_tank_pump_turn_on_level(self, inches):
        tank_level = self._conv_inches_to_tank_level(inches)
        if tank_level < self.TANK_MIN_LEVEL_OFFSET:
            tank_level = self.TANK_MIN_LEVEL_OFFSET
        log.info("Setting turn on level to {}".format(tank_level))
        resp_pkt = self.write_setting(SETTINGS_TANK_PUMP_TURN_ON_LEVEL, tank_level)
        if resp_pkt.payload.value == tank_level:
            print("Setting 'turn on level' programmed successfully!")
        else:
            print("Setting 'turn on level' programming failed!")

    def write_setting_tank_pump_turn_off_level(self, inches):
        tank_level = self._conv_inches_to_tank_level(inches)
        if tank_level < self.TANK_MIN_LEVEL_OFFSET:
            tank_level = self.TANK_MIN_LEVEL_OFFSET
        log.info("Setting turn off level to {}".format(tank_level))
        resp_pkt = self.write_setting(SETTINGS_TANK_PUMP_TURN_OFF_LEVEL, tank_level)
        if resp_pkt.payload.value == tank_level:
            print("Setting 'turn off level' programmed successfully!")
        else:
            print("Setting 'turn off level' programming failed!")

    
    def load_all_settings_from_eeprom(self):
        self.load_settings_from_eeprom()

    def save_all_settings_to_eeprom(self):
        self.save_settings_to_eeprom()

    def _conv_temp_to_f(self, temp):
        temp_f = round(((temp - self.VTEMP_OFFSET) / 10.0)*(9.0/5.0) + 32)
        return temp_f
    
    def _conv_tank_level_to_inches(self, tank_level):
        tank_level_in = round((tank_level - self.TANK_MIN_LEVEL_OFFSET) / 45 * 4)
        return tank_level_in

    def _conv_inches_to_tank_level(self, inches):
        tank_level = round((inches / 4 * 45) + self.TANK_MIN_LEVEL_OFFSET)
        return tank_level

    #### Fundamental Functions ####

    def read_setting(self, setting):
        pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_READ, setting, 3, 3]))
        resp_pkt = self._send_and_receive_packet(pkt)
        log.debug("Resp_pkt: {}".format(resp_pkt))
        return resp_pkt

    def write_setting(self, setting, val):
        pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_WRITE, setting, val & 0xFF, (val >> 8) & 0xFF]))
        resp_pkt = self._send_and_receive_packet(pkt)
        return resp_pkt

    def save_settings_to_eeprom(self, setting=None):
        if setting == None:
            # saving all settings
            pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_SAVE, SETTINGS_SAVE_ALL, 0, 0]))
            resp_pkt = self._send_and_receive_packet(pkt)
            return resp_pkt

        else:
            pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_SAVE, SETTINGS_SAVE_ONE, setting & 0xFF, (setting >> 8) & 0xFF]))
            resp_pkt = self._send_and_receive_packet(pkt)
            return resp_pkt
        
    def load_settings_from_eeprom(self, setting=None):
        if setting == None:
            # load all settings
            pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_LOAD, SETTINGS_LOAD_ALL, 0, 0]))
            resp_pkt = self._send_and_receive_packet(pkt)
            return resp_pkt

        else:
            pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_SETTINGS, payload_data=bytes([SETTINGS_OP_LOAD, SETTINGS_LOAD_ONE, setting & 0xFF, (setting >> 8) & 0xFF]))
            resp_pkt = self._send_and_receive_packet(pkt)
            return resp_pkt

    def read_status(self, status):
        pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_STATUS, payload_data=bytes([STATUS_OP_READ, status, 2, 3]))
        resp_pkt = self._send_and_receive_packet(pkt)
        return resp_pkt

    def write_status(self, status, value):
        pkt = Packet(dest_addr=self.addr, src_addr=self.src_addr, payload_type=PAYLOAD_TYPE_STATUS, payload_data=bytes([STATUS_OP_WRITE, status, value & 0xFF, (value >> 8) & 0xFF]))
        resp_pkt = self._send_and_receive_packet(pkt)
        if resp_pkt.payload.command == STATUS_ERROR:
            print("Node had an error handling packet")
        return resp_pkt

    def _send_and_receive_packet(self, pkt):
        if not pkt.valid:
            log.error("Packet error: {}".format(pkt.byte_arr))
            return
        self.send_packet(pkt.byte_arr)
        resp_pkt = Packet(byte_arr=self.read_response())
        log.debug("Got Packet from address {}".format(resp_pkt.src_addr))
        return resp_pkt        

    def send_packet(self, pkt):
        self.clear_input_buffer()
        self.ser.write(pkt)

    def read_response(self):
        resp_arr = self.ser.read(1000)
        log.debug("{}".format(resp_arr))
        return resp_arr

    def clear_input_buffer(self):
        self.ser.flushInput()


