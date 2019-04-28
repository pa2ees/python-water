import logging

log_level = logging.INFO
logging.basicConfig(level=log_level, format = '%(asctime)s  %(levelname)-10s %(name)s %(message)s', datefmt =  "%Y-%m-%d-%H-%M-%S")

log = logging.getLogger(__name__)

from waternode import *

import time
import socket, selectors, os
import queue

class WaterController(object):
    SOCK_NAME = './state_sockets/test_sock'
    SOCK_ADDR = ('localhost', 12346)

    def __init__(self):
        # get serial
        try:
            self.ser = serial.Serial('/dev/ttyUSB0', baudrate=9600, timeout=0.1)
        except serial.SerialException:
            pass
        try:
            self.ser = serial.Serial('/dev/ttyUSB1', baudrate=9600, timeout=0.1)
        except serial.SerialException:
            log.error("Could not open serial ports!")
            return

        # initialize nodes
        self.sprinkler_pump = WaterNode(addr=1, ser=self.ser)
        self.tank_monitor = self.sprinkler_pump
        self.tank_filler = WaterNode(addr=4, ser=self.ser)

        self.q = queue.Queue()

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.tank_high_thresh = 75
        self.tank_low_thresh = 40 #half full
        self.tank_level = 0

        self.filling_tanks = False

        self.sprinkler_pumping = False

        self.sprinkler_stations = []
        self.sprinkler_stations_on = []
        


        if os.path.exists(self.SOCK_NAME):
            os.remove(self.SOCK_NAME)

        self.sock.bind(self.SOCK_NAME)
        

        self.sock.setblocking(False)


        self.sock.listen(1)

        self.sel = selectors.DefaultSelector()

        self.sel.register(self.sock, selectors.EVENT_READ, self.socket_accept)

    def socket_accept(self, sock, mask):
        conn, addr = sock.accept()
        log.info("accepted {} from {}".format(conn, addr))
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.socket_read)

    def socket_read(self, conn, mask):
        data = conn.recv(1024)
        if data:
            log.info("Got message: {}".format(data))
            return_message = self.handle_message(data)
            if return_message:
                conn.send(return_message)

        else:
            log.info("Closing connection {}".format(conn))
            self.sel.unregister(conn)
            conn.close()

    def select(self):
        return self.sel.select(timeout=0.5)

    def handle_message(self, msg):

        if not msg:
            return False
        
        if msg == b'fill_tanks':
            self.filling_tanks = True

        elif msg == b'stop_filling_tanks':
            self.filling_tanks = False

        elif msg == b'get_filling_tanks':
            if self.filling_tanks:
                return b"filling_tanks"
            return b"not_filling_tanks"

        elif msg == b'get_sprinkler_pumping':
            if self.sprinkler_pumping:
                return b"sprinkler_pumping"
            return b"not_sprinkler_pumping"

        return False
                


    def run_server(self):
        filling = False
        self.already_filling = False

        count = 0

        while True:

            log.debug("Getting events...")
            events = self.sel.select(timeout=0.5)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

            log.debug("Getting tank level...")
            tank_level = self.tank_monitor.get_tank_level()
            if tank_level == None:
                log.error("Couldn't get tank level.")
                continue
            self.tank_level = tank_level

            log.debug("Getting filling status...")
            currently_filling = self.tank_filler.get_valve_state()
            if currently_filling == None:
                log.error("Couldn't get filling state.")
                continue

            log.debug("Getting sprinkling status...")
            currently_sprinkling = self.sprinkler_pump.get_valve_state()
            if currently_sprinkling == None:
                log.error("Couldn't get sprinkling state.")

            if self.filling_tanks and tank_level >= self.tank_high_thresh:
                self.filling_tanks = False

            if not self.filling_tanks and tank_level <= self.tank_low_thresh:
                self.filling_tanks = True


            log.debug("Check if wanting to fill tanks...")
            if self.filling_tanks:
                log.debug("We are filling tanks... do stuff")
                # we are trying to fill the tanks
                time_since_last_turn_off = time.time() - self.tank_filler.get_last_valve_turn_off_time()
                if currently_filling or time_since_last_turn_off > 10:
                    # either we are currently filling, or our last turn off was a while ago (to prevent rapid cycling)
                    self.tank_filler.set_valve_on()
                if time_since_last_turn_off <= 10:
                    log.info("Waiting to not rapic cycle valve")

            log.debug("Check if wanting to sprinkle...")
            if self.sprinkler_pumping:
                log.debug("We are sprinkling... do stuff")
                time_since_last_turn_off = time.time() - self.sprinkler_pump.get_last_valve_turn_off_time()
                if currently_sprinkling or time_since_last_turn_off > 60:
                    # either we are currently sprinkling, or our last turn off was over a minute ago (to prevent rapid cycling)
                    self.sprinkler_pump.set_valve_on()
                if time_since_last_turn_off <= 60:
                    log.info("Waiting to not rapic cycle valve")

            count += 1
            if count > 10:
                count = 0
                log.info("Tank Level: {}".format(self.tank_level))
                log.info("Filling: {}".format(self.filling_tanks))

        

if __name__ == '__main__':
    # wc = WaterController()
    # wc.run_server()
    pass
