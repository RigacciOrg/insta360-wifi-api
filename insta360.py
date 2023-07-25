# -*- coding: utf-8 -*-
"""
Operate an Insta360 camera through a TCP socket.

A simple TCP client to connect to an Insta360 camera through the
TCP/6666 port over WiFi. It is based on a partial reverse
engineering of the protocol used by the Android app. That
undocumented protocol uses messages serialized using the Google
Protocol Buffers, plus a 12 bytes header.

To run this program you need the protobuf definition language
(the *.proto files) which can be extracted from a binary
compiled file. The Android app Insta360_v1.42.1.apk has the
protobuf definition into the libOne.so library; you need a
special tool to extract the files.

This program requires also the Google Proto Buffers Python
library; you may install it with:

  pip3 install protobuf

This program does asyncronous communication: when an instance of
the insta360.camera() class is instantiated, a background thread
collects data arriving on the TCP socket, assembling and parsing
Insta360 messages. The main thread may call the varius methods
of the class to do actions, like insta360.camera.StartCapture(),
etc.

This program is little more than a proof-of-concept: only some
methods are implemented and they do not accept many parameters.

Web References:

  https://www.geeksforgeeks.org/python-daemon-threads/
  https://docs.python.org/3/library/threading.html
  https://superfastpython.com/lock-vs-semaphore-in-python/
  https://betterprogramming.pub/how-to-poll-sockets-using-python-3e1af3b047
  https://protobuf.dev/reference/python/

"""

import logging
import select
import signal
import socket
import struct
import sys
import time
import threading

from google.protobuf import json_format
sys.path.append('pb2')
import capture_state_pb2
import current_capture_status_pb2
import error_pb2
import get_current_capture_status_pb2
import get_file_list_pb2
import get_options_pb2
import get_photography_options_pb2
import options_pb2
import photo_pb2
import set_options_pb2
import set_photography_options_pb2
import start_capture_pb2
import start_live_stream_pb2
import stop_capture_pb2
import stop_live_stream_pb2
import storage_pb2
import storage_update_pb2
import take_picture_pb2
import video_pb2

__author__ = "Niccolo Rigacci"
__copyright__ = "Copyright 2023 Niccolo Rigacci <niccolo@rigacci.org>"
__license__ = "GPLv3-or-later"
__email__ = "niccolo@rigacci.org"
__version__ = "0.1.0"


def bytes_to_hexascii(bytes_string):
    """ Convert a bytearray or bytes into a printable string of hex codes and ASCII """
    hex_ascii_string = ''
    ascii_ranges = [(' ', '&'), ('(', '['), (']', '~')]
    for i in range(0, len(bytes_string)):
        b = bytes_string[i]
        is_ascii = False
        for r in ascii_ranges:
            if b >= ord(r[0]) and b <= ord(r[1]):
                hex_ascii_string += chr(b)
                is_ascii = True
                break
        if not is_ascii:
            hex_ascii_string += '\\x%02x' % (b)
    return hex_ascii_string


def bytes_to_hex(bytes_string):
    """ Convert a bytearray or bytes into a string of hex codes """
    hex_string = ''
    for i in range(0, len(bytes_string)):
        b = bytes_string[i]
        hex_string += '\\x%02x' % (b)
    return hex_string


def protobuf_to_dict(message, response_code=None, message_code=None):
    """ Convert a protobuf message into a Python dictionary """
    msg =json_format.MessageToDict(message, including_default_value_fields=True)
    msg['response_code'] = response_code
    msg['message_code'] = message_code
    return msg


class camera:

    # Socket timing parameters.
    SOCKET_TIMEOUT_SEC = 5.0           # Default timeout for the socket
    PKT_COMPLETE_TIMEOUT_SEC = 4.0     # Timeout for receiving a complete data packet

    KEEPALIVE_INTERVAL_SEC = 2.0
    IS_CONNECTED_TIMEOUT_SEC = 10.0
    RECONNECT_TIMEOUT_SEC = 30.0

    PKT_SYNC =      bytearray(b'\x06\x00\x00syNceNdinS')
    PKT_KEEPALIVE = bytearray(b'\x05\x00\x00')

    PHONE_COMMAND_BEGIN = 0
    PHONE_COMMAND_START_LIVE_STREAM = 1
    PHONE_COMMAND_STOP_LIVE_STREAM = 2
    PHONE_COMMAND_TAKE_PICTURE = 3
    PHONE_COMMAND_START_CAPTURE = 4
    PHONE_COMMAND_STOP_CAPTURE = 5
    PHONE_COMMAND_CANCEL_CAPTURE = 6
    PHONE_COMMAND_SET_OPTIONS = 7
    PHONE_COMMAND_GET_OPTIONS = 8
    PHONE_COMMAND_SET_PHOTOGRAPHY_OPTIONS = 9
    PHONE_COMMAND_GET_PHOTOGRAPHY_OPTIONS = 10
    PHONE_COMMAND_GET_FILE_EXTRA = 11
    PHONE_COMMAND_DELETE_FILES = 12
    PHONE_COMMAND_GET_FILE_LIST = 13
    PHONE_COMMAND_GET_CURRENT_CAPTURE_STATUS = 15

    RESPONSE_CODE_OK = 200
    RESPONSE_CODE_ERROR = 500

    CAMERA_NOTIFICATION_BATTERY_LOW = 8196
    CAMERA_NOTIFICATION_STORAGE_UPDATE = 8198
    CAMERA_NOTIFICATION_STORAGE_FULL = 8199
    CAMERA_NOTIFICATION_CAPTURE_STOPPED = 8201;
    CAMERA_NOTIFICATION_CURRENT_CAPTURE_STATUS = 8208

    # For each message code there is a specific protobuf message class.
    pb_msg_class = {
        PHONE_COMMAND_SET_OPTIONS: set_options_pb2.SetOptions(),
        PHONE_COMMAND_SET_OPTIONS: set_options_pb2.SetOptions(),
        PHONE_COMMAND_GET_OPTIONS: get_options_pb2.GetOptions(),
        PHONE_COMMAND_TAKE_PICTURE: take_picture_pb2.TakePicture(),
        PHONE_COMMAND_GET_FILE_LIST: get_file_list_pb2.GetFileList(),
        PHONE_COMMAND_SET_PHOTOGRAPHY_OPTIONS: set_photography_options_pb2.SetPhotographyOptions(),
        PHONE_COMMAND_GET_PHOTOGRAPHY_OPTIONS: get_photography_options_pb2.GetPhotographyOptions(),
        PHONE_COMMAND_START_CAPTURE: start_capture_pb2.StartCapture(),
        PHONE_COMMAND_STOP_CAPTURE: stop_capture_pb2.StopCapture(),
        PHONE_COMMAND_START_LIVE_STREAM: start_live_stream_pb2.StartLiveStream(),
        PHONE_COMMAND_STOP_LIVE_STREAM: stop_live_stream_pb2.StopLiveStream(),
        PHONE_COMMAND_GET_CURRENT_CAPTURE_STATUS: get_current_capture_status_pb2.CameraCaptureStatus()
    }

    def __init__(self, host='192.168.42.1', port=6666, logger=None, callback=None):
        self.connect_host = host
        self.connect_port = port
        if logger is None:
            self.logger = logging.getLogger(None)
        else:
            self.logger = logger
        self.callback_handler = callback
        self.camera_socket = None
        self.timer_keepalive = None
        self.message_seq = 0
        self.sent_messages_codes = {}
        self.rcv_thread = None
        self.rcv_buffer = b''
        self.socket_lock = None
        self.is_connected = False
        self.reconnect_time = time.time()
        self.last_pkt_sent_time = time.time()
        self.last_pkt_recv_time = time.time()
        self.program_killed = False
        signal.signal(signal.SIGTERM, self.SignalHandler)
        signal.signal(signal.SIGINT, self.SignalHandler)
        # Enable async receiving function.
        self.rcv_thread = threading.Thread(target=self.receive_packet, daemon=True)
        self.rcv_thread.start()


    def SignalHandler(self, signum, frame):
        self.logger.info('Received signal %d, exiting' % (signum,))
        self.program_killed = True
        self.Close()
        sys.exit(signum)


    def Open(self):
        """ Open a TCP socket to the camera """
        self.Close()
        self.reconnect_time = time.time()
        self.logger.info('Connecting socket to host %s:%d' % (self.connect_host, self.connect_port))
        try:
            self.camera_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.camera_socket.settimeout(self.SOCKET_TIMEOUT_SEC)
            self.camera_socket.connect((self.connect_host, self.connect_port))
            self.logger.debug('Socket opened')
        except Exception as ex:
            self.logger.error('Exception in socket.connect(): %s' % (ex,))
            self.camera_socket = None
        if not self.program_killed:
            # Mutex lock for socket send/receive.
            self.socket_lock = threading.Lock()
            # Send the first packets.
            self.send_packet(self.PKT_SYNC)
            self.send_packet(self.PKT_KEEPALIVE)
            self.SyncLocalTimeToCamera()
            # Enable async timers.
            self.timer_keepalive = self.KeepAliveTimer(self.KEEPALIVE_INTERVAL_SEC, self.KeepAlive)
            self.timer_keepalive.start()


    def Close(self):
        """ Stop the keep alive timer and close the TCP socket """
        self.logger.debug('Stopping keepalive timer and closing socket')
        if self.timer_keepalive is not None:
            self.timer_keepalive.cancel()
            self.timer_keepalive = None
        if self.camera_socket is not None:
            self.camera_socket.shutdown(socket.SHUT_RDWR)
            self.camera_socket.close()
            self.camera_socket = None
        self.is_connected = False
        self.message_seq = 0
        self.sent_messages_codes = {}


    class KeepAliveTimer(threading.Timer):
        """ Timer to call the KeepAlive function """
        def run(self):
            while not self.finished.wait(self.interval):
                self.function(*self.args, **self.kwargs)


    def SendMessage(self, message, message_code):
        """ Convert a dictionary into a protobuf message and send it """
        with self.socket_lock:
            seq_number = self.message_seq
            self.message_seq += 1
        protobuf_msg = self.pb_msg_class[message_code]
        proto_module = protobuf_msg.__class__.__module__
        proto_name = protobuf_msg.__class__.__name__
        self.logger.info('Sending message #%d: "%s.%s()"' % (seq_number, proto_module, proto_name))
        self.sent_messages_codes[seq_number] = message_code
        try:
            json_format.ParseDict(message, protobuf_msg)
            header  = b'\x04\x00\x00'
            header += message_code.to_bytes(2, 'little')
            header += b'\x02'
            header += struct.pack('<i', seq_number)[0:3]
            header += b'\x80\x00\x00'
            packet = header + protobuf_msg.SerializeToString()
            self.send_packet(packet)
        except Exception as ex:
            self.logger.error('Exception in SendMessage(): %s' % (ex,))
            del self.sent_messages_codes[seq_number]
        return seq_number


    def KeepAlive(self):
        """ Keep the TCP socket alive sending packets regularly """
        if self.is_connected:
            if (time.time() - self.last_pkt_recv_time) > self.IS_CONNECTED_TIMEOUT_SEC:
                self.logger.info('Timeout expecting packet: assuming disconnected')
                self.is_connected = False
            elif (time.time() - self.last_pkt_sent_time) > self.KEEPALIVE_INTERVAL_SEC:
                self.logger.debug('Sending KeepAlive')
                self.send_packet(self.PKT_KEEPALIVE)
                self.last_pkt_sent_time = time.time()
        else:
            # Try a new connection.
            if time.time() - self.reconnect_time > self.RECONNECT_TIMEOUT_SEC:
                self.logger.info('KeepAlive: Not connected: trying re-connect')
                self.Open()


    def parse_protobuf_message(self, message_class, message_bytes):
        """ Parse a protobuf message using the given class """
        proto_module = message_class.__class__.__module__
        proto_name = message_class.__class__.__name__
        try:
            message = message_class
            message.ParseFromString(message_bytes)
            self.logger.info('Parsed protobuf message "%s.%s()":\n%s' % (proto_module, proto_name, message))
        except:
            self.logger.error('Cannot parse message as "%s.%s()"' % (proto_module, proto_name))
            message = None
        return message


    def send_packet(self, pkt_payload):
        """ Send pkt_data (bytearray) to the socket, prepending the overall length """
        if self.camera_socket is not None:
            pkt_data = bytearray(struct.pack('<i', len(pkt_payload) + 4))
            pkt_data.extend(pkt_payload)
            self.logger.info("Sending packet: b'%s%s'" % (bytes_to_hex(pkt_payload[:12]), bytes_to_hexascii(pkt_payload[12:])))
            self.socket_send(pkt_data)
            time.sleep(0.1) # Actually 0.02 should suffice.


    def socket_send(self, pkt_data):
        """ Send the bytearray pkt_data to socket, return False on error """
        try:
            with self.socket_lock:
                self.camera_socket.sendall(pkt_data)
        except Exception as ex:
            self.logger.error('Exception in socket.sendall(): %s' % (ex,))
            return False
        return True


    def receive_packet(self):
        """ Receive data from socket and assemble full packets """
        # Wait for the main thread to eventually open the socket.
        time.sleep(0.12)
        # Start an infinite loop to receive packets.
        while True:
            self.logger.debug('Loop receive_packet() thread')
            if self.camera_socket is None:
                time.sleep(1.0)
                continue
            pkt_len = None
            pkt_data = b''
            t0 = time.time()
            poller = select.poll()
            poller.register(self.camera_socket, select.POLLIN)
            # Loop waiting a packet to be complete.
            while True:
                self.logger.debug("Receiving buffer: b'%s'" % (bytes_to_hexascii(self.rcv_buffer,)))
                if pkt_len is None and len(self.rcv_buffer) >= 4:
                    pkt_len = int.from_bytes(self.rcv_buffer[0:4], byteorder='little')
                    self.logger.debug('Received begin of packet, length = %d' % (pkt_len,))
                if pkt_len is not None and len(self.rcv_buffer) >= pkt_len:
                    self.logger.debug('Packet is complete, len(rcv_buffer): %s' % (len(self.rcv_buffer,)))
                    pkt_data = self.rcv_buffer[4:pkt_len]
                    self.rcv_buffer = self.rcv_buffer[pkt_len:]
                    break
                # Packet is not complete wait data from the socket.
                try:
                    self.logger.debug('Polling socket for data')
                    evts = poller.poll(int(self.PKT_COMPLETE_TIMEOUT_SEC * 1000))
                    for sock, evt in evts:
                        if evt and select.POLLIN:
                            if self.camera_socket is not None and sock == self.camera_socket.fileno():
                                self.rcv_buffer += self.camera_socket.recv(4096)
                except Exception as ex:
                    self.logger.error('Exception in receive_packet(): %s' % (ex,))
                if time.time() - t0 > self.PKT_COMPLETE_TIMEOUT_SEC:
                    self.logger.warning("Timeout in receive_packet(). Discarding buffer: b'%s'" % (bytes_to_hexascii(self.rcv_buffer),))
                    break
            # The packet is complete or receiving complete packet timeout.
            self.parse_packet(pkt_data)



    def parse_packet(self, pkt_data):
        """ Parse a received packet: header and protobuf body """
        if len(pkt_data) == 0:
            return
        self.last_pkt_recv_time = time.time()
        if pkt_data == self.PKT_SYNC:
            self.is_connected = True
            return
        if pkt_data == self.PKT_KEEPALIVE:
            return
        if len(pkt_data) < 12:
            return

        header = pkt_data[:12]
        body = pkt_data[12:]
        self.logger.info("Received packet: b'%s%s'" % (bytes_to_hex(header), bytes_to_hexascii(body)))
        # Responses to messages (header is [:10], protobuf is at [12:])
        # b'\x04\x00\x00\xc8\x00\x02\x1d\x00\x00\x80\x00\x00'  # GetOptionsResp 'LOCAL_TIME', 'TIME_ZONE'
        # b'\x04\x00\x00\xc8\x00\x02\x1e\x00\x00\x80\x3f\x00'  # GetOptionsResp BATTERY_STATUS, STORAGE_STATE, CAMERA_TYPE, FIRMWAREREVISION
        # b'\x04\x00\x00\xc8\x00\x02\x1f\x00\x00\x80\x00\x00'  # GetFileList
        # Response seq = 3 with error message:
        # b'\x04\x00\x00\xf4\x01\x02\x03\x00\x00\x80\x00\x00\x12\x0fcamera is busy.'
        # Response seq = 5 with error message:
        # b'\x04\x00\x00\xf4\x01\x02\x05\x00\x00\x80\x00\x0b\x12\x10msg execute err.'
        # Message out of sequence number: code = \x10\x20 = 8208 = CAMERA_NOTIFICATION_CURRENT_CAPTURE_STATUS
        # b'\x04\x00\x00\x10\x20\x02\xff\x8a\x43\xf4\x00\x00\x08\x01\x10\x00\x1a\x00'

        body = pkt_data[12:]
        response_type   = pkt_data[0:3] # b'\x04\x00\x00'
        # Response code:
        #  b'\xc8\x00' = 200  = OK
        #  b'\xf4\x01' = 500  = ERROR
        #  b'\x10\x20' = 8208 = CAMERA_NOTIFICATION_CURRENT_CAPTURE_STATUS
        response_code   = struct.unpack('<H', pkt_data[3:5])[0]
        unknown_1       = pkt_data[5:6]     # b'\x02'
        # Sequence number: 24 bit unsigned int, the same of the request packet.
        response_seq    = struct.unpack('<I', pkt_data[6:9] + b'\x00')[0]
        unknown_2       = pkt_data[9:10]    # b'\x80'
        unknown_3       = pkt_data[10:11]   # 3f, bf, 63, 00, 40, 41, 76, 58, 31
        unknown_4       = pkt_data[11:12]   # 00, ee, ff, 85, 6b, d8, d0, f4, 5c, 0b, 34

        self.logger.info("Received message: type: b'%s', code: %d, seq: %d" % (bytes_to_hex(response_type), response_code, response_seq))

        if response_code == self.RESPONSE_CODE_ERROR:
            message = self.parse_protobuf_message(error_pb2.Error(), body)
            if message is not None:
                err_message = message.message
                err_code = error_pb2.Error.ErrorCode.Name(message.code)
                self.logger.error('Message #%d raised %s "%s"' % (response_seq, err_code, err_message))
            if response_seq in self.sent_messages_codes:
                del self.sent_messages_codes[response_seq]
            return

        # TODO: Handle the CAMERA_NOTIFICATION_CAPTURE_STOPPED response code (SD full, etc.)

        if response_code == self.CAMERA_NOTIFICATION_CURRENT_CAPTURE_STATUS:
            message = self.parse_protobuf_message(current_capture_status_pb2.CaptureStatus(), body)
            if message is not None:
                msg_state = capture_state_pb2.CameraCaptureState.Name(message.state)
                msg_time = message.capture_time
                self.logger.info('Capture state notification: %s, time: %d' % (msg_state, msg_time))
                if self.callback_handler is not None:
                    self.callback_handler(protobuf_to_dict(message, response_code=response_code))
            return

        if response_code == self.CAMERA_NOTIFICATION_STORAGE_UPDATE:
            message = self.parse_protobuf_message(storage_update_pb2.NotificationCardUpdate(), body)
            if message is not None:
                msg_state = storage_pb2.CardState.Name(message.state)
                msg_location = storage_pb2.CardLocation.Name(message.location)
                self.logger.info('Storage update notification: %s, location: %s' % (msg_state, msg_location))
            return

        # If response sequence is not into the sent list, do not parse the response.
        if response_seq not in self.sent_messages_codes:
            return

        # Parse the protobuf message using the proper message type.
        sent_msg_code = self.sent_messages_codes[response_seq]
        sent_msg_class = self.pb_msg_class[sent_msg_code]
        proto_module = sent_msg_class.__class__.__module__
        proto_name = sent_msg_class.__class__.__name__
        self.logger.info('Received response #%d to message "%s.%s()"' % (response_seq, proto_module, proto_name))

        message = None
        if sent_msg_code == self.PHONE_COMMAND_GET_OPTIONS:
            message = self.parse_protobuf_message(get_options_pb2.GetOptionsResp(), body)
            # TODO: Save some options into self object properties.
        elif sent_msg_code == self.PHONE_COMMAND_SET_OPTIONS:
            message = self.parse_protobuf_message(set_options_pb2.SetOptionsResp(), body)
        elif sent_msg_code == self.PHONE_COMMAND_GET_FILE_LIST:
            message = self.parse_protobuf_message(get_file_list_pb2.GetFileListResp(), body)
        elif sent_msg_code == self.PHONE_COMMAND_STOP_CAPTURE:
            message = self.parse_protobuf_message(stop_capture_pb2.StopCaptureResp(), body)
        elif sent_msg_code == self.PHONE_COMMAND_TAKE_PICTURE:
            message = self.parse_protobuf_message(take_picture_pb2.TakePictureResponse(), body)
        elif sent_msg_code == self.PHONE_COMMAND_GET_PHOTOGRAPHY_OPTIONS:
            message = self.parse_protobuf_message(get_photography_options_pb2.GetPhotographyOptionsResp(), body)
        elif sent_msg_code == self.PHONE_COMMAND_GET_CURRENT_CAPTURE_STATUS:
            message = self.parse_protobuf_message(get_current_capture_status_pb2.GetCurrentCaptureStatusResp(), body)

        # Remove the sequence number from the dictionary of sent messages.
        del self.sent_messages_codes[response_seq]

        # Execute the callback function to notify the received message.
        if message is not None and self.callback_handler is not None:
            self.callback_handler(protobuf_to_dict(message, response_code=self.RESPONSE_CODE_OK, message_code=sent_msg_code))


    def SyncLocalTimeToCamera(self, timestamp=None, seconds_from_GMT=None):
        """ Send a message to set LOCAL_TIME and TIME_ZONE """
        # time.time() returns the Unix epoch: the timezone offset should be zero.
        if timestamp is None:
            timestamp = int(time.time())
        if seconds_from_GMT is None:
            seconds_from_GMT = 0
        message = {
            'optionTypes': [
                'LOCAL_TIME',
                'TIME_ZONE'],
            'value': {
                'local_time': timestamp,
                'time_zone_seconds_from_GMT': seconds_from_GMT}
        }
        return self.SendMessage(message, self.PHONE_COMMAND_SET_OPTIONS)


    def TestSetOptions(self, message):
        """ Send message (a Python dictionary) using set_options_pb2.SetOptions() """
        return self.SendMessage(message, self.PHONE_COMMAND_SET_OPTIONS)


    def GetCameraInfo(self):
        """ Request updated data about camera, battery and storage """
        # Data retrieved with this function maybe used also by
        # GetBatteryStatus, GetSerialNumber, GetCameraUUID,
        # GetStorageState and GetCameraType.
        #
        # WARNING: The value returned by asking for option_types: VIDEO_RESOLUTION,
        # e.g. value: { video_resolution: RES_3840_2160P60 }, does not match the one
        # selected on the camera. Ask for GetPhotographyOptions() instead.
        #
        # Options actually returned by the Insta360 ONE RS:
        # [x] BATTERY_STATUS
        # [x] SERIAL_NUMBER
        # [x] UUID
        # [x] STORAGE_STATE
        # [x] FIRMWAREREVISION
        # [x] CAMERA_TYPE
        # [ ] LED_SWITCH
        # [x] VIDEO_FOV
        # [x] STILL_FOV
        # [x] TEMP_VALUE
        # [x] VIDEO_RESOLUTION (not the actual resolution selected)
        # [ ] CAPTURE_TIME_LIMIT
        # [ ] REMAINING_PICTURES
        # [x] BUTTON_PRESS_OPTIONS
        # [ ] GAMMA_MODE
        # [ ] MCTF_ENABLE
        # [ ] AUTHORIZATION_ID
        # [ ] STANDBY_DURATION
        # [ ] QUICK_CAPTURE_ENABLE
        # [ ] TELEVISION_SYSTEM
        # [ ] PTZ_CTRL
        # [ ] CAMERA_POSTURE
        # [ ] OFFSET_STATES
        # [ ] OPTIONS_NUM
        message = {
            'optionTypes': [
                'BATTERY_STATUS',
                'SERIAL_NUMBER',
                'UUID',
                'STORAGE_STATE',
                'FIRMWAREREVISION',
                'CAMERA_TYPE',
                'TEMP_VALUE',
                'CAMERA_POSTURE',
                'OPTIONS_NUM']
        }
        return self.SendMessage(message, self.PHONE_COMMAND_GET_OPTIONS)


    def GetCameraType(self):
        pass


    def TakePicture(self):
        message = { 'mode': 'NORMAL' }
        return self.SendMessage(message, self.PHONE_COMMAND_TAKE_PICTURE)


    def GetSerialNumber(self):
        pass


    def GetCameraFilesList(self):
        """ Request file listing """
        message = {
            'media_type': 'VIDEO_AND_PHOTO',
            'limit': 500
        }
        return self.SendMessage(message, self.PHONE_COMMAND_GET_FILE_LIST)


    def DeleteCameraFile(self):
        pass


    def DownloadCameraFile(self):
        pass


    def SetNormalVideoOptions(self, record_resolution=None, fov_type=None, focal_length_value=None, gamma_mode=None, white_balance=None, white_balance_value=None):
        """ Set video capture settings """
        # Labels on camera display are not updated.
        # Request message example:
        # message = {
        #     'optionTypes': [
        #         'EXPOSURE_BIAS',
        #         'WHITE_BALANCE_VALUE',
        #         'VIDEO_GAMMA_MODE',
        #         'VIDEO_EXPOSURE_OPTIONS',
        #         'VIDEO_ISO_TOP_LIMIT',
        #         'RECORD_RESOLUTION',
        #         'FOV_TYPE',
        #         'FOCAL_LENGTH_VALUE'],
        #     'value': {
        #         'gamma_mode': 'VIVID',
        #         'video_exposure': {
        #             'iso': 400,
        #             'shutter_speed': 0.03333333333333333 },
        #         'record_resolution': 'RES_1920_1080P30',
        #         'fov_type': 'FOV_ULTRAWIDE',
        #         'focal_length_value': 17.4 },
        #     'function_mode': 'FUNCTION_MODE_NORMAL_VIDEO'
        #}
        message = {}
        message['optionTypes'] = []
        message['value'] = {}
        message['function_mode'] = 'FUNCTION_MODE_NORMAL_VIDEO'
        if record_resolution is not None:
            message['optionTypes'].append('RECORD_RESOLUTION')
            message['value']['record_resolution'] = record_resolution
        if fov_type is not None:
            message['optionTypes'].append('FOV_TYPE')
            message['value']['fov_type'] = fov_type
        if focal_length_value is not None:
            message['optionTypes'].append('FOCAL_LENGTH_VALUE')
            message['value']['focal_length_value'] = focal_length_value
        if gamma_mode is not None:
            message['optionTypes'].append('VIDEO_GAMMA_MODE')
            message['value']['gamma_mode'] = gamma_mode
        if white_balance is not None:
            message['optionTypes'].append('WHITE_BALANCE')
            message['value']['white_balance'] = white_balance
        if white_balance_value is not None:
            message['optionTypes'].append('WHITE_BALANCE_VALUE')
            message['value']['white_balance_value'] = white_balance_value
        self.logger.info('Sending message: %s' % (message,))
        return self.SendMessage(message, self.PHONE_COMMAND_SET_PHOTOGRAPHY_OPTIONS)


    def GetNormalVideoOptions(self):
        # WARNING: Sometimes, when the camera display is off (power saving),
        # changes to the FOCAL_LENGTH_VALUE will not result in the subsequent
        # PHONE_COMMAND_GET_PHOTOGRAPHY_OPTIONS requests. Sometimes FOV_WIDE
        # is not returned at all. The same happens when asking for VIDEO_FOV
        # using PHONE_COMMAND_GET_OPTIONS.
        # It seems that closing and re-opening the socket connection will
        # restore the correct reported value.
        message = {
            'option_types': [
                'EXPOSURE_BIAS',
                'WHITE_BALANCE',
                'WHITE_BALANCE_VALUE',
                'VIDEO_GAMMA_MODE',
                'VIDEO_EXPOSURE_OPTIONS',
                'VIDEO_ISO_TOP_LIMIT',
                'RECORD_RESOLUTION',
                'FOV_TYPE',
                'FOCAL_LENGTH_VALUE'],
            'function_mode': 'FUNCTION_MODE_NORMAL_VIDEO'
        }
        return self.SendMessage(message, self.PHONE_COMMAND_GET_PHOTOGRAPHY_OPTIONS)


    def StartCapture(self):
        message = {
            'mode': 'Capture_MODE_NORMAL'
        }
        return self.SendMessage(message, self.PHONE_COMMAND_START_CAPTURE)


    def StopCapture(self):
        message = {}
        return self.SendMessage(message, self.PHONE_COMMAND_STOP_CAPTURE)


    def GetExposureSettings(self):
        pass

    def SetExposureSettings(self):
        pass

    def SetCaptureSettings(self, record_resolution=None, fov_type=None, focal_length_value=None, gamma_mode=None):
        pass

    def GetCaptureSettings(self):
        pass


    def StartLiveStream(self):
        """ Start live stream """
        # It seems that live stream is embedded into packets received via the same socket.
        message = {
            'enableVideo': True,
            'videoBitrate': 40,
            'resolution': 'RES_1920_1080P30',
            'enableGyro': True,
            'videoBitrate1': 40,
            'resolution1': 'RES_424_240P15',
            'previewStreamNum': 1
        }
        return self.SendMessage(message, self.PHONE_COMMAND_START_LIVE_STREAM)


    def StopLiveStream(self):
        message = {}
        return self.SendMessage(message, self.PHONE_COMMAND_STOP_LIVE_STREAM)


    def GetCameraUUID(self):
        pass


    def GetCaptureCurrentStatus(self):
        """ Get current capture status """
        message = {}
        return self.SendMessage(message, self.PHONE_COMMAND_GET_CURRENT_CAPTURE_STATUS)


    def SetTimeLapseOption(self):
        pass

    def StartTimeLapse(self):
        pass

    def StopTimeLapse(self):
        pass

    def IsConnected(self):
        pass

    def GetBatteryStatus(self):
        pass

    def GetStorageState(self):
        pass


if __name__ == "__main__":
    sys.exit(0)
