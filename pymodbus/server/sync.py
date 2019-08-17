"""
Implementation of a Threaded Modbus Server
------------------------------------------

"""
from binascii import b2a_hex
import serial
import socket
import traceback
import os
import hashlib
import hmac
import binascii
import ssl
import datetime
import time
import threading
import sqlite3
import sys

from pymodbus.constants import Defaults
from pymodbus.utilities import hexlify_packets
from pymodbus.factory import ServerDecoder
from pymodbus.datastore import ModbusServerContext
from pymodbus.device import ModbusControlBlock
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.transaction import *
from pymodbus.exceptions import NotImplementedException, NoSuchSlaveException
from pymodbus.pdu import ModbusExceptions as merror
from pymodbus.compat import socketserver, byte2int

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
import logging
_logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Protocol Handlers
# --------------------------------------------------------------------------- #

class ModbusBaseRequestHandler(socketserver.BaseRequestHandler):
    """ Implements the modbus server protocol

    This uses the socketserver.BaseRequestHandler to implement
    the client handler.
    """
    running = False
    framer = None
    
    def setup(self):
        """ Callback for when a client connects
        """
        _logger.debug("Client Connected [%s:%s]" % self.client_address)
        self.running = True
        self.framer = self.server.framer(self.server.decoder, client=None)
        self.server.threads.append(self)

    def finish(self):
        """ Callback for when a client disconnects
        """
        _logger.debug("Client Disconnected [%s:%s]" % self.client_address)
        self.server.threads.remove(self)

    def execute(self, request):
        """ The callback to call with the resulting message

        :param request: The decoded request message
        """
        broadcast = False
        try:
            if self.server.broadcast_enable and request.unit_id == 0:
                broadcast = True
                # if broadcasting then execute on all slave contexts, note response will be ignored
                for unit_id in self.server.context.slaves():
                    response = request.execute(self.server.context[unit_id])
            else:
                context = self.server.context[request.unit_id]
                response = request.execute(context)
        except NoSuchSlaveException as ex:
            _logger.debug("requested slave does "
                          "not exist: %s" % request.unit_id )
            if self.server.ignore_missing_slaves:
                return  # the client will simply timeout waiting for a response
            response = request.doException(merror.GatewayNoResponse)
        except Exception as ex:
            _logger.debug("Datastore unable to fulfill request: "
                          "%s; %s", ex, traceback.format_exc())
            response = request.doException(merror.SlaveFailure)
        # no response when broadcasting
        if not broadcast:
            response.transaction_id = request.transaction_id
            response.unit_id = request.unit_id
            self.send(response)

    # ----------------------------------------------------------------------- #
    # Base class implementations
    # ----------------------------------------------------------------------- #
    def handle(self):
        """ Callback when we receive any data
        """
        raise NotImplementedException("Method not implemented"
                                      " by derived class")

    def send(self, message):
        """ Send a request (string) to the network

        :param message: The unencoded modbus response
        """
        raise NotImplementedException("Method not implemented "
                                      "by derived class")


class ModbusSingleRequestHandler(ModbusBaseRequestHandler):
    """ Implements the modbus server protocol

    This uses the socketserver.BaseRequestHandler to implement
    the client handler for a single client(serial clients)
    """
    def handle(self):
        """ Callback when we receive any data
        """
        while self.running:
            try:
                data = self.request.recv(1024)
                if data:
                    units = self.server.context.slaves()
                    if not isinstance(units, (list, tuple)):
                        units = [units]
                    # if broadcast is enabled make sure to process requests to address 0
                    if self.server.broadcast_enable:
                        if 0 not in units:
                            units.append(0)
                    single = self.server.context.single
                    self.framer.processIncomingPacket(data, self.execute,
                                                      units, single=single)
            except Exception as msg:
                # Since we only have a single socket, we cannot exit
                # Clear frame buffer
                self.framer.resetFrame()
                _logger.debug("Error: Socket error occurred %s" % msg)

    def send(self, message):
        """ Send a request (string) to the network

        :param message: The unencoded modbus response
        """
        if message.should_respond:
            # self.server.control.Counter.BusMessage += 1
            pdu = self.framer.buildPacket(message)
            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('send: [%s]- %s' % (message, b2a_hex(pdu)))
            return self.request.send(pdu)


class CustomSingleRequestHandler(ModbusSingleRequestHandler):

    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.running = True
        self.setup()


class ModbusConnectedRequestHandler(ModbusBaseRequestHandler):
    """ Implements the modbus server protocol

    This uses the socketserver.BaseRequestHandler to implement
    the client handler for a connected protocol (TCP).
    """

    def handle(self):
        """Callback when we receive any data, until self.running becomes False.
        Blocks indefinitely awaiting data.  If shutdown is required, then the
        global socket.settimeout(<seconds>) may be used, to allow timely
        checking of self.running.  However, since this also affects socket
        connects, if there are outgoing socket connections used in the same
        program, then these will be prevented, if the specfied timeout is too
        short.  Hence, this is unreliable.

        To respond to Modbus...Server.server_close() (which clears each
        handler's self.running), derive from this class to provide an
        alternative handler that awakens from time to time when no input is
        available and checks self.running.
        Use Modbus...Server( handler=... ) keyword to supply the alternative
        request handler class.

        """
        reset_frame = False
        while self.running:
            try:
                units = self.server.context.slaves()
                data = self.request.recv(1024)
                if not data:
                    self.running = False
                else:
                    if not isinstance(units, (list, tuple)):
                        units = [units]
                    # if broadcast is enabled make sure to
                    # process requests to address 0
                    if self.server.broadcast_enable:
                        if 0 not in units:
                            units.append(0)

                if _logger.isEnabledFor(logging.DEBUG):
                    _logger.debug('Handling data: ' + hexlify_packets(data))
                single = self.server.context.single
                self.framer.processIncomingPacket(data, self.execute, units,
                                                  single=single)
            except socket.timeout as msg:
                if _logger.isEnabledFor(logging.DEBUG):
                    _logger.debug("Socket timeout occurred %s", msg)
                reset_frame = True
            except socket.error as msg:
                _logger.error("Socket error occurred %s" % msg)
                self.running = False
            except:
                _logger.error("Socket exception occurred "
                              "%s" % traceback.format_exc() )
                self.running = False
                reset_frame = True
            finally:
                if reset_frame:
                    self.framer.resetFrame()
                    reset_frame = False

    def send(self, message):
        """ Send a request (string) to the network

        :param message: The unencoded modbus response
        """
        if message.should_respond:
            # self.server.control.Counter.BusMessage += 1
            pdu = self.framer.buildPacket(message)
            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('send: [%s]- %s' % (message, b2a_hex(pdu)))
            return self.request.send(pdu)


class ModbusDisconnectedRequestHandler(ModbusBaseRequestHandler):
    """ Implements the modbus server protocol

    This uses the socketserver.BaseRequestHandler to implement
    the client handler for a disconnected protocol (UDP). The
    only difference is that we have to specify who to send the
    resulting packet data to.
    """
    socket = None

    def handle(self):
        """ Callback when we receive any data
        """
        reset_frame = False
        while self.running:
            try:
                data, self.socket = self.request
                if not data:
                    self.running = False
                    data = b''
                if _logger.isEnabledFor(logging.DEBUG):
                    _logger.debug('Handling data: ' + hexlify_packets(data))
                # if not self.server.control.ListenOnly:
                units = self.server.context.slaves()
                single = self.server.context.single
                self.framer.processIncomingPacket(data, self.execute,
                                                  units, single=single)
            except socket.timeout: pass
            except socket.error as msg:
                _logger.error("Socket error occurred %s" % msg)
                self.running = False
                reset_frame = True
            except Exception as msg:
                _logger.error(msg)
                self.running = False
                reset_frame = True
            finally:
                # Reset data after processing
                self.request = (None, self.socket)
                if reset_frame:
                    self.framer.resetFrame()
                    reset_frame = False

    def send(self, message):
        """ Send a request (string) to the network

        :param message: The unencoded modbus response
        """
        if message.should_respond:
            #self.server.control.Counter.BusMessage += 1
            pdu = self.framer.buildPacket(message)
            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('send: [%s]- %s' % (message, b2a_hex(pdu)))
            return self.socket.sendto(pdu, self.client_address)

# --------------------------------------------------------------------------- #
# Server Implementations
# --------------------------------------------------------------------------- #
class ModbusTLSServer(socketserver.ThreadingTCPServer):
    """
    A modbus threaded tcp socket server

    We inherit and overload the socket server so that we
    can control the client threads as well as have a single
    server context instance.
    """

    def __init__(self, context, framer=None, identity=None,
                 address=None, handler=None, allow_reuse_address=False,
                 **kwargs):
        """ Overloaded initializer for the socket server

        If the identify structure is not passed in, the ModbusControlBlock
        uses its own empty structure.

        :param context: The ModbusServerContext datastore
        :param framer: The framer strategy to use
        :param identity: An optional identify structure
        :param address: An optional (interface, port) to bind to.
        :param handler: A handler for each client session; default is
                        ModbusConnectedRequestHandler
        :param allow_reuse_address: Whether the server will allow the
                        reuse of an address.
        :param ignore_missing_slaves: True to not send errors on a request 
                        to a missing slave
        :param broadcast_enable: True to treat unit_id 0 as broadcast address,
                        False to treat 0 as any other unit_id
        """
        self.threads = []
        self.allow_reuse_address = allow_reuse_address
        self.decoder = ServerDecoder()
        self.framer = framer or ModbusSocketFramer
        self.context = context or ModbusServerContext()
        self.control = ModbusControlBlock()
        self.address = address or ("", Defaults.Port)
        self.handler = handler or ModbusConnectedRequestHandler
        self.ignore_missing_slaves = kwargs.get('ignore_missing_slaves',
                                                Defaults.IgnoreMissingSlaves)
        self.broadcast_enable = kwargs.get('broadcast_enable', 
                                           Defaults.broadcast_enable)
        self.transaction_id = kwargs.get('transaction', Defaults.TransactionId)
        self.protocol_id = kwargs.get('protocol', Defaults.ProtocolId)
        self.unit_id = kwargs.get('unit', Defaults.UnitId)
        self.skip_encode = kwargs.get('skip_encode', False)

        if isinstance(identity, ModbusDeviceIdentification):
            self.control.Identity.update(identity)

        #socketserver.ThreadingTCPServer.__init__(self, self.address,
        #                                         self.handler)

        def getFullPath(path):
            #dir = os.path.dirname(os.path.realpath(__file__))
            dir = os.getcwd()
            if path[0] != '/':
                return dir + '/' + path
            else:
                return path
        
        def deriveKey(masterKey, deviceId):
            return hmacsha256(deviceId, masterKey)

        def hmacsha256(data, key):
            return hmac.new(key, data, digestmod=hashlib.sha256).digest()

        class ModbusSession:
            TYPE_SSL = 'ssl'
            TYPE_UDP = 'udp'
            def __init__(self, deviceId, protocol):
                self.protocol = protocol
                self.deviceId = deviceId
                self.clientAddr = None
                self.lastUdpMessage = None
                self.lastPayload = None
                self.sslSocket = None
                self.creationTime = datetime.datetime.now()
                self.lastUpdateTime = datetime.datetime.now()     
                self.lock = threading.Lock()
        
        def hadleSslCommunication(sslSocket, fromaddr):
            """ A helper method to create and monkeypatch
                a serial handler.
            :returns: A patched handler"""
            request = sslSocket
            response = sslSocket
            data = request.recv(1024)
            conn = sqlite3.connect('./roleDB.db')
            c = conn.cursor()
            for row in c.execute('SELECT * FROM roleTable uint_id'):
                if (row[1] == int(data[6].encode('hex'))):
                    flag = 1
                else:
                    flag = 0
            if flag == 0:
                print('Client modbus frame Authentication Denied')
                sslSocket.close()
                sys.exit()

            if _logger.isEnabledFor(logging.DEBUG):
                _logger.debug('Handling data: ' + hexlify_packets(data))
            
            PACKET_SIZE = 1024
            sslSocket.send(data+"\x00"*max(PACKET_SIZE-len(data),0))
            response.send(data)
        
        sessions = dict()
        serverName = raw_input('Enter server name (ex. domain name) for SSL certificate:')
        serverCertFile = getFullPath(os.path.join('servercert.pem'))  
        serverKeyFile = getFullPath(os.path.join('serverkey.pem'))
        os.system('openssl req -x509 -newkey rsa:2048 -keyout {0} -out {1} -days 36500 -subj "/C=NA/ST=NA/L=NA/O=IOT/CN={2}" -nodes'.format(serverKeyFile, serverCertFile, serverName))
        
        masterKey = os.urandom(64)
        deviceId = os.urandom(16)
        deviceKey = deriveKey(masterKey, deviceId)
        certSignature = hmacsha256(deviceId, deviceKey)        
        shortId = binascii.hexlify(deviceId)[:0]
        deviceConfigDir = getFullPath("conf-{0}".format(shortId))
        os.makedirs(deviceConfigDir)
        deviceKeyFile = os.path.join(deviceConfigDir,'devicekey.pem')  
        deviceCsrFile = os.path.join(deviceConfigDir,'device.csr')  
        openssl = os.path.join('./openssl.cnf')
        os.system('openssl req  -newkey rsa:2048 -nodes -keyout {0} -extensions RoleSpecCertIdentifier -out {1} -subj "/C=NA/ST=NA/L=NA/O=OT/CN={2}/description={3}" -config ./openssl.cnf'.format(deviceKeyFile, deviceCsrFile, binascii.hexlify(deviceId), binascii.hexlify(certSignature)))
        deviceCertFile = os.path.join(deviceConfigDir,'devicecert.pem')
        os.system('openssl x509 -req -in {0} -CA {1} -CAkey {2} -CAcreateserial -out {3} -days 36500 -sha256'.format(deviceCsrFile, serverCertFile, serverKeyFile, deviceCertFile))
        #os.remove(deviceCsrFile)
        
        caCertFile = 'servercert.pem'
        
        sslHost = address[0]
        sslPort = (address[1])

        # Create the DataBase
        conn = sqlite3.connect('roleDB.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE roleTable
                     (ID INTEGER PRIMARY KEY, unit_id INTEGER, role text)''')

        # Insert a row of data
        c.execute("INSERT INTO roleTable VALUES(1,5,'operator')")

        # Save (commit) the changes
        conn.commit()

        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        conn.close()

        logger = logging.getLogger()
        logging.basicConfig()
        logger.info("starting TCP SSL server listening at {0}:{1}".format(sslHost, sslPort))

        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  #bind even if local port is in TIME_WAIT
        bindsocket.bind((sslHost, sslPort))
        bindsocket.listen(5)

        while True:
            newsocket, fromaddr = bindsocket.accept()
            try:
                logger.info("New TCP connection from {0}:{1} - initiating ssl using serverCertFile={2}, serverKeyFile={3}".format(fromaddr[0], fromaddr[1], serverCertFile, serverKeyFile))
                sslSocket = ssl.wrap_socket(newsocket, server_side=True,certfile=serverCertFile,keyfile=serverKeyFile,cert_reqs=ssl.CERT_REQUIRED,ca_certs=caCertFile,ssl_version=ssl.PROTOCOL_TLSv1_2,do_handshake_on_connect=True, ciphers='ECDHE-RSA-AES256-SHA')
                sslSocket.settimeout(300)
                servercert = sslSocket.getpeercert()
                #check certificate signature
                subject = dict(x[0] for x in servercert['subject'])
                cn = subject['commonName']
                desc = subject['description']
                logger.info("Client certificate is valid, CN={0}, description={1} - validating deviceId and description".format(cn, desc))
                deviceId = str(bytearray.fromhex(cn))
                deviceKey = deriveKey(masterKey, deviceId)
                expectedSignature = binascii.hexlify(hmacsha256(deviceId, deviceKey))
                #check Role in certificated
                Requested_Extensions = dict(d[0] for x in servercert['Requested Extensions'])
                ModbusOID='1.3.6.1.4.50316.802.1'
                if ModbusOID == d[0]:
                    for row in c.execute('SELECT * FROM roleTable role'):
                        if (row[2] == int(data[6].encode('hex'))):
                            logger.info("Role valided, client authorized")
                        else:
                            logger.info("Role valided, client no authorized")
                            sslSocket.close()
                            sys.exit()
                #if certificate signature ok, generating the session
                if desc == expectedSignature:
                    logger.debug("certificate signature OK, creating session for device {0} at {1}:{2}".format(cn, fromaddr[0], fromaddr[1]))
                    if deviceId in sessions:
                        session = sessions[deviceId]       
                        session.clientAddr = fromaddr
                        session.sslSocket = sslSocket
                        session.lastUpdateTime = datetime.datetime.now()                                  
                    else:
                        logger.debug("    creating new session for SSL device: %s", binascii.hexlify(deviceId))
                        session = ModbusSession(deviceId, ModbusSession.TYPE_SSL)
                        session.clientAddr = fromaddr
                        session.sslSocket = sslSocket
                        session.lastUpdateTime = datetime.datetime.now()                                
                        sessions[deviceId] = session               
                    logger.debug("Creating thread for handling SSL communication with {0}".format(binascii.hexlify(deviceId)))
                    conectionThread = threading.Thread(target = hadleSslCommunication, args = (sslSocket, fromaddr))
                    conectionThread.daemon = True
                    conectionThread.start()
                else:
                    sslSocket.shutdown(socket.SHUT_RDWR)
                    sslSocket.close()
                    self.logger.warning('received invalid signature in certificate description field for device {0}. expected={1}, received={2} - closing connection'.format(cn, binascii.hexlify(expectedSignature), desc))
            except Exception as e:
                logger.exception(e)
                try:
                    newsocket.shutdown(socket.SHUT_RDWR)
                    newsocket.close()
                except:
                    pass

    def process_request(self, request, client):
        """ Callback for connecting a new client thread

        :param request: The request to handle
        :param client: The address of the client
        """
        _logger.debug("Started thread to serve client at " + str(client))
        socketserver.ThreadingTCPServer.process_request(self, request, client)

    def shutdown(self):
        """ Stops the serve_forever loop.

        Overridden to signal handlers to stop.
        """
        for thread in self.threads:
            thread.running = False
        socketserver.ThreadingTCPServer.shutdown(self)

    def server_close(self):
        """ Callback for stopping the running server
        """
        _logger.debug("Modbus server stopped")
        self.socket.close()
        for thread in self.threads:
            thread.running = False


class ModbusTcpServer(socketserver.ThreadingTCPServer):
    """
    A modbus threaded tcp socket server

    We inherit and overload the socket server so that we
    can control the client threads as well as have a single
    server context instance.
    """

    def __init__(self, context, framer=None, identity=None,
                 address=None, handler=None, allow_reuse_address=False,
                 **kwargs):
        """ Overloaded initializer for the socket server

        If the identify structure is not passed in, the ModbusControlBlock
        uses its own empty structure.

        :param context: The ModbusServerContext datastore
        :param framer: The framer strategy to use
        :param identity: An optional identify structure
        :param address: An optional (interface, port) to bind to.
        :param handler: A handler for each client session; default is
                        ModbusConnectedRequestHandler
        :param allow_reuse_address: Whether the server will allow the
                        reuse of an address.
        :param ignore_missing_slaves: True to not send errors on a request 
                        to a missing slave
        :param broadcast_enable: True to treat unit_id 0 as broadcast address,
                        False to treat 0 as any other unit_id
        """
        self.threads = []
        self.allow_reuse_address = allow_reuse_address
        self.decoder = ServerDecoder()
        self.framer = framer or ModbusSocketFramer
        self.context = context or ModbusServerContext()
        self.control = ModbusControlBlock()
        self.address = address or ("", Defaults.Port)
        self.handler = handler or ModbusConnectedRequestHandler
        self.ignore_missing_slaves = kwargs.get('ignore_missing_slaves',
                                                Defaults.IgnoreMissingSlaves)
        self.broadcast_enable = kwargs.get('broadcast_enable', 
                                           Defaults.broadcast_enable)

        if isinstance(identity, ModbusDeviceIdentification):
            self.control.Identity.update(identity)

        socketserver.ThreadingTCPServer.__init__(self, self.address,
                                                 self.handler)

    def process_request(self, request, client):
        """ Callback for connecting a new client thread

        :param request: The request to handle
        :param client: The address of the client
        """
        _logger.debug("Started thread to serve client at " + str(client))
        socketserver.ThreadingTCPServer.process_request(self, request, client)

    def shutdown(self):
        """ Stops the serve_forever loop.

        Overridden to signal handlers to stop.
        """
        for thread in self.threads:
            thread.running = False
        socketserver.ThreadingTCPServer.shutdown(self)

    def server_close(self):
        """ Callback for stopping the running server
        """
        _logger.debug("Modbus server stopped")
        self.socket.close()
        for thread in self.threads:
            thread.running = False


class ModbusUdpServer(socketserver.ThreadingUDPServer):
    """
    A modbus threaded udp socket server

    We inherit and overload the socket server so that we
    can control the client threads as well as have a single
    server context instance.
    """

    def __init__(self, context, framer=None, identity=None, address=None,
                 handler=None, **kwargs):
        """ Overloaded initializer for the socket server

        If the identify structure is not passed in, the ModbusControlBlock
        uses its own empty structure.

        :param context: The ModbusServerContext datastore
        :param framer: The framer strategy to use
        :param identity: An optional identify structure
        :param address: An optional (interface, port) to bind to.
        :param handler: A handler for each client session; default is
                            ModbusDisonnectedRequestHandler
        :param ignore_missing_slaves: True to not send errors on a request
                            to a missing slave
        :param broadcast_enable: True to treat unit_id 0 as broadcast address,
                            False to treat 0 as any other unit_id
        """
        self.threads = []
        self.decoder = ServerDecoder()
        self.framer = framer  or ModbusSocketFramer
        self.context = context or ModbusServerContext()
        self.control = ModbusControlBlock()
        self.address = address or ("", Defaults.Port)
        self.handler = handler or ModbusDisconnectedRequestHandler
        self.ignore_missing_slaves = kwargs.get('ignore_missing_slaves',
                                                Defaults.IgnoreMissingSlaves)
        self.broadcast_enable = kwargs.get('broadcast_enable', 
                                           Defaults.broadcast_enable)

        if isinstance(identity, ModbusDeviceIdentification):
            self.control.Identity.update(identity)

        socketserver.ThreadingUDPServer.__init__(self,
            self.address, self.handler)
        # self._BaseServer__shutdown_request = True

    def process_request(self, request, client):
        """ Callback for connecting a new client thread

        :param request: The request to handle
        :param client: The address of the client
        """
        packet, socket = request # TODO I might have to rewrite
        _logger.debug("Started thread to serve client at " + str(client))
        socketserver.ThreadingUDPServer.process_request(self, request, client)

    def server_close(self):
        """ Callback for stopping the running server
        """
        _logger.debug("Modbus server stopped")
        self.socket.close()
        for thread in self.threads:
            thread.running = False


class ModbusSerialServer(object):
    """
    A modbus threaded serial socket server

    We inherit and overload the socket server so that we
    can control the client threads as well as have a single
    server context instance.
    """

    handler = None

    def __init__(self, context, framer=None, identity=None, **kwargs):
        """ Overloaded initializer for the socket server

        If the identify structure is not passed in, the ModbusControlBlock
        uses its own empty structure.

        :param context: The ModbusServerContext datastore
        :param framer: The framer strategy to use
        :param identity: An optional identify structure
        :param port: The serial port to attach to
        :param stopbits: The number of stop bits to use
        :param bytesize: The bytesize of the serial messages
        :param parity: Which kind of parity to use
        :param baudrate: The baud rate to use for the serial device
        :param timeout: The timeout to use for the serial device
        :param ignore_missing_slaves: True to not send errors on a request
                            to a missing slave
        :param broadcast_enable: True to treat unit_id 0 as broadcast address,
                            False to treat 0 as any other unit_id
        """
        self.threads = []
        self.decoder = ServerDecoder()
        self.framer = framer or ModbusAsciiFramer
        self.context = context or ModbusServerContext()
        self.control = ModbusControlBlock()

        if isinstance(identity, ModbusDeviceIdentification):
            self.control.Identity.update(identity)

        self.device = kwargs.get('port', 0)
        self.stopbits = kwargs.get('stopbits', Defaults.Stopbits)
        self.bytesize = kwargs.get('bytesize', Defaults.Bytesize)
        self.parity = kwargs.get('parity',   Defaults.Parity)
        self.baudrate = kwargs.get('baudrate', Defaults.Baudrate)
        self.timeout = kwargs.get('timeout',  Defaults.Timeout)
        self.ignore_missing_slaves = kwargs.get('ignore_missing_slaves',
                                                Defaults.IgnoreMissingSlaves)
        self.broadcast_enable = kwargs.get('broadcast_enable',
                                           Defaults.broadcast_enable)
        self.socket = None
        if self._connect():
            self.is_running = True
            self._build_handler()

    def _connect(self):
        """ Connect to the serial server

        :returns: True if connection succeeded, False otherwise
        """
        if self.socket: return True
        try:
            self.socket = serial.Serial(port=self.device,
                                        timeout=self.timeout,
                                        bytesize=self.bytesize,
                                        stopbits=self.stopbits,
                                        baudrate=self.baudrate,
                                        parity=self.parity)
        except serial.SerialException as msg:
            _logger.error(msg)
        return self.socket is not None

    def _build_handler(self):
        """ A helper method to create and monkeypatch
            a serial handler.

        :returns: A patched handler
        """

        request = self.socket
        request.send = request.write
        request.recv = request.read
        self.handler = CustomSingleRequestHandler(request,
                                                  (self.device, self.device),
                                                  self)

    def serve_forever(self):
        """ Callback for connecting a new client thread
        """
        if self._connect():
            _logger.debug("Started thread to serve client")
            if not self.handler:
                self._build_handler()
            while self.is_running:
                self.handler.handle()
        else:
            _logger.error("Error opening serial port , "
                          "Unable to start server!!")

    def server_close(self):
        """ Callback for stopping the running server
        """
        _logger.debug("Modbus server stopped")
        self.is_running = False
        self.handler.finish()
        self.handler.running = False
        self.handler = None
        self.socket.close()


# --------------------------------------------------------------------------- #
# Creation Factories
# --------------------------------------------------------------------------- #
def StartTLSServer(context=None, identity=None, address=None,
                   custom_functions=[], **kwargs):
    """ A factory to start and run a tcp modbus server

    :param context: The ModbusServerContext datastore
    :param identity: An optional identify structure
    :param address: An optional (interface, port) to bind to.
    :param custom_functions: An optional list of custom function classes
        supported by server instance.
    :param ignore_missing_slaves: True to not send errors on a request to a
                                      missing slave
    """
    framer = kwargs.pop("framer", ModbusSocketFramer)
    server = ModbusTLSServer(context, framer, identity, address, **kwargs)

    for f in custom_functions:
        server.decoder.register(f)
    server.serve_forever()


def StartTcpServer(context=None, identity=None, address=None,
                   custom_functions=[], **kwargs):
    """ A factory to start and run a tcp modbus server

    :param context: The ModbusServerContext datastore
    :param identity: An optional identify structure
    :param address: An optional (interface, port) to bind to.
    :param custom_functions: An optional list of custom function classes
        supported by server instance.
    :param ignore_missing_slaves: True to not send errors on a request to a
                                      missing slave
    """
    framer = kwargs.pop("framer", ModbusSocketFramer)
    server = ModbusTcpServer(context, framer, identity, address, **kwargs)

    for f in custom_functions:
        server.decoder.register(f)
    server.serve_forever()


def StartUdpServer(context=None, identity=None, address=None,
                   custom_functions=[], **kwargs):
    """ A factory to start and run a udp modbus server

    :param context: The ModbusServerContext datastore
    :param identity: An optional identify structure
    :param address: An optional (interface, port) to bind to.
    :param custom_functions: An optional list of custom function classes
        supported by server instance.
    :param framer: The framer to operate with (default ModbusSocketFramer)
    :param ignore_missing_slaves: True to not send errors on a request
                                    to a missing slave
    """
    framer = kwargs.pop('framer', ModbusSocketFramer)
    server = ModbusUdpServer(context, framer, identity, address, **kwargs)
    for f in custom_functions:
        server.decoder.register(f)
    server.serve_forever()


def StartSerialServer(context=None, identity=None,  custom_functions=[],
                      **kwargs):
    """ A factory to start and run a serial modbus server

    :param context: The ModbusServerContext datastore
    :param identity: An optional identify structure
    :param custom_functions: An optional list of custom function classes
        supported by server instance.
    :param framer: The framer to operate with (default ModbusAsciiFramer)
    :param port: The serial port to attach to
    :param stopbits: The number of stop bits to use
    :param bytesize: The bytesize of the serial messages
    :param parity: Which kind of parity to use
    :param baudrate: The baud rate to use for the serial device
    :param timeout: The timeout to use for the serial device
    :param ignore_missing_slaves: True to not send errors on a request to a
                                  missing slave
    """
    framer = kwargs.pop('framer', ModbusAsciiFramer)
    server = ModbusSerialServer(context, framer, identity, **kwargs)
    for f in custom_functions:
        server.decoder.register(f)
    server.serve_forever()

# --------------------------------------------------------------------------- #
# Exported symbols
# --------------------------------------------------------------------------- #


__all__ = [
    "StartTcpServer", "StartUdpServer", "StartSerialServer"
]

