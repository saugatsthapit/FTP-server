#!/usr/bin/env python3
# --*-- coding: utf-8 --*--

import socket
import threading
import os
import stat
import sys
import time
import grp
import pwd
import ssl
import codecs

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

try:
    HOST = '127.0.0.1'  # socket.gethostbyname(socket.gethostname())
except socket.error:
    HOST = '127.0.0.1'
    
PORT = 8443  # command port
CWD = os.path.abspath('.')  # os.getenv('HOME')
allow_delete = True  # used to indicate if it's allowed to delete files or not
logfile = os.getcwd() + r'/socket-server.log'  # name of the log file
config_file_path = "ftpserverd.conf"

''' Reads the settings from the digital_ocean.ini file '''
config = ConfigParser.SafeConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/' + config_file_path)


def log(func, cmd, client_address=None):
    if client_address is not None:
        client = "%s, %s" % client_address
        logmsg = time.strftime("%Y-%m-%d %H-%M-%S [-] [" + client + "] " + func)
    else:
        logmsg = time.strftime("%Y-%m-%d %H-%M-%S [-] " + func)  
    print(logmsg, cmd)
    
    # Write log to file
    f = open(logfile, 'a+')  # 'a' will append to an existing file if it exists
    f.write(logmsg + " {}\n".format(cmd))  # write the text to the logfile and move to next line

        
# Load config properties
try: 
    # if config.has_option('server_options', 'port_mode'):
    #    self.api_token = config.get('server_options', 'port_mode')
    port_mode = config.get('server_options', 'port_mode').encode('utf-8')
    pasv_mode = config.get('server_options', 'pasv_mode').encode('utf-8')
except Exception as err:
    log('Config ERR', err)
    
# List of available commands
COMMANDS = ["CDUP", "CWD", "EPRT", "EPSV", "HELP", "LIST", "PASS",
            "PASV", "PORT", "PWD", "QUIT", "RETR", "STOR", "SYST", "TYPE", "USER",
            "NLIST", "DELE", "MKD", "RMD", "RNFR", "RNTO", "REST", "APPE"]


class FtpServerProtocol(threading.Thread):

    def __init__(self, conn, address):
        threading.Thread.__init__(self)
        self.authenticated = False
        self.banned_username = False
        self.pasv_mode = False
        self.rest = False
        self.cwd = CWD
        self.commSock = conn  # communication socket as command channel
        self.address = address
        self.dataSockAddr = HOST
        self.dataSockPort = PORT
        self._epsvall = False  # used for EPSV
        self._af = socket.AF_INET  # address_family

    def run(self):
        """
        receive commands from client and execute commands
        """
        self.sendWelcome()
        while True:
            
            try:
                # Receive the data in small chunks and retransmit it
                data = self.commSock.recv(1024).rstrip()
                try:
                    cmd = data.decode('utf-8')
                    log('Received data from client: ', cmd, self.address)
                except AttributeError:
                    cmd = data
                
                 # if received data is empty or not exists break this loop
                if not cmd or cmd is None: 
                    break
            
            except socket.error as err:
                log('Receive', err)

            try:
                cmd, arg = cmd[:4].strip().upper(), cmd[4:].strip() or None
                
                if cmd not in COMMANDS:
                    self.sendCommand('Not valid command\r\n')
                    continue

                if not self.authenticated and cmd not in ["USER", "PASS", "HELP"]:
                    self.sendCommand('530 User not logged in.\r\n')
                    continue
                
                func = getattr(self, cmd)
                func(arg)
            except Exception as err:
                self.sendCommand('500 Syntax error, command unrecognized. '
                    'This may include errors such as command line too long.\r\n')
                log('Error while trying to call command based on received data', err)

    #-------------------------------------#
    # # Create Ftp data transport channel ##
    #-------------------------------------#
    def startDataSock(self):
        log('startDataSock', 'Opening a data channel')
        try:
            self.dataSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.pasv_mode:
                self.dataSock, self.address = self.serverSock.accept()

            else:
                self.dataSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.dataSock.connect((self.dataSockAddr, self.dataSockPort))
        except socket.error as err:
            log('startDataSock', err)

    def stopDataSock(self):
        log('stopDataSock', 'Closing a data channel')
        try:
            if hasattr(self, 'dataSock') and self.dataSock is not None:
                self.dataSock.close()
                if self.pasv_mode:
                    self.serverSock.close()
        except socket.error as err:
            log('stopDataSock', err)

    def sendCommand(self, cmd):
        self.commSock.send(cmd.encode('utf-8'))

    def sendData(self, data):
        self.dataSock.send(data.encode('utf-8'))

    def sendWelcome(self):
        """
        when connection created with client will send a welcome message to the client
        """
        self.sendCommand('220 Welcome.\r\n')
    
    def _make_epasv(self, extmode=False):
        """Initialize a passive data channel with remote client which
        issued a PASV or EPSV command.
        If extmode argument is True we assume that client issued EPSV in
        which case extended passive mode will be used (see RFC-2428).
        """
        # close established data connections, if any
        if hasattr(self, 'dataSock') and self.dataSock is not None:
            self.stopDataSock()
            
        # open data channel
        try:
            self.pasv_mode = True  # extmode
            self._af = self.getIpVersion(HOST, PORT)
            self.serverSock = socket.socket(self._af, socket.SOCK_STREAM)
            self.serverSock.bind((HOST, 0))
            self.serverSock.listen(5)  # Enable a server to accept connections.
            addr, port = self.serverSock.getsockname()
            ipnum = socket.inet_aton(addr)
            log("EPSV", 'Address: ' + ipnum)
            if extmode:
                self.sendCommand("229 Entering Extended Passive Mode (|||" + str(port) + "|)")
                log("EPSV", 'Open socket Address: ' + addr + " and Port: " + str(port))
            else:
                self.sendCommand('227 Entering Passive Mode (%s,%u,%u).\r\n' % (','.join(addr.split('.')), port >> 8 & 0xFF, port & 0xFF))
                log("PASV", 'Open socket Address: ' + addr + " and Port: " + str(port))
        except:
            self.sendCommand("500 (EPSV) Failed to create data socket.")
    #-------------------------------------#
    # # Create FTP utilities functions ##
    #-------------------------------------#

    def validateCredentials(self):
        if not self.authenticated:
            for line in open("accounts.txt", "r").readlines():  # checks whether username/password is in the file
                info = line.split()  # splits a string into a list. Default separator is any whitespace.
                if self.username == info[0] and self.passwd == info[1]:
                    self.authenticated = True
                    self.sendCommand('230 User logged in, proceed.\r\n')
                    self.saveAuthentication(True)
                    break
        if not self.authenticated:
            self.sendCommand('Provided credentials are not found.\r\n')
      
    # Function used to save all authentication data together with number of tries to authenticate
    def saveAuthentication(self, resset):
        if self.username is not None and self.passwd is not None:
            user_founded = False
            
            # Read authentication saved data
            file = open('ftpserver.secure', 'r+')  # open the file:
            lines = file.readlines()  # get all your lines from the file
            file.close()  # close the file
            
            file = open('ftpserver.secure', 'w')  # reopen it in write mode
            for line in lines:
                if line.startswith(self.username):  # username found
                    user_founded = True
                    cnt_auth = int(line.split(":")[2])
                    
                    if cnt_auth > 3:
                        self.banned_username = True
                        
                    if resset:
                        file.write(self.username + ":" + self.passwd + ":%d" % (1))
                    else:
                        file.write(self.username + ":" + self.passwd + ":%d" % (cnt_auth + 1))
                    
                else:
                    file.write(line)  # write your lines back
            file.close()  # close the file again
                        
            # means credentials will be inserted into file
            if not user_founded:
                # open a file for writing and create it if does not exist
                with open('ftpserver.secure', 'a+') as f:
                    f.write(self.username + ":" + self.passwd + ":%d" % (1))
            
    def checkBlockedUsername(self):
        if hasattr(self, 'username') and self.username is not None:
            file = open('ftpserver.secure', 'r+')  # open the file:
            lines = file.readlines()  # get all your lines from the file
            for line in lines:
                if line.startswith(self.username):  # username found
                    cnt_auth = int(line.split(":")[2])
                    
                    if cnt_auth > 3:
                        self.banned_username = True
                        return True
        return False
        
    def _support_hybrid_ipv6(self):
        """Return True if it is possible to use hybrid IPv6/IPv4 sockets on this platform.
        """
        # Note: IPPROTO_IPV6 constant is broken on Windows, see:
        # http://bugs.python.org/issue6926
        try:
            if not socket.has_ipv6:
                return False
            return not self.serverSock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
        except:
            return False
        
    def fileProperty(self, filepath):
        """
        return information from given file, like this "-rw-r--r-- 1 User Group 312 Aug 1 2014 filename"
        """
        st = os.stat(filepath)
        file_message = [ ]

        def _getFileMode():
            modes = [
                stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH,
            ]
            mode = st.st_mode
            fullmode = ''
            fullmode += os.path.isdir(filepath) and 'd' or '-'
    
            for i in range(9):
                fullmode += bool(mode & modes[i]) and 'rwxrwxrwx'[i] or '-'
            return fullmode
    
        def _getFilesNumber():
            return str(st.st_nlink)
    
        def _getUser():
            return pwd.getpwuid(st.st_uid).pw_name
    
        def _getGroup():
            return grp.getgrgid(st.st_gid).gr_name
    
        def _getSize():
            return str(st.st_size)
    
        def _getLastTime():
            return time.strftime('%b %d %H:%M', time.gmtime(st.st_mtime))

        for func in ('_getFileMode()', '_getFilesNumber()', '_getUser()', '_getGroup()', '_getSize()', '_getLastTime()'):
            file_message.append(eval(func))
        file_message.append(os.path.basename(filepath))
        return ' '.join(file_message)

    #------------------------------#
    # # Ftp services and functions ##
    #------------------------------#
    
    # Change the working directory to the parent directory.
    def CDUP(self, cmd):
        log('CDUP', self.cwd)
        try:
            self.cwd = os.path.abspath(os.path.join(self.cwd, '..'))
            self.sendCommand('200 CDUP Command successful.\r\n' + self.cwd + '\r\n')
        except Exception as err:
            log('CDUP', err)
    
    # Change the working directory
    def CWD(self, dirpath):
        try:
            pathname = dirpath.endswith(os.path.sep) and dirpath or os.path.join(self.cwd, dirpath)
            log('CWD', pathname)
            if not os.path.exists(pathname) or not os.path.isdir(pathname):
                self.sendCommand('550 CWD failed Directory not exists.\r\n')
                return
            self.cwd = pathname
            self.sendCommand('250 CWD Command successful.' + self.cwd + '\r\n')
        except Exception as err:
            log('CWD', err)
    
    # Specifies an extended port to which the server should connect.
    def EPRT(self, line):
        '''Send a EPRT command with the current host and the given port number.'''
        log('EPRT', line)
        
        try:
            """Start an active data channel by choosing the network 
            protocol to use (IPv4/IPv6) as defined in RFC-2428. """
            if self._epsvall:
                self.sendCommand("501 EPRT not allowed after EPSV ALL.\r\n")
                return
            
            # Parse EPRT request for getting protocol, IP and PORT.
            # Request comes in as:
            # <d>proto<d>ip<d>port<d>
            # ...where <d> is an arbitrary delimiter character (usually "|") and
            # <proto> is the network protocol to use (1 for IPv4, 2 for IPv6).
            try:
                af, ip, port = line.split(line[0])[1:-1]
                port = int(port)
                if not 0 <= port <= 65535:
                    raise ValueError
            except (ValueError, IndexError, OverflowError):
                self.sendCommand("501 Invalid EPRT format.\r\n")
                return
    
            if af == "1":
                # test if AF_INET6 and IPV6_V6ONLY
                if (self._af == socket.AF_INET6 and not self._support_hybrid_ipv6()):
                    self.sendCommand('522 Network protocol not supported (use 2).\r\n')
                    
                else:
                    try:
                        octs = list(map(int, ip.split('.')))
                        if len(octs) != 4:
                            raise ValueError
                        for x in octs:
                            if not 0 <= x <= 255:
                                raise ValueError
                    except (ValueError, OverflowError):
                        self.sendCommand("501 Invalid EPRT format.\r\n")
                    else:
                        self.dataSockAddr = ip
                        self.dataSockPort = port
                        # self.startDataSock()
                        
            elif af == "2":
                if self._af == socket.AF_INET:
                    self.sendCommand('522 Network protocol not supported (use 1).\r\n')
                else:
                    self.dataSockAddr = ip
                    self.dataSockPort = port
                    # self.startDataSock()
            else:
                if self._af == socket.AF_INET:
                    self.sendCommand('501 Unknown network protocol (use 1).\r\n')
                else:
                    self.sendCommand('501 Unknown network protocol (use 2).\r\n')
    
            # The format of EPRT is: EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>
            # <net-prt>:
            # AF Number   Protocol
            # ---------   --------
            # 1           Internet Protocol, Version 4 [Pos81a]
            # 2           Internet Protocol, Version 6 [DH96]
            self.sendCommand('200 Success: ' 
                             +"EPRT |" + af + "|" + self.dataSockAddr + "|" + str(self.dataSockPort) + "|\r\n")
    
        except Exception as err:
            log('EPRT', err)
    
    # Set passive data connection over IPv4 or IPv6 (RFC-2428 - FTP Extensions for IPv6 and NATs)
    def EPSV(self, cmd):
        log('EPSV', cmd)
        try:
            log('EPSV', cmd)
            
            """Start a passive data channel by using IPv4 or IPv6 as defined in RFC-2428. """
            # RFC-2428 specifies that if an optional parameter is given,
            # we have to determine the address family from that otherwise
            # use the same address family used on the control connection.
            # In such a scenario a client may use IPv4 on the control channel
            # and choose to use IPv6 for the data channel.
            # But how could we use IPv6 on the data channel without knowing
            # which IPv6 address to use for binding the socket?
            # Unfortunately RFC-2428 does not provide satisfing information
            # on how to do that.  The assumption is that we don't have any way
            # to know wich address to use, hence we just use the same address
            # family used on the control connection.
            
            if not cmd:
                self._make_epasv(extmode=True)
                
            # IPv4
            elif cmd == "1":
                if self._af != socket.AF_INET:
                    self.sendCommand('522 Network protocol not supported (use 2).\r\n')
                else:
                    self._make_epasv(extmode=True)
                    
            # IPv6
            elif cmd == "2":
                if self._af == socket.AF_INET:
                    self.sendCommand('522 Network protocol not supported (use 1).\r\n')
                else:
                    self._make_epasv(extmode=True)
                    
            elif cmd.lower() == 'all':
                self._epsvall = True
                self.sendCommand('220 Other commands other than EPSV are now disabled.\r\n')
                
            else:
                if self._af == socket.AF_INET:
                    self.sendCommand('501 Unknown network protocol (use 1).\r\n')
                else:
                    self.sendCommand('501 Unknown network protocol (use 2).\r\n')
            
        except Exception as err:
            log('EPSV', err)
    
    # A HELP request asks for human-readable information from the server. 
    # The server may accept this request with code 211 or 214, or reject it with code 502.
    def HELP(self, arg):
        help = """
            214
            CDUP Changes the working directory on the remote host to the parent of the current directory.
                'Syntax: CDUP (go to parent directory).'
            CWD Type a directory path to change working directory.
                'Syntax: CWD [<SP> dir-name] (change working directory).'
            EPRT Initiate a data connection required to transfer data (such as directory listings or files) between the client and server.
                Is required during IPv6 active mode transfers.
                'Syntax: EPRT <SP> |protocol|ip|port| (extended active mode).'
            EPSV Tells the server to enter a passive FTP session rather than Active. (Its use is required for IPv6.) 
                This allows users behind routers/firewalls to connect over FTP when they might not be able to connect over an 
                Active (PORT/EPRT) FTP session. EPSV mode has the server tell the client where to connect for the data port on the server.
                'Syntax: EPSV [<SP> proto/"ALL"] (extended passive mode).'
            HELP Displays help information.
                'Syntax: HELP [<SP> cmd] (show help).'
            LIST [dirpath or filename] This command allows the server to send the list to the passive DTP. If
                 the pathname specifies a path or The other set of files, the server sends a list of files in
                 the specified directory. Current information if you specify a file path name, the server will
                 send the file.
                'Syntax: LIST [<SP> path] (list files).'
            PASS [password], Its argument is used to specify the user password string.
                'Syntax: PASS [<SP> password] (set user password).'
            PASV The directive requires server-DTP in a data port.
                'Syntax: PASV (open passive data connection).'
            PORT [h1, h2, h3, h4, p1, p2] The command parameter is used for the data connection data port
                'Syntax: PORT <sp> h,h,h,h,p,p (open active data connection).'
            PWD Get current working directory.
                'Syntax: PWD (get current working directory).'
            QUIT This command terminates a user, if not being executed file transfer, the server will shut down
                 Control connection
                'Syntax: QUIT (quit current session).'
            RETR This command allows server-FTP send a copy of a file with the specified path name to the data
                connection The other end.
                'Syntax: RETR <SP> file-name (retrieve a file).'
            STOR This command allows server-DTP to receive data transmitted via a data connection, and data is
                 stored as A file server site.
                'Syntax: STOR <SP> file-name (store a file).'
            SYST  This command is used to find the server's operating system type.
                'Syntax: SYST (get operating system type).'
            USER [name], Its argument is used to specify the user's string. It is used for user authentication.
                'Syntax: USER <SP> user-name (set username).'
            \r\n.
            """
        self.sendCommand(help)
    
    # Asks the server to send the contents of a directory over the data connection already established
    def LIST(self, dirpath):
        if not self.authenticated:
            self.sendCommand('530 User not logged in.\r\n')
            return

        if not dirpath:
            pathname = os.path.abspath(os.path.join(self.cwd, '.'))
        elif dirpath.startswith(os.path.sep):
            pathname = os.path.abspath(dirpath)
        else:
            pathname = os.path.abspath(os.path.join(self.cwd, dirpath))

        log('LIST', pathname)
        if not self.authenticated:
            self.sendCommand('530 User not logged in.\r\n')

        elif not os.path.exists(pathname):
            self.sendCommand('550 LIST failed Path name not exists.\r\n')

        else:
            self.sendCommand('150 Listing content.\r\n')
            self.startDataSock()
            if not os.path.isdir(pathname):
                file_message = self.fileProperty(pathname)
                self.dataSock.sock(file_message + '\r\n')

            else:
                for file in os.listdir(pathname):
                    file_message = self.fileProperty(os.path.join(pathname, file))
                    self.sendData(file_message + '\r\n')
            self.stopDataSock()
            self.sendCommand('226 List done.\r\n')
    
    # Set password for current user used to authenticate
    def PASS(self, passwd):
        log("PASS", passwd)
        
        if passwd is None or not passwd:
            self.sendCommand('501 Syntax error in parameters or arguments.\r\n')

        elif not hasattr(self, 'username') or not self.username:
            self.sendCommand('503 The username is not available. '
                             'Please set username first calling the function "USER".\r\n')

        else:
            self.checkBlockedUsername()
            if self.banned_username:
                log('PASS', "The username: " + self.username + " is blocked. You should unlock username first.")
            else:
                self.passwd = passwd
                self.saveAuthentication(False)
                self.validateCredentials()
            
    # Asks the server to accept a data connection on a new TCP port selected by the server. 
    # PASV parameters are prohibited
    def PASV(self, cmd):
        if pasv_mode is not None and pasv_mode.lower().decode() == "yes":
            log("PASV", cmd)
            self.pasv_mode = True
            self.serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.serverSock.bind((HOST, 0))
            self.serverSock.listen(5)
            addr, port = self.serverSock.getsockname()
            self.sendCommand('227 Entering Passive Mode (%s,%u,%u).\r\n' % 
                    (','.join(addr.split('.')), port >> 8 & 0xFF, port & 0xFF))
        else:
           log("PASV", "PASV function is disabled by config file") 
    
    # Use a different mechanism of creating a data connection. The PORT request has a parameter in the form:
    # h1,h2,h3,h4,p1,p2 : meaning that the client is listening for connections on TCP port p1*256+p2 
    # at IP address h1.h2.h3.h4
    def PORT(self, cmd):
        if port_mode is not None and port_mode.lower().decode() == "yes" :
            """Start an active data channel by using IPv4."""
            log("PORT: ", cmd)
            if self.pasv_mode:
                self.servsock.close()
                self.pasv_mode = False
            l = cmd[5:].split(',')
            self.dataSockAddr = '.'.join(l[:4])
            self.dataSockPort = (int(l[4]) << 8) + int(l[5])
            self.sendCommand('200 Get port.\r\n')
        else:
           log("PORT", "PORT function is disabled by config file") 
           
    # Return current working directory
    def PWD(self, cmd):
        log('PWD', cmd)
        self.sendCommand('257 "%s".\r\n' % self.cwd)
    
    def QUIT(self, arg):
        log('QUIT', arg)
        self.authenticated = False
        self.username = None
        self.passwd = None
        self.sendCommand('221 Goodbye.\r\n')
    
    # Send the contents of a file over the data connection already established
    def RETR(self, filename):
        pathname = os.path.join(self.cwd, filename)
        log('RETR', pathname)
        if not os.path.exists(pathname):
            return
        try:
            if self.mode == 'I':
                file = open(pathname, 'rb')
            else:
                file = open(pathname, 'r')
        except OSError as err:
            log('RETR', err)

        self.sendCommand('150 Opening data connection.\r\n')
        if self.rest:
            file.seek(self.pos)
            self.rest = False

        self.startDataSock()
        while True:
            data = file.read(1024)
            if not data: break
            self.sendData(data)
        file.close()
        self.stopDataSock()
        self.sendCommand('226 Transfer complete.\r\n')
    
    # Read the contents of a file and upload to server
    def STOR(self, filename):
        if not self.authenticated:
            self.sendCommand('530 STOR failed User not logged in.\r\n')
            return

        pathname = os.path.join(self.cwd, filename)
        log('STOR', pathname)
        try:
            if self.mode == 'I':
                file = open(pathname, 'wb')
            else:
                file = open(pathname, 'w')
        except OSError as err:
            log('STOR', err)

        self.sendCommand('150 Opening data connection.\r\n')
        self.startDataSock()
        while True:
            data = self.dataSock.recv(1024)
            if not data: break
            file.write(data)
        file.close()
        self.stopDataSock()
        self.sendCommand('226 Transfer completed.\r\n')
    
    # Sets the transfer mode (ASCII/Binary).
    def TYPE(self, type):
        log('TYPE', type)
        self.mode = type
        if self.mode == 'I':
            self.sendCommand('200 Binary mode.\r\n')
        elif self.mode == 'A':
            self.sendCommand('200 Ascii mode.\r\n')
    
    # Information about the server's operating system
    def SYST(self, arg):
        log('SYST', arg)
        self.sendCommand('215 %s type.\r\n' % sys.platform)
    
    # Set the username required to authenticate
    def USER(self, user):
        log("USER", user)
        if not user:
            self.sendCommand('501 Syntax error in parameters or arguments.\r\n')

        else:
            if self.banned_username:
                log('USER', "This username is blocked: " + user)
            else:
                self.sendCommand('331 User name okay, need password.\r\n')
                self.username = user

    # # Optional functions ##

    def NLIST(self, dirpath):
        self.LIST(dirpath)

    def DELE(self, filename):
        pathname = filename.endswith(os.path.sep) and filename or os.path.join(self.cwd, filename)
        log('DELE', pathname)
        if not self.authenticated:
            self.sendCommand('530 User not logged in.\r\n')

        elif not os.path.exists(pathname):
            self.sendCommand('550 DELE failed File %s not exists.\r\n' % pathname)

        elif not allow_delete:
            self.sendCommand('450 DELE failed delete not allow.\r\n')

        else:
            os.remove(pathname)
            self.sendCommand('250 File deleted.\r\n')

    def MKD(self, dirname):
        pathname = dirname.endswith(os.path.sep) and dirname or os.path.join(self.cwd, dirname)
        log('MKD', pathname)
        if not self.authenticated:
            self.sendCommand('530 User not logged in.\r\n')

        else:
            try:
                os.mkdir(pathname)
                self.sendCommand('257 Directory created.\r\n')
            except OSError:
                self.sendCommand('550 MKD failed Directory "%s" already exists.\r\n' % pathname)

    def RMD(self, dirname):
        import shutil
        pathname = dirname.endswith(os.path.sep) and dirname or os.path.join(self.cwd, dirname)
        log('RMD', pathname)
        if not self.authenticated:
            self.sendCommand('530 User not logged in.\r\n')

        elif not allow_delete:
            self.sendCommand('450 Directory deleted.\r\n')

        elif not os.path.exists(pathname):
            self.sendCommand('550 RMDIR failed Directory "%s" not exists.\r\n' % pathname)

        else:
            shutil.rmtree(pathname)
            self.sendCommand('250 Directory deleted.\r\n')

    def RNFR(self, filename):
        pathname = filename.endswith(os.path.sep) and filename or os.path.join(self.cwd, filename)
        log('RNFR', pathname)
        if not os.path.exists(pathname):
            self.sendCommand('550 RNFR failed File or Directory %s not exists.\r\n' % pathname)
        else:
            self.rnfr = pathname

    def RNTO(self, filename):
        pathname = filename.endswith(os.path.sep) and filename or os.path.join(self.cwd, filename)
        log('RNTO', pathname)
        if not os.path.exists(os.path.sep):
            self.sendCommand('550 RNTO failed File or Direcotry  %s not exists.\r\n' % pathname)
        else:
            try:
                os.rename(self.rnfr, pathname)
            except OSError as err:
                log('RNTO', err)

    def REST(self, pos):
        self.pos = int(pos)
        log('REST', self.pos)
        self.rest = True
        self.sendCommand('250 File position reseted.\r\n')

    def APPE(self, filename):
        if not self.authenticated:
            self.sendCommand('530 APPE failed User not logged in.\r\n')
            return

        pathname = filename.endswith(os.path.sep) and filename or os.path.join(self.cwd, filename)
        log('APPE', pathname)
        self.sendCommand('150 Opening data connection.\r\n')
        self.startDataSock()
        if not os.path.exists(pathname):
            if self.mode == 'I':
                file = open(pathname, 'wb')
            else:
                file = open(pathname, 'w')
            while True:
                data = self.dataSock.recv(1024)
                if not data:
                    break
                file.write(data)

        else:
            n = 1
            while not os.path.exists(pathname):
                filename, extname = os.path.splitext(pathname)
                pathname = filename + '(%s)' % n + extname
                n += 1

            if self.mode == 'I':
                file = open(pathname, 'wb')
            else:
                file = open(pathname, 'w')
            while True:
                data = self.dataSock.recv(1024)
                if not data:
                    break
                file.write(data)
        file.close()
        self.stopDataSock()
        self.sendCommand('226 Transfer completed.\r\n')


def serverListener():
    
    ''' AF_INET refers to the address family ipv4 '''
    ''' SOCK_STREAM means connection oriented TCP protocol '''
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((HOST, PORT))
    listen_sock.listen(5)  # put the socket into listening mode
    
    log('Server started', 'Listen on: %s, %s' % listen_sock.getsockname())
    
    ''' a forever loop until we interrupt it or an error occurs '''
    while True:
        connection, address = listen_sock.accept()  # Establish connection with client.
        f = FtpServerProtocol(connection, address)
        f.start()
        log('Accept', 'Created a new connection %s, %s' % address)
            

if __name__ == "__main__":
    
    # if config file is not configured properly the stop the server
    if port_mode.lower().decode() == "no" and pasv_mode.lower().decode() == "no":
        log('Server stop', "PortMode and PasvMode can't be both disabled. Please check config file")
        sys.exit()
        
    # the program should have 2 arguments: `1- log file; 2- port number
    if len(sys.argv) == 3:  # Should be check for 3 because the first argument is the running filename

        arg_log_file = sys.argv[1]  # This should be the path file to write logs
        arg_port = int(sys.argv[2])  # This should be the port number to run the server 

        if os.path.exists(os.path.dirname(arg_log_file)):
            logfile = arg_log_file
        else:
            logfile = os.getcwd() + r'/' + arg_log_file
        
        if not 0 <= arg_port <= 65535:
            log('Server stop', 'The port number should be between 0 and 65535')
            sys.exit()
        else:
            PORT = arg_port
            
        log('Start ftp server:', 'Enter q or Q to stop ftpServer...')
        listener = threading.Thread(target=serverListener)
        listener.start()
    
        if sys.version_info[0] < 3:
            input = raw_input
    
        if input().lower() == "q":
            listen_sock.close()
            log('Server stop', 'Server closed')
            sys.exit()
        
    else:  # send error
       log('Server stop', 'To start the socket server you should pass 2 arguments')
       log('Server stop', 'First is the log file and the Second is the port which the program will be running')
       log('Server stop', 'Syntax: python ftp_server_v0.1 socket-server.log 8888.')
       sys.exit()
