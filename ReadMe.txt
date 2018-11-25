Saugat Sthapit
README

Python version- 2.7
Tested using Eclipse, FileZilla on MacOS Mojave 10.14 
Supports multiple clients

First:
Make sure configuration file is properly configured. 
Configuration file: ftpserverd.conf

Steps:
To start server
 python server.py logAandE 8886 (python <filename.py> <logfile> <port>)


‘accounts.txt’ file is hardcoded. This is where the username and password are found. In this case, we have admin and admin as username and password so you can login with these credentials.


USER admin
PASS admin


Now you can use your FTP client- I use FileZilla to initiate data transfer and test the server. Everything works! 


Code is properly documented, however just in case, below are the descriptions of each functions implemented in the code.




Functions Descriptions:


#### CDUP
The CDUP command causes the server to change the client's current working directory to the immediate parent directory of the current working directory. For example, if a client's current working directory is /usr/files, issuing the CDUP command will change the working directory to /usr.


Common responses
200 |
421 |
500, 501, 502, 530, 550






#### CWD
The CWD command is issued to change the client's current working directory to the path specified with the command. FileZilla and other GUI-based FTP clients will automatically issue these commands as the user browses the remote file system from within the program.


Common responses
250 |
421 |
500, 501, 502, 530, 550


#### EPRT (Extended Data Port)
The EPRT command is issued by the client to initiate a data connection required to transfer data (such as directory listings or files) between the client and server. The PORT command is used during "active" mode transfers and its use is required during IPv6 active mode transfers.


When issuing the EPRT command, the client will include information on the address and port that the server is to use in order to connect back to the client. Thus, the structure of the EPRT command is clearly defined to allow servers to parse this information from the command. The structure of the EPRT command is: EPRT (|af|network address|Port|).


AF - The AF indicates the version of Internet Protocol used by the connection. 1 represents IPv4, 2 represents IPv6.
Network Address - The Network Address is the IP Address of the client, either IPv4 or IPv6 depending on the AF.
Port - The port number for the server to connect on.


Common Responses
200 |
530, 522, 501


#### EPSV (Extended Passive Mode)
The EPSV command tells the server to enter a passive FTP session rather than Active. (Its use is required for IPv6.) This allows users behind routers/firewalls to connect over FTP when they might not be able to connect over an Active (PORT/EPRT) FTP session. EPSV mode has the server tell the client where to connect for the data port on the server.


When issuing the EPSV command, the client will include information on the port that the server is to use in order to connect back to the client. Thus, the structure of the EPSV command is clearly defined to allow servers to parse this information from the command. The structure of the EPSV command is: EPSV (|||Port|). The EPSV command does not include IP address information since it is assumed that the IP address of the data channel is the same as the address of the control channel.


FTP:Response to Port 50209, '229  Entering Extended Passive Mode (|||34347|)'


#### LIST
The LIST command is issued to transfer information about files on the server through a previously established data connection. When no argument is provided with the LIST command, the server will send information on the files in the current working directory. If the argument specifies a directory or other group of files, the server should transfer a list of files in the specified directory. If the argument specifies a file, then the server should send current information about the file.


Advanced options
The server supports the option to return full paths in the LIST command in the command response. Enabling this advanced option allows server to return the full path when LIST is issued for a specific file. The format is:
-rw-rw-rw- 1 user group 0 Nov 11 19:00 /subdirectory/file.txt 
Instead of: 
-rw-rw-rw- 1 user group 0 Nov 11 19:00 file.txt


Common responses
110, 150 |
226, 250 |
421, 425, 426, 450, 451 |
500, 501, 502, 530, 534, 535


#### PASS
A PASS request has a parameter called a password. The client must not send a PASS request except immediately after a USER request.
The server may accept PASS with code 230, meaning that permission to access files under this username has been granted; or with code 202, meaning that permission was already granted in response to USER; or with code 332, meaning that permission might be granted after an ACCT request. The server may reject PASS with code 503 if the previous request was not USER or with code 530 if this username and password are jointly unacceptable.


If USER is accepted with code 230, clients do not need to bother sending PASS. However, pipelining clients will normally send PASS without waiting for the USER response, and many of today's non-pipelining clients send PASS in every case; so it is important for the server to accept PASS with code 202.


#### PASV
This command tells the server to enter a passive FTP session rather than Active. This allows users behind routers/firewalls to connect over FTP when they might not be able to connect over an Active (PORT) FTP session. PASV mode has the server tell the client where to connect the data port on the server.


Common responses
227 |
421 |
500, 501, 502, 530


#### PORT
The PORT command is issued by the client to initiate a data connection required to transfer data (such as directory listings or files) between the client and server. This command is used during "active" mode transfers.


When issuing the PORT command, the client will include information on the address and port that the server is to use in order to connect back to the client. Thus, the structure of this command is clearly defined to allow servers to parse this information from the command. 
The structure of the command is: PORT (h1,h2,h3,h4,p1,p2).


The numbers used for the values of h1-h4 constitute the IP address the server should connect on. The numbers used for the values of p1-p2 are used to calculate the port number. In order to get the decimal value of the port, the following formula is used: (p1 * 256) + p2 = data port.


Common responses
200 |
421 |
500, 501, 530


#### PWD
This command displays the current working directory on the server for the logged in user.


Common responses
257 |
421 |
500, 501, 502, 550


#### QUIT
This command ends a USER session and if file transfer is not in progress, the server closes the control connection. If file transfer is in progress, the connection will remain open so it can receive the response from the data transfer before the server closes it.


Note: An unexpected close on the control connection will cause the server to effectively respond as though an abort (ABOR) and a logout (QUIT) were issued.


Common responses
221 |
500


#### RETR
A client issues the RETR command after successfully establishing a data connection when it wishes to download a copy of a file on the server. The client provides the file name it wishes to download along with the RETR command. The server will send a copy of the file to the client. This command does not affect the contents of the server's copy of the file.


Common responses
110, 125, 150 |
226, 250 |
421, 425, 426, 450, 451 |
500, 501, 530, 534, 535, 550


#### STOR
A client issues the STOR command after successfully establishing a data connection when it wishes to upload a copy of a local file to the server. The client provides the file name it wishes to use for the upload. If the file already exists on the server, it is replaced by the uploaded file. If the file does not exist, it is created. This command does not affect the contents of the client's local copy of the file.


Common responses
110, 125, 150 |
226, 250 |
421, 425, 426, 450, 451, 452 |
500, 501, 530, 532, 534, 535, 551, 552, 553


#### SYST
A client can issue this command to the server to determine the operating system running on the server. Not all server responses are accurate in this regard, however, as some servers respond with the system they emulate or may not respond at all due to potential security risks.


Common responses
215 |
421 |
500, 501, 502


#### TYPE
The TYPE command is issued to inform the server of the type of data that is being transferred by the client. Most modern Windows FTP clients deal only with type A (ASCII) and type I (image/binary).


Text data is usually transferred as type ASCII so that the server knows to convert the data according to its local storage specifications (relevant when transferring across platforms such as from a Windows client to a Linux server or vice versa). Auto-ASCII is a commonly supported FTP client feature that automatically manages the changing of the representation type based upon the extension of the file the client is transferring.


Common responses
200 |
421 |
500, 501, 504, 530


#### USER
USER is followed by a text string identifying the user. The user identification is that which is required by the server for access to its file system. This command will normally be the first command transmitted by the user after the control connections are made. This command is usually followed by the PASS (Password) command.


Common responses
230, 232 |
331, 332, 336 |
421 |
500, 501, 530


#### NLIST
List contents of remote directory.


#### DELE
The DELE command is used to delete the specified file from the server. To delete a directory, use the RMD command.


Common responses
250 |
421, 450 |
500, 501, 502, 530, 550


#### MKD
This command causes the directory specified in the pathname to be created on the server. If the specified directory is a relative directory, it is created in the client's current working directory.


Common responses
257 |
421 |
500, 501, 502, 530, 550


#### RMD
This command causes the directory specified in the path name to be removed. If a relative path is provided, the server assumes the specified directory to be a subdirectory of the client's current working directory. To delete a file, the DELE command is used.


Common responses
250 |
421 |
500, 501, 502, 530, 550


#### RNFR
The RNFR command is issued when an FTP client wants to rename a file on the server. The client specifies the name of the file to be renamed along with the command. After issuing an RNFR command, an RNTO command must immediately follow.


Common responses
350 |
421, 450 |
500, 501, 502, 530, 550


#### RNTO
The RNTO command is used to specify the new name of a file specified in a preceding RNFR (Rename From) command.


Common responses
250 |
421 |
500, 501, 502, 503, 530, 532, 553


#### REST
The REST command is used to specify a marker to the server for the purposes of resuming a file transfer. Issuing the REST command does not actually initiate the transfer. After issuing a REST command, the client must send the appropriate FTP command to transfer the file. The server will use the marker specified in the REST command to resume file transfer at the specified point.


Common responses
350 |
421 |
500, 501, 502, 530


#### APPE
A client issue the APPE command after successfully establishing a data connection when it wishes to upload data to the server. The client provides the file name it wishes to use for the upload. If the file already exists on the server, the data is appended to the existing file. If the file does not exist, it is created.


Common responses
110, 125, 150 |
226, 250 |
421, 425, 426, 450, 451 |
500, 501, 502, 530, 534, 535, 551, 552