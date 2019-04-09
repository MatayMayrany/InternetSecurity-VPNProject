# Final VPN project
### Project for the Internet Security and Privacy course IK2206. 

## How to run the VPN

In order to run the VPN you need to run the ForwardServer class.

You should run the ForwardServer class with specific program arguments:

`--handshakeport=2206 --usercert=certs/server.pem --cacert=certs/CA.pem --key=certs/serverprivatekey.pem`

These are program arguments for the client:

`--handshakehost=localhost --handshakeport=2206 --targethost=localhost --targetport=1337 --usercert=certs/client.pem --cacert=certs/CA.pem --key=certs/clientprivatekey.der`

## How to test it

Open a netcat listening to the target port specified by the client.

Connect a netcat to the client's forward port that it specifies in the logs of its program after the handshake is complete.

You should then be able to write text between the two netcats.

Test the encryption is working by looking at the ForwardThread file and uncomment the block of code specified in the file.
