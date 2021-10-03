#!/bin/sh

# Generate self signed root CA cert
openssl  req -nodes -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -subj "/C=IN/ST=Karnataka/L=Bangalore/O=Bluechink.com/OU=root/CN=`hostname -f`/emailAddress=magesh.s@bluechink.com"
#openssl  req -nodes -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=root/CN=example.com/emailAddress=admin@crescent.com"


# Generate server cert to be signed
openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -days 3650 -subj "/C=IN/ST=Karnataka/L=Bangalore/O=Bluechink.com/OU=Server/CN=`hostname -f`/emailAddress=magesh.s@bluechink.com"
#openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=server/CN=example.com/emailAddress=admin@crescent.com"

# Sign the server cert
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Create server PEM file
cat server.key server.crt > server.pem


# Generate client cert to be signed#
openssl req -nodes -newkey rsa:2048 -keyout client.key -out client.csr -days 3650 -subj "/C=IN/ST=Karnataka/L=Bangalore/O=Bluechink.com/OU=Client/CN=`hostname -f`/emailAddress=magesh.s@bluechink.com"
#openssl req -nodes -newkey rsa:2048 -keyout client.key -out client.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=client"

# Sign the client cert
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -out client.crt

# Create client PEM file
cat client.key client.crt > client.pem

#remote certificate requests
rm -f *.csr *.srl

# Verify server  Certificate
openssl verify -purpose sslserver -CAfile ca.crt server.crt

# Verify Client Certificate
openssl verify -purpose sslclient -CAfile ca.crt client.crt

mv ca.* /home/magesh/02_Work/Openssl/ca
mv client.* /home/magesh/02_Work/Openssl/client
mv server.* /home/magesh/02_Work/Openssl/server


# Create clientPFX file (for Java, C#, etc)
# openssl pkcs12 -inkey client.key -in client.crt -export -out client.pfx


# Start mongod with SSL
# mkdir -p data/db
# mongod --sslMode requireSSL --sslPEMKeyFile server.pem --sslCAFile ca.crt --dbpath data/db --logpath data/mongod.log --fork

# Connect to mongod with SSL
# mongo --ssl --sslCAFile ca.crt --sslPEMKeyFile client.pem --host `hostname -f`
