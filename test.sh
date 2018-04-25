#! /bin/bash
set -e

cd "$(dirname "$(realpath "$0")")";
_HEADER="***** "
export MONGO_INITDB_ROOT_USERNAME="test_user"
export MONGO_INITDB_ROOT_PASSWORD="test_pass"
_MONGO_INIT_TIME="10"
_PCAP_FOLDER="./pcap"
_LARGE_PCAP="$_PCAP_FOLDER/large.pcap"
_SMALL_PCAP="$_PCAP_FOLDER/small.pcap"
_LARGE_PCAP_IN=".$_LARGE_PCAP"
_SMALL_PCAP_IN=".$_SMALL_PCAP"

_STATUS=0

__set_fail() {
    _STATUS=1
}

# PREREQUISITES

# Grab mongo-diff #TODO: Autobuild mongo-diff and pull from quay
if [ ! -d "./mongo-diff" ]; then
    echo "$_HEADER MISSING mongo-diff"
    git clone https://github.com/activecm/mongo-diff
    echo ""
fi

# Grab docker-ca
if [ ! -d "./docker-ca" ]; then
    echo "$_HEADER MISSING docker-ca"
    git clone https://github.com/activecm/docker-ca.git
    echo ""
fi

# Grab PCAPs
if [ ! -f "$_LARGE_PCAP" ]; then
    mkdir -p "$_PCAP_FOLDER"
    echo "$_HEADER MISSING $_LARGE_PCAP"
    wget -q --show-progress -O "$_LARGE_PCAP.gz" "https://download.netresec.com/pcap/maccdc-2012/maccdc2012_00016.pcap.gz"
    gunzip "$_LARGE_PCAP.gz"
    echo ""
fi

if [ ! -f "$_SMALL_PCAP" ]; then
    echo "$_HEADER MISSING $_SMALL_PCAP"
    wget -q --show-progress -O "$_SMALL_PCAP" "https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=msnms.pcap"
    echo ""
fi

# Grab RITA
if [ "$(docker images -q activecm/rita:bro-rita-test 2> /dev/null)" == "" ]; then
    echo "$_HEADER MISSING activecm/rita:bro-rita-test"
    wget -q --show-progress -O /tmp/rita-test-build.tar.gz https://github.com/activecm/bro-rita-test/releases/download/v0.9/rita-test-build.tar.gz
    docker load -i /tmp/rita-test-build.tar.gz
    rm /tmp/rita-test-build.tar.gz
    echo ""
fi

# Bring the system down if its running
docker-compose down -v > /dev/null 2>&1

# Build the latest images
printf "$_HEADER Building Test Images\n"
docker-compose build > /dev/null
echo ""

# Generate TLS certificates
if [ ! -d "./tls" ]; then
    echo "$_HEADER Generating TLS certificates"
    mkdir -p tls
    docker-compose run docker-ca server mongodb-tls db-tls > /dev/null 2>&1
    docker-compose run docker-ca server mongodb-x509 db-x509 > /dev/null 2>&1
    docker-compose run docker-ca client user1 user1@alice.fake > /dev/null 2>&1
    docker cp broritatest_docker-ca_run_1:/root/ca/certs/ca.cert.pem ./tls/ca.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/ca-chain.cert.pem ./tls/ca-chain.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/mongodb-tls.key.pem ./tls/mongodb-tls.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/mongodb-tls.cert.pem ./tls/mongodb-tls.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/mongodb-x509.key.pem ./tls/mongodb-x509.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/mongodb-x509.cert.pem ./tls/mongodb-x509.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/user1.key.pem ./tls/user1.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/user1.cert.pem ./tls/user1.cert.pem
    yes | docker-compose rm docker-ca > /dev/null 2>&1
    cat ./tls/mongodb-tls.key.pem  ./tls/mongodb-tls.cert.pem  > ./tls/mongodb-tls.pem
    cat ./tls/mongodb-x509.key.pem ./tls/mongodb-x509.cert.pem > ./tls/mongodb-x509.pem
    cat ./tls/user1.key.pem ./tls/user1.cert.pem > ./tls/user1.pem
    rm -f ./tls/mongodb-tls.key.pem  ./tls/mongodb-tls.cert.pem \
          ./tls/mongodb-x509.key.pem ./tls/mongodb-x509.cert.pem \
          ./tls/user1.key.pem ./tls/user1.cert.pem
    echo ""
fi

# TEST 1: RITA COMPLIANCE
echo "$_HEADER Running Bro and RITA without authentication or encryption"
docker-compose up -d db > /dev/null 2>&1
sleep "$_MONGO_INIT_TIME"

echo "Running Bro IDS..."
docker-compose run --rm bro-rita -Cr "$_LARGE_PCAP_IN" rita.bro \
  "RITAWriter::URI = \"mongodb://db:27017\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\""
sleep 5

# BUG: Sometimes RITA doesn't see the log files?
echo "Running RITA..."
docker-compose run --rm rita import

echo ""
echo "$_HEADER Comparing Databases"
docker-compose run --rm mongo-diff mongodb://db:27017 RITA-TEST PLUGIN-TEST
if [ $? -ne 0 ]; then 
    __set_fail
fi
echo ""

docker-compose down -v > /dev/null 2>&1

# TEST 2: AUTHENTICATION
echo "$_HEADER Testing authenticated connections"
docker-compose up -d db-auth > /dev/null 2>&1
sleep "$_MONGO_INIT_TIME"

docker-compose run --rm bro-rita -Cr "$_SMALL_PCAP_IN" rita.bro \
  "RITAWriter::URI = \"mongodb://$MONGO_INITDB_ROOT_USERNAME:$MONGO_INITDB_ROOT_PASSWORD@db-auth:27017\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\""

docker-compose run --rm db-client mongodb://$MONGO_INITDB_ROOT_USERNAME:$MONGO_INITDB_ROOT_PASSWORD@db-auth:27017/admin --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Authenticated connection successful"
else
    echo "Authenticated connection unsuccessful"
    __set_fail
fi
echo ""

docker-compose down -v > /dev/null 2>&1

# TEST 3: ENCRYPTION NO VERIFICATION
echo "$_HEADER Testing encrypted connections (no-verification)"
docker-compose up -d db-tls > /dev/null 2>&1
sleep "$_MONGO_INIT_TIME"

docker-compose run --rm bro-rita -Cr "$_SMALL_PCAP_IN" rita.bro \
  "RITAWriter::URI = \"mongodb://db-tls:27017/admin?ssl=true\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\"" \
  "RITAWriter::VERIFY_CERT = \"false\""

docker-compose run --rm db-client mongodb://db-tls:27017/admin --ssl --sslAllowInvalidCertificates --sslAllowInvalidHostnames --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Encrypted connection successful"
else
    echo "Encrypted connection unsuccessful"
    __set_fail
fi
echo ""

docker-compose down -v > /dev/null 2>&1

# TEST 4: ENCRYPTION WITH VERIFICATION
echo "$_HEADER Testing encrypted connections (with-verification)"
docker-compose up -d db-tls > /dev/null 2>&1
sleep "$_MONGO_INIT_TIME"

docker-compose run --rm bro-rita -Cr "$_SMALL_PCAP_IN" rita.bro \
  "RITAWriter::URI = \"mongodb://db-tls:27017/admin?ssl=true\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\"" \
  "RITAWriter::CA_FILE = \"/root/tls/ca-chain.cert.pem\""

docker-compose run --rm db-client mongodb://db-tls:27017/admin --ssl --sslCAFile /etc/ssl/ca-chain.cert.pem --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Encrypted connection successful"
else
    echo "Encrypted connection unsuccessful"
    __set_fail
fi
echo ""

docker-compose down -v > /dev/null 2>&1

#TEST 5: ENCRYPTION WITH X.509 MUTUAL AUTHENTICATION
echo "$_HEADER Testing encrypted connections (with-verification) with X.509 mutual authentication"
docker-compose up -d db-x509 > /dev/null 2>&1
sleep "$_MONGO_INIT_TIME"

_USER_DN="CN=user1@alice.fake,OU=Clients,O=Alice Ltd,ST=England,C=GB"
_ADD_X509_USER_CMD="db.getSiblingDB(\"\$external\").runCommand(
    {
        createUser: \"$_USER_DN\",
        roles: [
            { role: 'root', db: 'admin' },
        ],
        writeConcern: { w: \"majority\", wtimeout: 5000 }
    }
)"
_X509_AUTH_CMD="db.getSiblingDB(\"\$external\").auth(
    {
        mechanism: \"MONGODB-X509\",
        user: \"$_USER_DN\"
    }
)"

#use the localhost exception to create the first user
docker-compose exec db-x509 mongo -ssl --sslAllowInvalidCertificates --sslAllowInvalidHostnames --sslPEMKeyFile /etc/ssl/user1.pem --eval "$_ADD_X509_USER_CMD" > /dev/null 2>&1

docker-compose run --rm bro-rita -Cr "$_SMALL_PCAP_IN" rita.bro \
  "RITAWriter::URI = \"mongodb://db-x509:27017/admin?ssl=true&authMechanism=MONGODB-X509\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\"" \
  "RITAWriter::CA_FILE = \"/root/tls/ca-chain.cert.pem\"" \
  "RITAWriter::CLIENT_CERT = \"/root/tls/user1.pem\""

docker-compose run --rm db-client mongodb://db-x509:27017/admin -ssl --sslCAFile /etc/ssl/ca-chain.cert.pem --sslPEMKeyFile /etc/ssl/user1.pem \
    --eval "$_X509_AUTH_CMD; db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"

if [ $? -eq 0 ]; then
    echo "X.509 mutual auth successful"
else
    echo "X.509 mutual auth connection unsuccessful"
    __set_fail
fi
echo ""

docker-compose down -v > /dev/null 2>&1
exit $_STATUS
