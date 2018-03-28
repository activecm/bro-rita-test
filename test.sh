cd "$(dirname "$(realpath "$0")")";
_HEADER="***** "
export MONGO_INITDB_ROOT_USERNAME="test_user"
export MONGO_INITDB_ROOT_PASSWORD="test_pass"

if [ ! -d "./mongo-diff" ]; then
    echo "$_HEADER Downloading mongo-diff"
    git clone https://github.com/ocmdev/mongo-diff
fi

if [ ! -f "./pcap/test.pcap" ]; then
    echo "$_HEADER MISSING ./pcap/test.pcap"
    exit
fi

if [ "$(docker images -q ocmdev/rita:bro-rita-test 2> /dev/null)" == "" ]; then
  docker load rita/rita-test-build.tar.gz
fi

docker-compose down -v > /dev/null 2>&1

printf "$_HEADER Building Test Images\n"
docker-compose build > /dev/null

# TEST 1: RITA COMPLIANCE
echo ""
echo "$_HEADER Running Bro and RITA without authentication or encryption"
docker-compose up -d db > /dev/null 2>&1
echo "Running Bro IDS..."
docker-compose run --rm bro-rita -Cr ../pcap/test.pcap rita.bro \
  "RITAWriter::URI = \"mongodb://db:27017\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\""

sleep 5
echo "Running RITA..."
docker-compose run --rm rita import

echo ""
echo "$_HEADER Comparing Databases"
docker-compose run --rm mongo-diff mongodb://db:27017 RITA-TEST PLUGIN-TEST

docker-compose down -v > /dev/null 2>&1


# TEST 2: AUTHENTICATION
echo "$_HEADER Testing authenticated connections"
docker-compose up -d db-auth > /dev/null 2>&1
sleep 5
docker-compose run --rm bro-rita -Cr ../pcap/test-small.pcap rita.bro \
  "RITAWriter::URI = \"mongodb://$MONGO_INITDB_ROOT_USERNAME:$MONGO_INITDB_ROOT_PASSWORD@db-auth:27017\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\""

docker-compose run --rm db-client mongodb://$MONGO_INITDB_ROOT_USERNAME:$MONGO_INITDB_ROOT_PASSWORD@db-auth:27017/admin --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Authenticated connection successful"
else
    echo "Authenticated connection unsuccessful"
fi

docker-compose down -v > /dev/null 2>&1

# TEST 3: ENCRYPTION
if [ ! -d "./tls" ]; then
    echo "$_HEADER Generating TLS certificates"
    mkdir tls
    docker-compose run docker-ca server mongodb-tls db-tls > /dev/null
    docker-compose run docker-ca server mongodb-x509 db-x509 > /dev/null
    docker-compose run docker-ca client user1 user1@alice.fake > /dev/null
    docker cp broritatest_docker-ca_run_1:/root/ca/certs/ca.cert.pem ./tls/ca.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/ca-chain.cert.pem ./tls/ca-chain.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/mongodb-tls.key.pem ./tls/mongodb-tls.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/mongodb-tls.cert.pem ./tls/mongodb-tls.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/mongodb-x509.key.pem ./tls/mongodb-x509.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/mongodb-x509.cert.pem ./tls/mongodb-x509.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/user1.key.pem ./tls/user1.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/user1.cert.pem ./tls/user1.cert.pem
    yes | docker-compose rm docker-ca > /dev/null
    cat ./tls/mongodb-tls.key.pem  ./tls/mongodb-tls.cert.pem  > ./tls/mongodb-tls.pem
    cat ./tls/mongodb-x509.key.pem ./tls/mongodb-x509.cert.pem > ./tls/mongodb-x509.pem
    cat ./tls/user1.key.pem ./tls/user1.cert.pem > ./tls/user1.pem
    rm -f ./tls/mongodb-tls.key.pem  ./tls/mongodb-tls.cert.pem \
          ./tls/mongodb-x509.key.pem ./tls/mongodb-x509.cert.pem \
          ./tls/user1.key.pem ./tls/user1.cert.pem
fi

echo "$_HEADER Testing encrypted connections (no-verification)"
docker-compose up -d db-tls > /dev/null 2>&1
sleep 5
docker-compose run --rm bro-rita -Cr ../pcap/test-small.pcap rita.bro \
  "RITAWriter::URI = \"mongodb://db-tls:27017/admin?ssl=true\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\"" \
  "RITAWriter::VERIFY_CERT = \"false\""

docker-compose run --rm db-client mongodb://db-tls:27017/admin --ssl --sslAllowInvalidCertificates --sslAllowInvalidHostnames --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Encrypted connection successful"
else
    echo "Encrypted connection unsuccessful"
fi

docker-compose down -v > /dev/null 2>&1

echo "$_HEADER Testing encrypted connections (with-verification)"
docker-compose up -d db-tls > /dev/null 2>&1
sleep 5
docker-compose run --rm bro-rita -Cr ../pcap/test-small.pcap rita.bro \
  "RITAWriter::URI = \"mongodb://db-tls:27017/admin?ssl=true\"" \
  "RITAWriter::DB = \"PLUGIN-TEST\"" \
  "RITAWriter::CA_FILE = \"/root/tls/ca-chain.cert.pem\""

docker-compose run --rm db-client mongodb://db-tls:27017/admin --ssl --sslCAFile /etc/ssl/ca-chain.cert.pem --eval "db.adminCommand('listDatabases')" | grep -q "PLUGIN-TEST"
if [ $? -eq 0 ]; then
    echo "Encrypted connection successful"
else
    echo "Encrypted connection unsuccessful"
fi

docker-compose down -v > /dev/null 2>&1

echo "$_HEADER Testing encrypted connections (with-verification) with X.509 mutual authentication"
docker-compose up -d db-x509 > /dev/null 2>&1
sleep 5
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

docker-compose run --rm bro-rita -Cr ../pcap/test-small.pcap rita.bro \
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
fi

docker-compose down -v > /dev/null 2>&1

