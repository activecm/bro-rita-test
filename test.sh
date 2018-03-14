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
    docker-compose run docker-ca server mongodb db-tls > /dev/null
    docker cp broritatest_docker-ca_run_1:/root/ca/certs/ca.cert.pem ./tls/ca.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/ca-chain.cert.pem ./tls/ca-chain.cert.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/private/mongodb.key.pem ./tls/mongodb.key.pem
    docker cp broritatest_docker-ca_run_1:/root/ca/intermediate/certs/mongodb.cert.pem ./tls/mongodb.cert.pem
    yes | docker-compose rm docker-ca > /dev/null
    cat ./tls/mongodb.key.pem ./tls/mongodb.cert.pem > ./tls/mongodb.pem
    rm -f ./tls/mongodb.key.pem ./tls/mongodb.cert.pem
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
