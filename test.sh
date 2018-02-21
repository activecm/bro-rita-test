cd "$(dirname "$(realpath "$0")")";

if [ ! -d "./mongo-diff" ]; then
    echo "***** Downloading mongo-diff"
    git clone https://github.com/ocmdev/mongo-diff
fi

if [ ! -f "./pcap/test.pcap" ]; then
    echo "***** MISSING ./pcap/test.pcap"
    exit
fi

docker-compose down -v > /dev/null 2>&1

printf "***** Building Test Images\n"
docker-compose build

printf "\n***** Running Bro and RITA\n"
docker-compose up -d db > /dev/null 2>&1
docker-compose run --rm bro-rita -Cr ../pcap/test.pcap rita.bro "RITAWriter::URI = \"mongodb://db:27017\"" "RITAWriter::DB = \"PLUGIN-TEST\""
sleep 5
docker-compose run --rm rita import

printf "\n***** Comparing Databases\n"
docker-compose run --rm mongo-diff mongodb://db:27017 RITA-TEST PLUGIN-TEST

docker-compose stop db > /dev/null 2>&1
