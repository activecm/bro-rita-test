#Bro-RITA Tests

This is a suite of integration tests for [Bro-RITA](https://github.com/activecm/bro-rita), a plugin for writing Bro IDS records to MongoDB.

The test suite relies on [docker-ca](https://github.com/activecm/docker-ca) and [mongo-diff](https://github.com/activecm/mongo-diff).
Docker-ca is used to generate certificates for testing TLS and X.509 mutual authentication, while mongo-diff is used to ensure Bro-RITA is 
a drop in replacement for RITA's existing parser.

To run the test suite simply clone the repo and run `./test.sh`. 

### Tests

- Drop in replacement test for RITA's existing parser
- SCRAM-SHA-1 test
- TLS (Skip server authentication)
- TLS (Enforce server authentication)
- TLS/X.509 (Mutual Authentication) 
