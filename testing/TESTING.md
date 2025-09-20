# testing guide

this guide explains how to run tests and generate code coverage reports for the fmcrypto Service.

## quick start

### to run all tests with coverage
```bash
cd testing
./run_tests.sh
```

### to run indivisual tests
```bash
cd testing
source .venv/bin/activate
export PYTHONPATH="../:$PYTHONPATH"
python -m pytest test_crypto_utils.py::TestCryptoUtils::test_serialize_pk_invalid_object -v
```

### to run sonarcube analysis
```bash
cd testing
export SONAR_TOKEN="your_sonarqube_token_here"
./run_sonar.sh
```

## configuration

### pytest.ini
- configure pytest with coverage settings

### sonar-project.properties
- define sonarqube project settings


## Environment Variables

tests require these environment variables:
```bash
export HSM_IP="localhost"
export HSM_PORT="1234" 
export CRYPTO_HSM="GP"
export ENVIRONMENT="test"
```
