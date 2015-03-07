

# Installation
## Python requirements
* python-mcrypt
* python-iptools

## Backend
```
cd /usr/local
git clone https://github.com/zarya/phpipam-powerdns-backend.git
cd phpipam-powerdns-backend
cp backend.conf_example backend.conf
```
Change the backend.conf to your configuration

## Powerdns
add the folowing to the powerdns configuration
```
pipe-command=/usr/local/phpipam-powerdns-backend/powerdns-pipe.py
pipebackend-abi-version=2
launch=pipe
```
