This Python script gives certbot the ability update a Synology SSL certificate from a remote machine by using the deploy hook

# Requirements
* Python 3
* `requests` module
* `pyOpenSSL` module

# Assumptions
This script assumes that you have already imported the certificate into Synology once. This script looks for a certificate with the same common name as the certificate that was issued. For example, if your certificate is for www.example.com, the script will attempt to update the equivalent Synology certificate with the common name www.example.com

# Usage
#### Required Configuration
In synology.py, fill in `base_url`, `username`, and `password` based on your Synology configuration

#### Certbot Renewal Command
```shell script
certbot renew ... --deploy-hook /path/to/deployhook.sh
```

#### deployhook.sh
```shell script
python3 /path/to/synology.py $RENEWED_LINEAGE/privkey.pem $RENEWED_LINEAGE/fullchain.pem
```
