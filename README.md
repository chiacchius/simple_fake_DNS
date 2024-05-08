# simple_fake_DNS
A simple fake dns server implemented using scapy. Whenever it receives a DNS request, it crafts a response with the target IP address that you specify. This allows you to control which IP address the requester gets when querying a domain name.

## Usage

1. Clone the repository:

 ```bash
   git clone https://github.com/chiacchius/simple_fake_DNS.git
   cd simple_fake_DNS

2. Install requirements:

 ```bash
   pip install -r requirements.txt

3. Run the fake dns server:

```bash
   sudo python3 fakeDNS.py [target_ip]

