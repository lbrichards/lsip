# lsip

A small Python script that scans our local network for IPv4 addresses starting with `192.168.*`, using [Scapy](https://scapy.net/).

## Features
- Quickly discovers live hosts on our local network
- Filters for addresses matching `192.168.*`
- Displays a concise list of IP addresses

## Installation
1. **Clone the Repository**
`git clone https://github.com/OUR_USERNAME/lsip.git`
2. **Install Dependencies**
`pip install -r requirements.txt`
Or, if we’re installing Scapy directly:
`pip install scapy`
## Usage
1. **Run the Script**
python lsip.py
2. **Optional Arguments**
- We can specify a different network range, for example:
  ```
  python lsip.py --network-range 192.168.0.0/24
  ```

## Contributing
- We welcome contributions from anyone interested in improving `lsip`.
- Feel free to open an issue or submit a pull request.

## License
This project is distributed under the MIT License (or whichever license we choose).
   
