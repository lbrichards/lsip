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
### Installing with pipx
If we’d like to install and run `lsip` globally without typing `python` each time, we can use [pipx](https://pypa.github.io/pipx/). Make sure we have pipx installed:
`python -m pip install –user pipx
python -m pipx ensurepath`
Then install `lsip` via pipx (from the cloned local folder):
cd lsip
pipx install .
- This will build and install `lsip` as a globally available command.
- From now on, we can just run the `lsip` command anywhere.
- (If not installed via pipx, we can still run:)
  `python lsip.py`
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
   
