# Secuserver
SecuServer is a lightweight Python program for secure, encrypted 
communication over TCP using AES and RSA encryption. It protects the system
where is installed.

It ensures safe transmission of sensitive data between clients and servers. 
Ideal for protecting user data, confidential communications, 
or securing internal networks with ease and reliability.

> **Note:** The main script is obfuscated intentionally to protect sensitive parts of the code.

## Installation Instructions for Windows Users

Follow these simple steps to install SecuServer on your Windows system.

### Prerequisites

1. **Python**: Ensure that you have Python installed on your system. If not, download and install the latest version of Python 
from [python.org](https://www.python.org/downloads/).
   
2. **Git**: Install Git if you don't already have it. You can download it from [git-scm.com](https://git-scm.com/).

### Quick Installation

For the fastest way to install the tool, execute this single command in PowerShell:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/NeronNymus/Secuserver/main/install.ps1" -OutFile "$env:TEMP\install.ps1"; & "$env:TEMP\install.ps1"
```

This will automatically download the install.ps1 script and execute it to complete the setup.

### Detailed Installation Steps

1. **Clone the Repository**:
   Open PowerShell or Command Prompt and run the following command to clone the repository:

```powershell
   git clone https://github.com/NeronNymus/Secuserver.git
```

### Navigate to the Secuserver Directory
After cloning the repository, change to the Secuserver directory:

```powershell
cd Secuserver
```

Execute the install.ps1 script to complete the installation:

```powershell
.\install.ps1
```

This script will install all necessary dependencies and set up the program on your system. 
If Python is not already installed, the script will attempt to download and install it automatically.

# Installation Instructions for Linux Users

There are two ways to install SecuServer: using `curl` or the Python interpreter.

## Option 1: Install Using curl

1. **Install curl (if you don't have it already):**

```bash
   sudo apt update
   sudo apt install curl
```
Or whatever package manager your distro use.

Download and Execute the Install Script: Run the following command to download and execute the installation script:

 ```bash
curl -O https://raw.githubusercontent.com/NeronNymus/Secuserver/main/install.py && sudo python3 install.py
```


## Option 2: Install Using Python
2. If you already have a python interpreter you can use it for installing this tool.
All you need is the 'requests' library, fetch it with

```bash
sudo pip install requests
```

Now, download the installation script:

```bash
python3 -c "import requests; r = requests.get('https://raw.githubusercontent.com/NeronNymus/Secuserver/main/install.py'); open('install.py', 'wb').write(r.content)"
```

Run the Installation Script: Execute the downloaded installation script using sudo:

```bash
sudo python3 install.py
```

This will download the necessary files and set up the SecuServer program on your Linux system.


