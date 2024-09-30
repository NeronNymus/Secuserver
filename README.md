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
