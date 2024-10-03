# Azmis-Recon-Tool
Azmi's Recon Tool (ART) is a versatile network and web reconnaissance tool for security professionals. It offers features like traceroute, nslookup, HTTP headers check, ISP info, WHOIS info, port scanning, and more. This tool helps identify vulnerabilities and understand the infrastructure of target domains and websites.

## License

This software, tool, code, and materials are licensed under the **Creative Commons Attribution 4.0 International License (CC BY 4.0)**. You are free to share and adapt the material for any purpose, including commercial use, as long as appropriate credit is provided.

Attribution must include the name **"Azizul Abedin Azmi"** or the logo found in this repository.

[![View License](https://img.shields.io/badge/View-License-blue?style=for-the-badge)](LICENSE)

# 🌐 **Azmi's Recon Tool** 🌐

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

Welcome to **Azmi's Recon Tool**! This versatile network reconnaissance tool allows you to perform various network analysis tasks, such as traceroute, DNS lookups, and security checks. 

## 💾 **Installation Instructions**

You can install this tool on **Termux** (Android), **Linux**, or **Windows**. Follow the steps below for each platform:

### 📱 **Termux Installation**

1. **Install Termux** from the Google Play Store or F-Droid.
2. **Open Termux** and run the following commands:

   ```bash
   pkg update && pkg upgrade -y
   pkg install python git -y
   git clone https://github.com/yourusername/azmis-recon-tool.git
   cd azmis-recon-tool
   pip install -r requirements.txt
   ```

3. **Run the Tool**:

   ```bash
   python ART.py
   ```

### 🐧 **Linux Installation**

1. **Open Terminal** and execute:

   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install python3 python3-pip git -y
   git clone https://github.com/yourusername/azmis-recon-tool.git
   cd azmis-recon-tool
   pip3 install -r requirements.txt
   ```

2. **Run the Tool**:

   ```bash
   python3 ART.py
   ```

### 💻 **Windows Installation**

1. **Install Python** from [python.org](https://www.python.org/downloads/). Make sure to check "Add Python to PATH" during installation.
2. **Open Command Prompt** and run:

   ```cmd
   git clone https://github.com/yourusername/azmis-recon-tool.git
   cd azmis-recon-tool
   pip install -r requirements.txt
   ```

3. **Run the Tool**:

   ```cmd
   python ART.py
   ```

## 🔑 **Login Mechanism**

The tool includes a simple username and password login mechanism. Here's how it works:

1. When you start the tool, you will be prompted to enter your **username** and **password**. 
2. The default credentials are:
   - **Username**: `azmi`
   - **Password**: `azmi`
3. You can modify these credentials in the source code if needed.

```python
def login():
    print_ascii_art("Login", Fore.CYAN)
    username = input(Fore.YELLOW + "Enter username: ").strip()
    password = getpass.getpass(Fore.YELLOW + "Enter password: ").strip()
    # Replace with your actual username and password check
    if username == "azmi" and password == "azmi":
        print(Fore.GREEN + "✅ Login successful!")
        return True
    else:
        print(Fore.RED + "❌ Invalid username or password.")
        return False
```

## ⚙️ **Features**

The tool offers a variety of features, including:

1. 🌐 **Traceroute**: Trace the path packets take to reach a domain.
2. 🔍 **NS Lookup**: Retrieve DNS records for a domain.
3. 📄 **HTTP Headers Check**: Analyze HTTP headers for caching and other information.
4. 🌍 **ISP Information**: Gather information about your Internet Service Provider (ISP).
5. 🔐 **WHOIS Lookup**: Get domain registration information.
6. 🔍 **Port Scanning**: Check open ports on a domain or IP.
7. 🏷️ **Site Title Fetching**: Retrieve the title of a website.
8. 🖥️ **Web Server Detection**: Identify the web server software in use.
9. 🛠️ **CMS Detection**: Detect the content management system (CMS) of a website.
10. ☁️ **Cloudflare Check**: Determine if a site is protected by Cloudflare.
11. 📜 **robots.txt Fetching**: Access the robots.txt file to see what is disallowed for web crawlers.
12. 📡 **Banner Grabbing**: Fetch the server banner to gather information.
13. 🌐 **Subdomain Scanning**: Discover subdomains of a given domain.
14. 🔁 **Reverse IP Lookup**: Find all domains hosted on a specific IP.
15. 📝 **Bloggers View**: Fetch HTTP response codes and site titles.
16. 📅 **WordPress Scan**: Identify WordPress installations.
17. 🗂️ **Sensitive Files Crawling**: Search for sensitive files in the web root.
18. 🔍 **Version Detection**: Check for server software versions.
19. 🕷️ **Web Crawling**: Gather all links present on a webpage.
20. 📧 **MX Lookup**: Retrieve mail exchange records for a domain.
21. 🚀 **All Scan**: Perform all checks in one command for comprehensive analysis.

## 📚 **Usage Tips**

- Always run the tool with appropriate permissions, especially for port scanning and network-related features. ⚙️
- Use the tool responsibly and avoid unauthorized scanning or probing of networks you do not own. 🚫
- Keep the tool updated to benefit from new features and improvements. 🔄

## 🎉 **Enjoy Exploring!** 

Feel free to customize and extend the tool according to your needs. Happy recon! 🚀

**Need Help or Have Queries?**

If you need any help or have any queries, feel free to contact me.

[![Facebook](https://img.shields.io/badge/Facebook-%231877F2.svg?style=for-the-badge&logo=Facebook&logoColor=white)](https://www.facebook.com/azizul.abedin.azmi) [![Instagram](https://img.shields.io/badge/Instagram-%23E4405F.svg?style=for-the-badge&logo=Instagram&logoColor=white)](https://www.instagram.com/azizulabedin/)