import subprocess ,platform ,requests ,socket ,whois ,signal ,sys ,getpass #line:1
from concurrent .futures import ThreadPoolExecutor #line:2
from bs4 import BeautifulSoup #line:3
from urllib .parse import urlparse #line:4
from colorama import init ,Fore #line:5
import pyfiglet #line:6
init (autoreset =True )#line:8
def signal_handler (_OOO0000000OOOOOOO ,__ ):#line:10
    print (Fore .RED +"\nExiting gracefully...")#line:11
    sys .exit (0 )#line:12
signal .signal (signal .SIGINT ,signal_handler )#line:14
if platform .system ().lower ()!='windows':#line:15
    signal .signal (signal .SIGTSTP ,signal_handler )#line:16
def print_ascii_art (OOOOO0OOOO00O0O0O ,color =Fore .GREEN ):#line:18
    print (color +pyfiglet .figlet_format (OOOOO0OOOO00O0O0O ))#line:19
def traceroute (O0O0OO00O0O00OOO0 ):#line:21
    print_ascii_art ("Traceroute",Fore .CYAN )#line:22
    O0000O000OOOO00OO =['tracert',O0O0OO00O0O00OOO0 ]if platform .system ().lower ()=='windows'else ['traceroute',O0O0OO00O0O00OOO0 ]#line:23
    try :#line:24
        OO0O0000O0O0000OO =subprocess .Popen (O0000O000OOOO00OO ,stdout =subprocess .PIPE ,stderr =subprocess .PIPE ,text =True )#line:25
        for OOOO0OO0OOO0O0O00 in iter (OO0O0000O0O0000OO .stdout .readline ,''):#line:26
            print (Fore .CYAN +OOOO0OO0OOO0O0O00 ,end ='')#line:27
            O0OO0OOOOOOOO0000 =OOOO0OO0OOO0O0O00 .split ()#line:28
            if O0OO0OOOOOOOO0000 :#line:29
                O000000000000000O =O0OO0OOOOOOOO0000 [-1 ].strip ('()')#line:30
                if is_valid_ip (O000000000000000O ):#line:31
                    fetch_ip_info (O000000000000000O )#line:32
        OO0O0000O0O0000OO .stdout .close ()#line:33
        OO0O0000O0O0000OO .wait ()#line:34
    except FileNotFoundError :#line:35
        print (Fore .RED +"Traceroute command not found.")#line:36
def is_valid_ip (O0O00O0OOOO0000O0 ):#line:38
    try :#line:39
        socket .inet_pton (socket .AF_INET ,O0O00O0OOOO0000O0 )#line:40
        return True #line:41
    except socket .error :#line:42
        try :#line:43
            socket .inet_pton (socket .AF_INET6 ,O0O00O0OOOO0000O0 )#line:44
            return True #line:45
        except socket .error :#line:46
            return False #line:47
def fetch_ip_info (OOO0O000OOOOO0000 ):#line:49
    try :#line:50
        O0OO0O000O0OO00OO =requests .get (f"https://ipinfo.io/{OOO0O000OOOOO0000}/json").json ()#line:51
        print (Fore .GREEN +f"IP: {OOO0O000OOOOO0000}\nISP: {O0OO0O000O0OO00OO.get('org', 'N/A')}\nLocation: {O0OO0O000O0OO00OO.get('city', 'N/A')}, {O0OO0O000O0OO00OO.get('region', 'N/A')}, {O0OO0O000O0OO00OO.get('country', 'N/A')}\nHostname: {O0OO0O000O0OO00OO.get('hostname', 'N/A')}")#line:52
    except requests .exceptions .RequestException as O00OOOOO0O000O0OO :#line:53
        print (Fore .RED +f"Error fetching IP info: {O00OOOOO0O000O0OO}")#line:54
def nslookup (OO0O0O0O0O0OOOOOO ):#line:56
    print_ascii_art ("NSLookup",Fore .CYAN )#line:57
    try :#line:58
        O0O0OOOOOOO0OO0OO =subprocess .run (['nslookup',OO0O0O0O0O0OOOOOO ],capture_output =True ,text =True )#line:59
        print (Fore .CYAN +O0O0OOOOOOO0OO0OO .stdout )#line:60
    except FileNotFoundError :#line:61
        print (Fore .RED +"nslookup command not found.")#line:62
def check_http_headers (OO0OOO00O0O0000O0 ):#line:64
    print_ascii_art ("HTTP Headers",Fore .CYAN )#line:65
    try :#line:66
        OOOOO0O0O0O00O000 =requests .get (OO0OOO00O0O0000O0 ).headers #line:67
        OO000OO000OOOOO00 ={O0O0OO0O0OOOO0000 :O00O0O000O00O000O for O0O0OO0O0OOOO0000 ,O00O0O000O00O000O in OOOOO0O0O0O00O000 .items ()if 'cache'in O0O0OO0O0OOOO0000 .lower ()or 'via'in O0O0OO0O0OOOO0000 .lower ()}#line:68
        if OO000OO000OOOOO00 :#line:69
            print (Fore .GREEN +"Cache-related headers found:")#line:70
            for O000O0O0O000O0000 ,O00O00O00O00OO0OO in OO000OO000OOOOO00 .items ():#line:71
                print (Fore .GREEN +f"{O000O0O0O000O0000}: {O00O00O00O00OO0OO}")#line:72
        else :#line:73
            print (Fore .YELLOW +"No cache-related headers found.")#line:74
    except requests .exceptions .RequestException as O0OO0OO0OOOO000OO :#line:75
        print (Fore .RED +f"Error fetching HTTP headers: {O0OO0OO0OOOO000OO}")#line:76
def get_isp_info ():#line:78
    print_ascii_art ("ISP Info",Fore .CYAN )#line:79
    try :#line:80
        O00OO0OO00OOOO000 =socket .gethostbyname (socket .gethostname ())#line:81
        print (Fore .GREEN +f"Your local IP address: {O00OO0OO00OOOO000}")#line:82
    except socket .error as O0O000OOOOOO00000 :#line:83
        print (Fore .RED +f"Error fetching IP information: {O0O000OOOOOO00000}")#line:84
def get_whois_info (O0000O00O00OO0000 ):#line:86
    print_ascii_art ("WHOIS Info",Fore .CYAN )#line:87
    try :#line:88
        O0OO00OOOO0OOOO00 =whois .whois (O0000O00O00OO0000 )#line:89
        print (Fore .GREEN +f"Domain Name: {O0OO00OOOO0OOOO00.domain_name}\nRegistrar: {O0OO00OOOO0OOOO00.registrar}\nWHOIS Server: {O0OO00OOOO0OOOO00.whois_server}\nCreation Date: {O0OO00OOOO0OOOO00.creation_date}\nExpiration Date: {O0OO00OOOO0OOOO00.expiration_date}\nName Servers: {O0OO00OOOO0OOOO00.name_servers}\nStatus: {O0OO00OOOO0OOOO00.status}\nEmails: {O0OO00OOOO0OOOO00.emails}")#line:90
    except Exception as O000O00000OOO0O0O :#line:91
        print (Fore .RED +f"Error fetching WHOIS information: {O000O00000OOO0O0O}")#line:92
def port_scan (O0O000000OOO00000 ):#line:94
    print_ascii_art ("Port Scan",Fore .CYAN )#line:95
    try :#line:96
        O00OO00000O000OO0 =socket .gethostbyname (O0O000000OOO00000 )#line:97
        OOOOO0OOOO0000OOO =input (Fore .YELLOW +"Enter scan type (1 for basic, 2 for all): ").strip ()#line:98
        O0OO0O0O000OOO0OO =range (1 ,65536 )if OOOOO0OOOO0000OOO =='2'else [21 ,22 ,23 ,25 ,53 ,80 ,110 ,143 ,443 ,445 ,3389 ,20 ,69 ,123 ,161 ,162 ,389 ,636 ,989 ,990 ,993 ,995 ,1723 ,3306 ,5432 ,5900 ,8080 ,8443 ]#line:99
        with ThreadPoolExecutor (max_workers =100 )as OO0OOO0OO0OO000OO :#line:100
            OO0OOO0OO0OO000OO .map (scan_port ,[O00OO00000O000OO0 ]*len (O0OO0O0O000OOO0OO ),O0OO0O0O000OOO0OO )#line:101
    except socket .error as OOO0OOOOOO00OOO00 :#line:102
        print (Fore .RED +f"Error resolving domain to IP: {OOO0OOOOOO00OOO00}")#line:103
def scan_port (OOOOO00000OOOOO0O ,O00O000O00OOO0O0O ):#line:105
    with socket .socket (socket .AF_INET ,socket .SOCK_STREAM )as OOO0O000OO00000O0 :#line:106
        OOO0O000OO00000O0 .settimeout (1 )#line:107
        if OOO0O000OO00000O0 .connect_ex ((OOOOO00000OOOOO0O ,O00O000O00OOO0O0O ))==0 :#line:108
            try :#line:109
                O0O000OOOO00OOO0O =socket .getservbyport (O00O000O00OOO0O0O )#line:110
            except OSError :#line:111
                O0O000OOOO00OOO0O ="Unknown"#line:112
            print (Fore .GREEN +f"Port {O00O000O00OOO0O0O} is open on {OOOOO00000OOOOO0O} (Service: {O0O000OOOO00OOO0O})")#line:113
def fetch_site_title (O0OO000OOO00O00O0 ):#line:115
    print_ascii_art ("Site Title",Fore .CYAN )#line:116
    try :#line:117
        O00OOOO00O0000O00 =BeautifulSoup (requests .get (O0OO000OOO00O00O0 ).text ,'html.parser')#line:118
        print (Fore .GREEN +f"Site Title: {O00OOOO00O0000O00.title.string if O00OOOO00O0000O00.title else 'N/A'}")#line:119
    except requests .exceptions .RequestException as OO0000O0O0OO000O0 :#line:120
        print (Fore .RED +f"Error fetching site title: {OO0000O0O0OO000O0}")#line:121
def detect_web_server (O00000O00OO00000O ):#line:123
    print_ascii_art ("Web Server",Fore .CYAN )#line:124
    try :#line:125
        O00OOOO0O00OO00O0 =requests .get (O00000O00OO00000O ).headers .get ('Server','N/A')#line:126
        print (Fore .GREEN +f"Web Server: {O00OOOO0O00OO00O0}")#line:127
    except requests .exceptions .RequestException as O000O000OO000O0OO :#line:128
        print (Fore .RED +f"Error detecting web server: {O000O000OO000O0OO}")#line:129
def detect_cms (OOOO00OO00OO0OOOO ):#line:131
    print_ascii_art ("CMS Detection",Fore .CYAN )#line:132
    try :#line:133
        OOO0O0OOOO0O000O0 =requests .get (OOOO00OO00OO0OOOO ).text #line:134
        if 'wp-content'in OOO0O0OOOO0O000O0 :#line:135
            print (Fore .GREEN +"CMS: WordPress")#line:136
        elif 'Joomla'in OOO0O0OOOO0O000O0 :#line:137
            print (Fore .GREEN +"CMS: Joomla")#line:138
        else :#line:139
            print (Fore .YELLOW +"CMS: Unknown")#line:140
    except requests .exceptions .RequestException as O0000O00O0O00OOOO :#line:141
        print (Fore .RED +f"Error detecting CMS: {O0000O00O0O00OOOO}")#line:142
def check_cloudflare (OO00OOOO0OO00OO0O ):#line:144
    print_ascii_art ("Cloudflare Check",Fore .CYAN )#line:145
    try :#line:146
        if 'cloudflare'in requests .get (OO00OOOO0OO00OO0O ).headers .get ('Server','').lower ():#line:147
            print (Fore .GREEN +"Site is behind Cloudflare")#line:148
        else :#line:149
            print (Fore .YELLOW +"Site is not behind Cloudflare")#line:150
    except requests .exceptions .RequestException as O00O0O0O000O00000 :#line:151
        print (Fore .RED +f"Error checking Cloudflare: {O00O0O0O000O00000}")#line:152
def fetch_robots_txt (O0O0O00O0OOOOOO00 ):#line:154
    print_ascii_art ("Robots.txt",Fore .CYAN )#line:155
    try :#line:156
        OO0O0O0OOOO0O0000 =requests .get (f"{O0O0O00O0OOOOOO00}/robots.txt")#line:157
        if OO0O0O0OOOO0O0000 .status_code ==200 :#line:158
            print (Fore .GREEN +"robots.txt content:\n"+OO0O0O0OOOO0O0000 .text )#line:159
        else :#line:160
            print (Fore .YELLOW +"robots.txt not found")#line:161
    except requests .exceptions .RequestException as O0O0O00OOO0O0O0O0 :#line:162
        print (Fore .RED +f"Error fetching robots.txt: {O0O0O00OOO0O0O0O0}")#line:163
def grab_banners (OO0000O0O000O0OO0 ):#line:165
    print_ascii_art ("Banner Grabbing",Fore .CYAN )#line:166
    try :#line:167
        print (Fore .GREEN +f"Banner: {requests.get(f'http://{OO0000O0O000O0OO0}').headers.get('Server', 'N/A')}")#line:168
    except requests .exceptions .RequestException as OOO000O00000O0OOO :#line:169
        print (Fore .RED +f"Error grabbing banner: {OOO000O00000O0OOO}")#line:170
def sub_domain_scanner (OOO0O000OOOOOOOOO ):#line:172
    print_ascii_art ("Subdomain Scanner",Fore .CYAN )#line:173
    try :#line:174
        OOOOO0000OO0O00O0 =requests .get (f"https://api.hackertarget.com/hostsearch/?q={OOO0O000OOOOOOOOO}")#line:175
        if OOOOO0000OO0O00O0 .status_code ==429 :#line:176
            print (Fore .RED +"API count exceeded - Increase Quota with Membership")#line:177
            return #line:178
        for OOO00OO0O0O00O0OO in OOOOO0000OO0O00O0 .text .split ('\n'):#line:179
            print (Fore .GREEN +OOO00OO0O0O00O0OO )#line:180
    except requests .exceptions .RequestException as OOOOOO000O000O00O :#line:181
        print (Fore .RED +f"Error scanning sub-domains: {OOOOOO000O000O00O}")#line:182
def reverse_ip_lookup (OOOO00000OOOO00OO ):#line:184
    print_ascii_art ("Reverse IP Lookup",Fore .CYAN )#line:185
    try :#line:186
        OO0OOO0O000OOOOO0 =requests .get (f"https://api.hackertarget.com/reverseiplookup/?q={OOOO00000OOOO00OO}")#line:187
        if OO0OOO0O000OOOOO0 .status_code ==429 :#line:188
            print (Fore .RED +"API count exceeded - Increase Quota with Membership")#line:189
            return #line:190
        for O0OO000O00O000O00 in OO0OOO0O000OOOOO0 .text .split ('\n'):#line:191
            if is_valid_ip (O0OO000O00O000O00 ):#line:192
                print (Fore .GREEN +O0OO000O00O000O00 )#line:193
                detect_cms (f"http://{O0OO000O00O000O00}")#line:194
    except requests .exceptions .RequestException as O00O00000O0OO00OO :#line:195
        print (Fore .RED +f"Error performing reverse IP lookup: {O00O00000O0OO00OO}")#line:196
def bloggers_view (O0O0O0O0OOO00O000 ):#line:198
    print_ascii_art ("Bloggers View",Fore .CYAN )#line:199
    try :#line:200
        OOO0O00O0OO0O000O =requests .get (O0O0O0O0OOO00O000 )#line:201
        print (Fore .GREEN +f"HTTP Response Code: {OOO0O00O0OO0O000O.status_code}")#line:202
        fetch_site_title (O0O0O0O0OOO00O000 )#line:203
    except requests .exceptions .RequestException as OO000O00O000O0O00 :#line:204
        print (Fore .RED +f"Error fetching bloggers view: {OO000O00O000O0O00}")#line:205
def wordpress_scan (O000OOO00O0OO00O0 ):#line:207
    print_ascii_art ("WordPress Scan",Fore .CYAN )#line:208
    try :#line:209
        if 'wp-content'in requests .get (O000OOO00O0OO00O0 ).text :#line:210
            print (Fore .GREEN +"WordPress site detected")#line:211
    except requests .exceptions .RequestException as O0OO000O00O00OO00 :#line:212
        print (Fore .RED +f"Error performing WordPress scan: {O0OO000O00O00OO00}")#line:213
def sensitive_files_crawling (OO000OOOO0O00O0O0 ):#line:215
    print_ascii_art ("Sensitive Files",Fore .CYAN )#line:216
    try :#line:217
        for OOOO00000OO0O0O00 in ['.env','config.php','wp-config.php','.htaccess']:#line:218
            if requests .get (f"{OO000OOOO0O00O0O0}/{OOOO00000OO0O0O00}").status_code ==200 :#line:219
                print (Fore .RED +f"Sensitive file found: {OOOO00000OO0O0O00}")#line:220
    except requests .exceptions .RequestException as O000O0OO000O0OO00 :#line:221
        print (Fore .RED +f"Error crawling for sensitive files: {O000O0OO000O0OO00}")#line:222
def version_detection (O0OOO0O0OO0000OO0 ):#line:224
    print_ascii_art ("Version Detection",Fore .CYAN )#line:225
    try :#line:226
        print (Fore .GREEN +f"Server Version: {requests.get(O0OOO0O0OO0000OO0).headers.get('Server', 'N/A')}")#line:227
    except requests .exceptions .RequestException as O0OOOOO00O00OO000 :#line:228
        print (Fore .RED +f"Error detecting version: {O0OOOOO00O00OO000}")#line:229
def crawler (OO000OOO0000O0O00 ):#line:231
    print_ascii_art ("Crawler",Fore .CYAN )#line:232
    try :#line:233
        OOOOOOOOOO0OOO0O0 =BeautifulSoup (requests .get (OO000OOO0000O0O00 ).text ,'html.parser')#line:234
        for O0O0000O000OO000O in [O00OOOOO0OO00OO00 ['href']for O00OOOOO0OO00OO00 in OOOOOOOOOO0OOO0O0 .find_all ('a',href =True )]:#line:235
            print (Fore .GREEN +O0O0000O000OO000O )#line:236
    except requests .exceptions .RequestException as O0OOOO0OO000OO0OO :#line:237
        print (Fore .RED +f"Error performing web crawling: {O0OOOO0OO000OO0OO}")#line:238
def mx_lookup (OOOO00O0O0OO0O000 ):#line:240
    print_ascii_art ("MX Lookup",Fore .CYAN )#line:241
    try :#line:242
        O000O0OOOOOOO0O0O =subprocess .run (['nslookup','-type=mx',OOOO00O0O0OO0O000 ],capture_output =True ,text =True )#line:243
        print (Fore .CYAN +O000O0OOOOOOO0O0O .stdout )#line:244
    except FileNotFoundError :#line:245
        print (Fore .RED +"nslookup command not found.")#line:246
def all_scan (OO0000000O0OO0000 ):#line:248
    print_ascii_art ("All Scan",Fore .CYAN )#line:249
    O0000OOOO0O00OOO0 =f"http://{OO0000000O0OO0000}"#line:250
    traceroute (OO0000000O0OO0000 )#line:251
    nslookup (OO0000000O0OO0000 )#line:252
    check_http_headers (O0000OOOO0O00OOO0 )#line:253
    get_isp_info ()#line:254
    get_whois_info (OO0000000O0OO0000 )#line:255
    port_scan (OO0000000O0OO0000 )#line:256
    fetch_site_title (O0000OOOO0O00OOO0 )#line:257
    detect_web_server (O0000OOOO0O00OOO0 )#line:258
    detect_cms (O0000OOOO0O00OOO0 )#line:259
    check_cloudflare (O0000OOOO0O00OOO0 )#line:260
    fetch_robots_txt (O0000OOOO0O00OOO0 )#line:261
    grab_banners (OO0000000O0OO0000 )#line:262
    sub_domain_scanner (OO0000000O0OO0000 )#line:263
    reverse_ip_lookup (OO0000000O0OO0000 )#line:264
    bloggers_view (O0000OOOO0O00OOO0 )#line:265
    wordpress_scan (O0000OOOO0O00OOO0 )#line:266
    sensitive_files_crawling (O0000OOOO0O00OOO0 )#line:267
    version_detection (O0000OOOO0O00OOO0 )#line:268
    crawler (O0000OOOO0O00OOO0 )#line:269
    mx_lookup (OO0000000O0OO0000 )#line:270
def login ():#line:272
    print_ascii_art ("Login",Fore .CYAN )#line:273
    O0O00OO0000OOOOO0 =input (Fore .YELLOW +"Enter username: ").strip ()#line:274
    OO0OO00O00O0000O0 =getpass .getpass (Fore .YELLOW +"Enter password: ").strip ()#line:275
    if O0O00OO0000OOOOO0 =="azmi"and OO0OO00O00O0000O0 =="azmi":#line:277
        print (Fore .GREEN +"Login successful!")#line:278
        return True #line:279
    else :#line:280
        print (Fore .RED +"Invalid username or password.")#line:281
        return False #line:282
def main ():#line:284
    print_ascii_art ("Azmi's Recon Tool",Fore .CYAN )#line:285
    if not login ():#line:286
        return #line:287
    OOO0O0OOO0OOOOOOO ={'1':traceroute ,'2':nslookup ,'3':check_http_headers ,'4':get_isp_info ,'5':get_whois_info ,'6':port_scan ,'7':fetch_site_title ,'8':detect_web_server ,'9':detect_cms ,'10':check_cloudflare ,'11':fetch_robots_txt ,'12':grab_banners ,'13':sub_domain_scanner ,'14':reverse_ip_lookup ,'15':bloggers_view ,'16':wordpress_scan ,'18':sensitive_files_crawling ,'19':version_detection ,'20':crawler ,'21':mx_lookup ,'22':all_scan }#line:295
    while True :#line:297
        print (Fore .YELLOW +"Select a feature to run:")#line:298
        for OOOO00OO0OO00O0OO ,OOO0O00O0OOO00O00 in OOO0O0OOO0OOOOOOO .items ():#line:299
            print (Fore .YELLOW +f"{OOOO00OO0OO00O0OO}: {OOO0O00O0OOO00O00.__name__.replace('_', ' ').title()}")#line:300
        print (Fore .YELLOW +"0: Exit")#line:301
        OO0OO00O00O0OO00O =input (Fore .YELLOW +"Enter your choice: ").strip ()#line:303
        if OO0OO00O00O0OO00O =='0':#line:304
            print (Fore .RED +"Exiting...")#line:305
            break #line:306
        if OO0OO00O00O0OO00O in OOO0O0OOO0OOOOOOO :#line:308
            if OO0OO00O00O0OO00O in ['1','2','5','6','13','14','21','22']:#line:309
                OO00000OOO0O0OO0O =input (Fore .YELLOW +"Enter the domain: ").strip ()#line:310
                OO00000OOO0O0OO0O =urlparse (OO00000OOO0O0OO0O ).netloc or OO00000OOO0O0OO0O #line:311
                OOO0O0OOO0OOOOOOO [OO0OO00O00O0OO00O ](OO00000OOO0O0OO0O )#line:312
            elif OO0OO00O00O0OO00O in ['3','7','8','9','10','11','12','15','16','17','18','19','20']:#line:313
                O0000OOOO0OOOO0OO =input (Fore .YELLOW +"Enter the URL: ").strip ()#line:314
                OOO0O0OOO0OOOOOOO [OO0OO00O00O0OO00O ](O0000OOOO0OOOO0OO )#line:315
            elif OO0OO00O00O0OO00O =='4':#line:316
                OOO0O0OOO0OOOOOOO [OO0OO00O00O0OO00O ]()#line:317
        else :#line:318
            print (Fore .RED +"Invalid choice. Please enter a valid number.")#line:319
if __name__ =="__main__":#line:321
    main ()#line:322
