# NSM PORT / VULN SCANNER       Developed By NSM Barii

# USER INTERFACE // IMPORTS
from rich.table import Table
from rich.console import Console
from rich.live import Live
from rich.panel import Panel

# IMPORTS
from time import sleep
import socket
import pyfiglet
import os
import requests
import time
from plyer import notification
import threading
import json
from datetime import datetime
import dns.resolver
import subprocess
import platform
from rich.progress import Progress
import shodan
import shodan.exception

# FOR FILE HANDLING
from pathlib import Path

# INTIALIZE CONSOLE 
console = Console()
terminal_width = console.size.width


# GLOBAL VARIABLES
domain_name = ""    # DEFINE VARIABLE
ip_address = ""     # DEFINE VARIABLE
open_ports = 0      # OPEN PORTS
closed_fit = 0      # CLOSED / FILTERED PORTS
yes_dns = 0         # COMPLETED SUB-DOMAIN LOOKUPS
paused_time = time.time()   # USED IN THE THREADER FUNCTION WITH CHOICE / TYPE 3 // NOT IN USE // WILL KEEP IN CASE I CHANGE THAT
lock = threading.Lock()     # USED WITH THREADS 
results_open_ports = []     # HOLDS THE ACTUAL OPEN PORTS
results_subs_ports = []     # HOLDS THE ACTUAL SUB DOMAINS  
geo_info = ""               # SAVES GEO INFO
shodan_results = []        # SAVES SHOLDAN INFO

#C:\Users\jabar\Documents
# FILE PATHS



# Base directory for storing files (change this value to relocate all files)
# You can switch between `Path.home()` or `os.getenv('APPDATA')` depending on your preference.
base_directory = Path.home() / ".net_tool"  # For example, C:\Users\<YourUsername>\.net_tool
# Alternatively for Windows convention: Path(os.getenv('APPDATA')) / "NetTool"

# Create base directory if it doesn't exist
base_directory.mkdir(parents=True, exist_ok=True)

# File paths using the base directory
file_path_clean = base_directory / "netvuln_clear.txt"
file_path = base_directory / "netvuln.txt"
file_path_setting = base_directory / "netvuln_setting.json"
file_path_error_log = base_directory / "netvuln_error_log.txt"


# OLD PATH WAYS VERY REDUNDENT
#file_path = "netvuln.txt"
#file_path_setting = "netvuln_setting.json"


# CONNECTION CHECK // ONLINE OR OFFLINE
def connection_status():
         
    while True:

        try:
            # GET HOST NAME THEN / LOCAL IP ADDRESS
            host = socket.gethostname()
            host = str(host)
            local_ip = socket.gethostbyname(host)

            split = local_ip.split('.')
            split[2] = "xxxx"        # CHANGING THE 3RD OCTET TO X'S
            split[3] = "xxxx"        # CHANGING THE 4TH OCTET TO X'S 

            local_ip ='.'.join(split)  # JOINS THE SEPERATED GROUPS BACK TOGETHER

        # MESSAGE VARIABLES
            msg_offline = "Connection Status: Offline\nPlease Check Your Connection & Try Again!"
            msg = "Connection Status: ONLINE"
            
            # CHECKING INTERNET CONNECTIVITY 
            response = requests.get("http://google.com", timeout=5)
            code = response.status_code                        #   ONLINE / OFFLINE 


        # PANELS FOR OUTPUTS
            panel_on = Panel(f"CONNECTION STATUS: ONLINE\nLocal IP: {local_ip}", style="yellow on black", border_style=" yellow", width=min(130, terminal_width - 2))
            panel_off = Panel("CONNECTION STATUS: OFFLINE", style="red on black", border_style="bold red", width=min(130, terminal_width - 2), padding=(1, 2))
            #panel_error = Panel(f"CONNECTION STATUS: OFFLINE (Error:  {e})", style="red on black", border_style="bold red")
            panel_leavin = Panel("Sorry To see you go hope to see you again soon", style="yellow on black", border_style="red", width=min(130, terminal_width - 2))
            
        

            if code == 200:
              
                noty(1,msg)
                console.print(panel_on)
                break                    # EXITS THE LOOP IF SUCCESSFUL

            else:

                noty(1,msg_offline)
                console.print(panel_off, width=min(130, terminal_width - 2), padding=(1, 2))
                console.input("[yellow]Press[/yellow] [green]Enter[/green] [yellow]to Re-Try[/yellow] [green]Connection[/green] or [red]Ctrl + c to exit[/red]: ")
                
        

        # HANDLES DNS ERRORS AND NETWORK MISCONFIGURATIONS
        except socket.gaierror as e:   

            panel_socket = Panel(f"Failed To resolve Hostname / Local IP  {e}")            # ERROR PANEL
            console.print(panel_socket)
            error_log(e)
           

        # NETWORK RELATED ERRORS LIKE NO INTERNET
        except requests.exceptions.RequestException as e:   

            panel_error = Panel(f"CONNECTION STATUS: OFFLINE (Error: {e})", style="red on black", border_style="bold red")
            panel_error = Panel(f"CONNECTION STATUS: OFFLINE (Error: {e})", style="red on black", border_style="bold red")

            noty(1,msg_offline)
            console.print(panel_error)
            console.input("[yellow]Press[/yellow] [green]Enter[/green] [yellow]to Re-Try[/yellow] [green]Connection[/green] or [red]Ctrl + c to exit[/red]: ")
            error_log(e)
          

         
        # THIS IS SO THE USER CAN EXIT GRACEFULLY INSTEAD OF BEING STUCK IN THE WHILE THRU LOOP // CUZ THERE INTERNET SUCKS // LOL
        except KeyboardInterrupt as e:

            console.print(panel_leavin)
            time.sleep(3)
            exit()
            error_log(e)

        
        # WILL HANDLE GENERAL EXCEPTION ERRORS
        except Exception as e:      

            panel_error = Panel(f"CONNECTION STATUS: OFFLINE (Error:  {e})", style="red on black", border_style="bold red")
            noty(1,msg_offline)
            console.print(panel_error)
            console.input("[yellow]Press[/yellow] [green]Enter[/green] [yellow]to Re-Try[/yellow] [green]Connection[/green] or [red]Ctrl + c to exit[/red]: ")
            error_log(e)
           
    

# WELCOME SCREEN
def welcome():
    if os.name == "nt":
        os.system("title Developed By NSM Barii")

    welcome_panel = Panel("Network Scanner Module ", style=" yellow on black", border_style=" yellow")  
    
    while True:     # AUTOMATICALLY RETRY TO LOAD FILE AFTER MAKING IT INSTEAD OF CLOSING PROGRAM

        try:

            with open(f"{file_path_setting}", "r") as file:
                content = json.load(file)
                display_name = content.get("display_name")
                scans = content.get("scans", 0)
                scan_show = content.get("scan_show", "on")
                break


        except FileNotFoundError as e:
            data = {
                "display_name":  ""    ,
                "noty_setting": "on",
                "scans": 0,
                "scan_show": "on",
                "api_key_geo": "",
                "api_key_shodan": "",
                "api_key_nvd": "",
                "api_setting": "off"
            }

            with open(f"{file_path_setting}", "w") as file:
                json.dump(data, file, indent=9)
                
                console.print("Default File Path Successfully Created!", style="bold green")
                time.sleep(2)
            error_log(e)

        except json.JSONDecodeError as e:
            console.print(e, style="red")
            data = {}
            with open(f"{file_path_setting}", "w") as file:
                json.dump(data, file, indent=9)
                console.print("Default File Path Successfully Created!", style="bold green")
                time.sleep(2)
            error_log(e)


        except Exception as e:
            console.print(e, style="red")
            data = {}
            with open(f"{file_path_setting}", "w") as file:
                json.dump(data, file, indent=9)
                console.print("Default File Path Successfully Created!", style="bold green")
                time.sleep(2)
            error_log(e)

    if scan_show == "on":
        scan_a = (f"Scans Completed: {scans}")
    else:
        scan_a = ""

    if display_name:

        welcome_message = pyfiglet.figlet_format(f"Welcome\n{display_name}")          # CREATING THE MESSAGE                                                                      # Fixed width
        nsm_outline = Panel(f"{welcome_message}\n\n[cyan]NetVuln - 1.8                                 {scan_a}[/cyan]", title="Network Vulnerability Scanner",  width=min(130, terminal_width - 2) )
        console.print(nsm_outline, style="bold red on black")
    
    else:
        
         # CREATING THE PANEL
        welcome_message = pyfiglet.figlet_format("N S M\nPORT SCANNER")          # CREATING THE MESSAGE
        nsm_outline = Panel(f"{welcome_message}\n\n[cyan]NetVuln - 1.7                               {scan_a}[/cyan]", title="Network Vulnerability Scanner", width=min(130, terminal_width - 2))
        console.print(nsm_outline, style="bold red on black")


# USER ENTERS DOMAIN NAME // WHICH GETS RESOLVED TO IP ADDRESS
def domain_resolver():

    global  start_time, ip_address, domain_name

    while True:
            try:

                domain_name = console.input("\n[red]Enter Domain Name[/red]: ")                                 # DOMAIN NAME TO IP ADDRESS
                ip_address = socket.gethostbyname(domain_name)
                
                start_time = time.time()                                                                        # VARIABLE TO KEEP TRACK OF START TIME

                table_hostgrab = Table(title=f"\nDomain Resolution",  border_style="purple")

                table_hostgrab.add_column("Domain Name", justify="center", style="bold blue")
                table_hostgrab.add_column("Target IP", justify="center", style="red")

                # ADD INPUT RESULTS INTO THE ROWS
                table_hostgrab.add_row(domain_name, ip_address)
                break

            except socket.gaierror as e:
                print(f"Error: {e}, Enter a valid Domain Name") 
                error_log(e) 

        # CALL UPON THE TABLE MADE FOR DOMAIN NAME TO IP 
    console.print(table_hostgrab)
    print("")
    return ip_address


# TAKES THE IP ADDRESS // AND SCAN IT FOR OPEN PORTS   // # PORT SCANNER FOR / COMMON / FULL / CUSTOM SCANS / THIS INSTEAD OF SEPERATE FUNCTIONS FOR EACH. 
def port_scan(port,table):
    
    global  closed_fit, ip_address, open_ports, results_open_ports
    closed = 1

    target = ip_address
    
    # USE THIS IN CASE SOME PORT SERVICES CANT BE GRABBED WE DEFUALT BACK TO WHAT WE KNOW THEM TO BE
    known_ports = {
        465: "smtp",
        587: "smtp",
        2053: "cloudflare",
        2082: "cPanel",
        2083: "cPanel",
        2086: "whm",
        2087: "whm",
        2052: "clearVisn Services",
        2095: "cPanel Webmail",
        2096: "cPanel Webmail",
        2087: "cPanel whm",
        8080: "Http Alternative",
        8443: "Https Alternative",
        8880: "Http Alternative"
    }

    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
        
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    #version = get_service_version(service)

                except OSError as e:
                    service = known_ports.get(port, "unkown")
                    error_log(e)
           
                table.add_row(f"{port}",f"{service}", "OPEN")
                open_ports += 1                                 # SAVES THE NUMBER OFF OPEN PORTS 
                results_open_ports.append(f"[bold blue]Port:[/bold blue] [bold green]{port} -[/bold green] [yellow]{service}[/yellow]")                 # ADDS THE OPEN PORT TO A LIST TO SAVE FOR FILE RESULTS
                    
            else:
                closed_fit += closed

    except socket.gaierror as e:
        e = (f"gaierror{e}")
        error_log(e)

    except Exception as e:
        error_log(e)
        pass


# THREAD FUNCTION THAT U CAN PASS A FUNCTION INTO WITH ARGS  // MAKES PORT SCAN MUCH MUCH FASTER // LOL
def threader(choice,target):
    
    # NEW TYPE OF PORT SCAN WITH THREADING
    threads = []                                                   # THIS IS WHERE THE THREADS FOR EACH PORT IS STORED
    global closed_fit # open_ports 

    # PORT SCAN OPTIONS / COMMON SCAN / FULL SCAN / CUSTOM SCAN  
    common_ports = range(0,1024)
    full_ports = range(0,65535)
    custom_scan = []               # NOT IN USE 
    
   
    table = Table(title="Port Scan", style="purple", title_style="green")
    table.add_column("Port", style="bold blue")
    table.add_column("Service", style="yellow")
    table.add_column("Status", style="bold green")

    # BASED ON USER CHOOSE PORTS WILL BECOME COMMON / FULL / OR A CUSTOM SCAN 
    if choice == 1:
        ports = common_ports
    
    elif choice == 2:
        ports = full_ports


    
    # PANELS FOR IF IT WORKED OR NOT
    panel_on = Panel("[bold green]✅ Success: Port Scan Complete[/bold green]", style="bold green on black", border_style="bold green", width=terminal_width)      # TELLS THE USER THE PORT SCAN IS COMPLETE
   # panel_off = Panel(f"[bold red]Error: Port Scan Failed[/bold red]")                                                             # TELLS THE USER THE SCAN FAILED


    try:
      
 
        # THREADS ARE MADE FOR EACH PORT DEPENDING ON USERS CHOICE
        for port in ports:

            t = threading.Thread(target=target, args=(port,table))            
            threads.append(t)

        with Live(table, console=console, refresh_per_second=1):

            for thread in threads:
                thread.start()

            for thread in threads:

                thread.join()
        
        # ONCE SCAN IS COMPLETE / SUCCESSFULL 
        console.print(f"\n[green]Open Port(s): {open_ports}[/green]")
        console.print(f"[red]Closed/Filtered Port(s): {closed_fit}[/red][bold green]")
        console.print(panel_on)                # TELLS THE USER THE SCAN WAS A SUCCESS
        print("")       # PUTS A SPACE BETWEEN THE TABLES
       
        

    except Exception as e:
        panel_off = Panel(f"[bold red]Error: {str(e)}[/bold red]")
        console.print(panel_off)
       # print(f"reguler error: {e}")          # USE THIS FOR ERROR DEBUGGING 
        t = (f"Thread: {e}")
        error_log(t)


# TAKES THE IP ADDRESS AND DOES A GEO-LOOKUP
def geo_lookup(): 

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #global domain_name 
    global ip_address, geo_info

    try:

        with open(f"{file_path_setting}", "r") as file:                   # IF THEY HAVE A API KEY THEN WE WILL USE THAT
            content = json.load(file)
            api_key_geo = content.get("api_key_geo", None)
            if api_key_geo:
                url = f"http://ipinfo.io/{ip_address}?token={api_key_geo}"

            else:
                url = (f"https://ipinfo.io/{ip_address}/json")   # FALLBACK TO FREE TIER IF SETTING IS NOT FOUND

    
    except FileNotFoundError as e:
        url = (f"https://ipinfo.io/{ip_address}/json")       # FALLBACK TO FREE TIER IF SETTING IS NOT FOUND
        error_log(e)
 
    # GEO-LOOKUP  //  # GO ON THE IPINFO WEBSITE TO CREATE AND OBTAIN A FREE API-KEY
                 
    
    try:
       
        response = requests.get(url)
        response.raise_for_status()    # FOR NETWORK RELATED ERROR HANDLING
        data = response.json()

        # TRANSFER RESULTS INTO SEPERATE VARIABLES
        show = True                                 # BOOLEAN VARIABLE SET TO SHOW SUCCESSFUL PANEL
        city = data.get('city', 'N/A')       # NA IS A BACKUP FOR IF THE FIRST FAILS AND CANT BE FOUND
        region = data.get('region', 'N/A')
        country = data.get('country', 'N/A')
        postal = data.get('postal', "N/A")
        timezone = data.get('timezone', "N/A")
        org = data.get("org", "N/A")
        host_name = data.get('hostname', "N/A")
        loc = data.get('loc', "N/A")

        # FOR IF DOMAIN IS A IP OR WE CANT FIND LOCATION
        if city and region and country and postal and timezone and org and host_name and loc == "N/A":
            panel_geo_na = Panel(f"❌ Geo-Lookup Failed,[yellow] All values == N/A[/yellow]", style= "red on black", border_style="bold red", width=terminal_width)
            show = False

        # CREATE TABLE FOR GEO LOCATION
        table_geo = Table(title="Geo-Lookup",style="purple")
        table_geo.add_column("Variable", style="bold blue")
        table_geo.add_column("Value", style="bold green")
        table_geo.add_row("Host name",f"{host_name}" )
        table_geo.add_row("Postal", (postal))
        table_geo.add_row(f"City", (city))
        table_geo.add_row("Region", (region)) 
        table_geo.add_row("Country", (country))  
        table_geo.add_row("Coordinates", f"{loc}")
        table_geo.add_row("Timezone", (timezone))
        table_geo.add_row("Organization", (org))
        
        panel_geo_pass = Panel("✅ Success: Geo-Lookup Complete",style= "bold green on black", border_style="bold green", width=terminal_width)     # THIS WILL TELL THE USER THAT TASK HAS COMPLETED
        console.print(table_geo)    
      
        
        if show:
          geo_info = (f"[bold purple]Postal:[/bold purple] [bold blue]{postal},[/bold blue] [bold purple]City:[/bold purple] [bold blue]{city},[/bold blue] [bold purple]Region:[/bold purple] [bold blue]{region},[/bold blue] [bold purple]Country:[/bold purple] [bold blue]{country},[/bold blue] [bold purple]Timezone:[/bold purple] [bold blue]{timezone},[/bold blue] [bold purple]Organization:[/bold purple] [bold blue]{org}[/bold blue]")
          console.print(panel_geo_pass)

        elif show == False:
          geo_info = (f"[bold purple]Postal:[/bold purple] [bold blue]{postal},[/bold blue] [bold purple]City:[/bold purple] [bold blue]{city},[/bold blue] [bold purple]Region:[/bold purple] [bold blue]{region},[/bold blue] [bold purple]Country:[/bold purple] [bold blue]{country},[/bold blue] [bold purple]Timezone:[/bold purple] [bold blue]{timezone},[/bold blue] [bold purple]Organization:[/bold purple] [bold blue]{org}[/bold blue]")
          console.print(panel_geo_na)

    except requests.exceptions.RequestException as req_error:   # Handle network-related errors  
        panel_geo_fail = Panel(f"❌ Network Error: {req_error}", style="red on black", border_style="bold red", width=terminal_width)
        console.print(panel_geo_fail)
        error_log(e = req_error)
    
    except Exception as e:
        panel_geo_fail = Panel(f"❌ Error: Geo-Lookup Failed, {e}",style= "red on black", border_style="bold red", width=terminal_width)     # THIS WILL TELL THE USER TASK HAS FAILED
        console.print(panel_geo_fail)
        error_log(e)

    
# SUB DOMAIN LOOKUP
def sub_resolver(sub,table):
    
    # GLOBAL VARIABLE
    global domain_name, yes_dns, results_subs_ports
    
      # FUNCTION VARIABLES


    try:

        subdomain = (f"{sub}.{domain_name}")
        rdata = dns.resolver.resolve(subdomain, "A")
        if rdata:
            data = ", ".join([str(r.address) for r in rdata])
            table.add_row(f"{subdomain}", f"{data}")
            with lock:
                 yes_dns += 1
                 result = (f"[green]{subdomain},[/green] [yellow]---- >[/yellow] [red]{data}[/red]")
                 results_subs_ports.append(result)
        
        else:
            pass

    except dns.resolver.NXDOMAIN as e:
        #error_log(e=(f"1{e}"))
        pass
        
    except dns.resolver.Timeout as e:
        error_log(e=(f"2{e}"))
        pass

    except Exception as e:
        #error_log(e=(f"3{e}"))
        pass
     
    
# SEPERATE THREAD FUNCTION DESIGINATED FOR SUB_DOMAIN LOOKUPS
def threader2(choice,target):

    print("")  # PUTS SOME SPACE BETWEEN TABLES 
    global yes_dns
    threads = []
    sub_domains = []

    # 2K SUB DOMAINS // THIS IS GONNA BE AWESOME
   
    
    if choice == 2:
    # SUB DOMAIN LIST // 140 SUB-DOMAINS IN TOTAL FOR FULL SCAN    
        closed = 140
        sub_domains = [
            "www", "mail", "webmail", "smtp", "imap", "pop3", "ftp", "http", "https", 
            "admin", "dev", "staging", "api", "cdn", "static", "cloud", "files", "assets", 
            "ssh", "vpn", "server", "management", "admin", "gateway", "nms", "monitor", 
            "sensor", "scan", "security", "logs", "test", "backup", "support", "sales", 
            "marketing", "hr", "helpdesk", "docs", "portal", "intranet", "partners", "partners", 
            "shop", "store", "payment", "cart", "account", "billing", "order", "checkout", 
            "cameras", "sensors", "monitoring", "devices", "iot", "files", "backup", "sync", 
            "dropbox", "drive", "docs", "db", "mysql", "mongodb", "postgres", "sql", "redis", 
            "cache", "data", "help", "test", "docs", "git", "staging", "www1", "www2", "web", 
            "public", "api.v1", "api.v2", "app", "apps", "service", "services", 
            "wordpress", "joomla", "drupal", "shopify", "magento", "azure", "aws", "gcp", 
            "digitalocean", "heroku", "cassandra", "hadoop", "elasticsearch", "kafka", "iot1", 
            "iot2", "devices", "gadget", "game", "media", "stream", "cdn1", "cdn2", 
            "mobile", "video", "chat", "auth", "files1", "static1", "cdn3", "cdn4", "private", 
            "testapi", "adminpanel", "demo", "portal1", "support1", "user", "helpdesk1", 
            "analytics", "database", "interface", "version", "webapp", "public1"
            ]

        
    elif choice == 1:
    # SUB DOMAIN LIST // 31 SUB-DOMAINS IN TOTAL FOR COMMON SCAN
        closed = 31
        sub_domains = ["www", "api", "admin", "mail", "blog", "dev", "shop", "store", "support", "ftp", "staging", 
                    "docs", "secure", "mobile", "test", "m", "vuln", "login", "cdn", "www2", "api1", "api2", 
                    "api3","intranet", "webmail", "portal", "files", "static", "mail1", "mail2", "billing" ]
        

    # TABLE FOR RESULTS
    table = Table(title="Subdomain - Lookup", style="purple")
    table.add_column("Subdomain", style="bold blue")
    table.add_column("Value", style="green")

    # PANEL FOR SUCCESS OR FAIL
    panel_on = Panel("✅ Success: Sub-Domain Lookup Complete", style="bold green on black", border_style="bold green", width=terminal_width)
    panel_off = Panel("❌ Sub-Domain Lookup Failed, No valid Sub-Domains found", style="red on black", border_style="bold red", width=terminal_width)
    
    for sub in sub_domains:
        t = threading.Thread(target=target, args=(sub,table))
        threads.append(t)
    
    with Live(table, console=console, refresh_per_second=1):
        
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


    closed = closed - yes_dns  # CALCULATES HOW MANY FAILED LOOKUPS OCCURED
    print("")
    console.print(f"[bold green]Successful Lookups: {yes_dns}[/bold green]")
    console.print(f"[red]Failed Lookups: {closed}[/red]")


    if yes_dns > 0:               # CHECKS WEATHER TO PRINT FAILED OR SUCCESSFUL 
       console.print(panel_on)
       yes_dns = 0

    else:
       console.print(panel_off)  # IF THERE WERE NO SUCCESSFUL LOOKUPS THEN YOU GET FAILED
       yes_dns = 0
    
    console.print("")  # SPACE BETWEEN TABLES

# DEEP ANYALSIS + CVE LOOKUP // WITH SHODAN
def version_lookup():


    global results_open_ports, ip_address, shodan_results

    shodan_results = []       # MAKE A LIST TO STORE RESULTS IN 


    try:
        with open(f"{file_path_setting}", "r") as file:
            content = json.load(file)
            api_setting = content.get("api_setting", "off")

            if api_setting == "on":                # IF API SETTINGS IS ON THEN WE WILL ASK ELSE SKIP
    
                try:
                    #with open(f"{file_path_setting}", "r") as file:            # CHECK SETTINGS FILE FOR SHODAN API KEY
                       # content = json.load(file)

                        api_key_shodan = content.get("api_key_shodan", None)
                        
                        if api_key_shodan:

                            print("")     # CREATES SPACE BETWEEN TABLES
                            vuln = False
            
                            try:
                            
                                # CREATE THE API OBJECT
                                api = shodan.Shodan(api_key_shodan)
                                host = api.host(ip_address)
                                #print(host)
                                
                                # CREATE TABLE FOR OUTPUT
                                table = Table(title="Shodan Host Information", style='purple', title_style="bold red", header_style="bold red")
                                table.add_column("Variable", style="bold blue")
                                table.add_column("Value", style="green")

                                # PANEL FOR SUCCESS
                                panel = Panel("✅ Success: Shodan info lookup complete", style="bold green", border_style="bold green", width=terminal_width)
                                
                                # FOR VULNS
                               
                            
                                with Live(table, console=console, refresh_per_second=1):

                                    for item in host["data"]:

                                        
                                        table.add_row(f"Port:", f"{item.get('port', 'unkown')}")
                                        table.add_row(f"IP Address:", f"{item.get('ip_str', 'Unknown')}")
                                        table.add_row(f"Vulns:", f"{item.get('vulns', 'none found')}")
                                        table.add_row(f"ASN:", f"{item.get('asn', 'Unknown')}")
                                        table.add_row(f"Organization:", f"{item.get('org', 'Unknown')}")
                                        table.add_row(f"Service:", f"{item.get('http', {}).get('status', 'Unknown')} - {item.get('http', {}).get('title', 'Unknown')}")
                                        table.add_row(f"Location:", f" {item.get('location', {}).get('city', 'Unknown')}, {item.get('location', {}).get('region_code', 'Unknown')}, {item.get('location', {}).get('country_name', 'Unknown')}")
                                        table.add_row(f"Cloud Provider:", f"{item.get('cloud', {}).get('provider', 'Unknown')}")
                                        table.add_row(f"Hostnames:", f"{', '.join(item.get('hostnames', ['Unknown']))}")
                                        table.add_row(f"Tags:", f"{', '.join(item.get('tags', ['None']))}")
                                        table.add_row(f"Domains:", f"{', '.join(item.get('domains', ['None']))}")

                                        vulnerabilites = item.get("vulns", False)
                                        if vulnerabilites:
                                            for vuln in vulnerabilites:
                                                table.add_row("Vuln ID", f"{vuln}")
                                            vuln = list(vulnerabilites) if vulnerabilites else []


                                        else:
                                            vuln = False

                                        # SAVE TO VARIABLES SO WE CAN SAVE THEM TO FILE OUTPUTS
                                        port = (f"{item.get('port', 'unkown')}")
                                        ip = (f"{item.get('ip_str', 'Unknown')}")
                                        asn = (f"{item.get('asn', 'Unknown')}")
                                        org = f"{item.get('org', 'Unknown')}"
                                        service = (f"{item.get('http', {}).get('status', 'Unknown')} - {item.get('http', {}).get('title', 'Unknown')}")
                                        location = (f" {item.get('location', {}).get('city', 'Unknown')}, {item.get('location', {}).get('region_code', 'Unknown')}, {item.get('location', {}).get('country_name', 'Unknown')}")
                                        cloud = (f"{item.get('cloud', {}).get('provider', 'Unknown')}")
                                        hostname = (f"{', '.join(item.get('hostnames', ['Unknown']))}")
                                        tags = (f"{', '.join(item.get('tags', ['None']))}")
                                        domains = (f"{', '.join(item.get('domains', ['None']))}")

                                        # NOW ADD TO RESULTS
                                        
                                        result_s = (f"[bold blue]Port:[/bold blue] {port}, [bold blue]IP Address:[/bold blue] {ip}, [bold red]Vuln ID: {vuln}[/bold red], [bold blue]ASN:[/bold blue] {asn}, [bold blue]Organization:[/bold blue] {org}, [bold blue]Service:[/bold blue] {service}, [bold blue]Location:[/bold blue] {location}, [bold blue]Cloud:[/bold blue] {cloud}, [bold blue]Hostname:[/bold blue] {hostname} [bold blue]Tags:[/bold blue] {tags} [bold blue] Domain Names: [/bold blue]{domains}")
                                        shodan_results.append(result_s)


                                        table.add_section()

                                console.print(panel)
                                return shodan_results
                            
                                



                            except shodan.exception.APITimeout as e:
                                panel_fail = Panel(f"[red]❌ Shodan API Timeout Error:[/red] [yellow]{e}[/yellow]", border_style="bold red", width=terminal_width)
                                console.print(panel_fail)
                                error_log(e)
                        

                            except shodan.exception.APIError as e:
                                panel_fail = Panel(f"[red]❌ Shodan API Error:[/red] [yellow]{e} // Refer to the help menu if problem persist[/yellow]", border_style="bold red", width=terminal_width)
                                console.print(panel_fail)
                                error_log(e)
                          
                                #api = shodan.Shodan(api_key_shodan)
                                #status = api.info()
                                #console.print(status, style="green")  # USE FOR DEBUG

                            
                            except Exception as e:
                                panel_fail = Panel(f"[red]❌ Shodan unkown Error:[/red] [yellow]{e}[/yellow]", border_style="bold red", width=terminal_width)
                                console.print(panel_fail)
                                error_log(e)
                            
                                
                            finally:
                                nvd(vulns=vuln)# PASS CVE'S TO NVD // OR PASS IF SHOLDAN DIDNT RETURN ANY
                  

                        else:
                            panel_off = Panel("❌ Skipped: Unable to use shodan services without an API Key, Read the help menu to assign one!", style="yellow on black", border_style="bold red", width=terminal_width)
                            #print("\n")
                            console.print(panel_off)
                            nvd(vulns=False)
                          

                            pass
                

                except FileNotFoundError as e:        # IF FILE NOT FOUND SKIP // DEEPER ISSUE THAT SHOULD BE RESOLVED BY DATA AND WELCOME FUNCTION
                    panel_off = Panel("❌ Skipped: Unable to use Shodadadn services without an API Key, Read the help menu to assign one!", style="yellow on black", border_style="bold blue", width=terminal_width)
                    #print("\n")
                    console.print(panel_off)
                    nvd(vulns=False)
                    error_log(e)
                    pass

            else:
                pass
    
    except FileNotFoundError:
        console.print(f"[red]❌ Error: [/red][yellow]{e}[/yellow] [green]Please restart the program and try again[/green]")
        time.sleep(2.5)
        error_log(e)
    
   
# CVE LOOKUP WITH // NVD
def nvd(vulns):# CVE DETECTION
    
    # IF SETTING IS TURNED ON // OR OFF
    
    try:
        with open(f"{file_path_setting}", "r") as file:
            content = json.load(file)
            api_setting = content.get("api_setting", "off")  # CHECK THE SETTING OPTION
    
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] [yellow]File not found please restart the program! [/yellow]")
        api_setting = "off"
        error_log(e)
    
    except Exception as e:
        console.print(f"[red]Error:[/red] [yellow]{e},[/yellow] [green]If the issue persist please launch the help menu[/green]")
        api_setting = "off"
        error_log(e)



    # IF SETTING IS TURNED ON // OR OFF
 
    if api_setting == "on":

        api_key_nvd = content.get("api_key_nvd", False)
        #print("pass")

        if api_key_nvd and vulns:
                #print("pass")
                console.print("NVD ON", style="bold green")
                console.print("")  # PUTS SOME SPACE BETWEEN TABLE OUTPUTS
                
                # CREATE TABLE FOR OUTPUT
                table = Table(title="test", style="bold purple")
                table.add_column("CVE ID")
                table.add_column("CVE Desc")

                # PANELS
                panel_on = Panel("✅ Success: NVD info lookup complete", style="bold green", border_style="bold green", width=terminal_width)
                panel_no = Panel(f"No known CVE's found for {domain_name}", style="bold green", border_style="bold green", width=terminal_width)
                show = False

                with Live(table, console=console, refresh_per_second=2):
                    for vuln in vulns:
                        try:
                            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0{vuln}"
                            
                            headers = {"apikey": api_key_nvd
                                    }
                            
                            response = requests.get(url, headers=headers)
                            
                            if response.status_code == 200:

                                cve = response.json() 
                                # DEFINE VARIABLES // PULL INFO FROM NVD
                                vuln_info = cve.get('vulnerabilities', [])[0].get('cve', {})
                                cve_id = vuln_info.get('id', 'N/A')
                                cve_desc = vuln_info.get('descriptions', [])[0].get('value', 'No description available')

                                table.add_row(cve_id, cve_desc)
                                show = True
                
                               
                            else:
                                console.print(f"[yellow]❌ Warning:[/yellow] Failed to fetch CVE {cve_id}, status: {response.status_code}")
                                                             
                     

                        except Exception as e:
                            console.print(f"[red]❌ Error processing CVE data:[/red] {e}")
                            error_log(e)

                    if show:
                        console.print(panel_on)
                    else:
                        console.print(panel_no) 
                              
        else:
            panel_off = Panel("❌ Skipped: Unable to use NVD services without SHOLDAN, Read the help menu if further help or info is needed!", style="yellow on black", border_style="bold red", width=terminal_width)
            panel_def = Panel("Skipped: Vulnerability Lookup with // NVD CVE // COMING SOON", style="yellow on black", border_style="bold red", width=terminal_width)
            console.print("")
            #console.print(panel_off)
            console.print(panel_def)

    else:
        pass


          
# DISPLAYS TO THE USER ABOUT INFORMATION ABOUT ME I GUESS // THE DEVELOPER OF THIS PROJECT  // LOL    
def about_me():

    clear_screen()
    name = pyfiglet.figlet_format("N S M  Barii")
    namepanel = Panel(name, style="purple", border_style="bold purple", width=terminal_width)
    print("\n")
    console.print(namepanel)
    descpanel = Panel("\n Yooooooo wassuh yall boyz. As yall already know my name is Jabari & as of me writing this i am currently at the end of this project and finally made"
    " my decision to just go ahead and push this project over to GitHub where I will from here on out be posting any and all of my most polished projects i honestly cant wait."
    " I just want to thank you guyz for watching my Youtube video if you have seen it and i am really happy and motivated for whats to come. Between programming and reading"
    " all the motivational comments on my videos I am now and forever will be a programmer and its honestly such a good thing to be able to say."
    "\n\n I had created this project while working full time 40-50 hours a week, going to school full time, learning how to programming as im only 2 months in learning Python, while also trying to squeeze in the gym. If not for all of that i lowkey feel as if i could have completed it in about maybe half the time but it was worth it glad yall got to see the progress."
    "\nAnyways see you guys in my next major project."
    "\n\n\nStart Date: [bold blue]12/12/2024[/bold blue]"
    "\nEnd Date: [bold blue]1/16/2025[/bold blue]"
    "\n\nAuthor: [bold blue]NSM Bari[/bold blue]",
     style="green", border_style="purple", width=terminal_width)
    console.print(descpanel)
    console.input("[red]\n\n\nENTER TO EXIT OR DONT IF YOU LOVE IT HERE: [/red]")
    clear_screen()
    welcome()


# DISPLAYS TO THE USER WHICH EACH TYPE OF PORT SCAN DOES // COMMON // FULL // CUSTOM
def show_help_menu():

    clear_screen()
    # TABLES
    help_in = pyfiglet.figlet_format("NSM Help Menu")
    help_menu_title = Panel(f"{help_in}", style="green", border_style="bold green", width= terminal_width)
    help_menu_desc = Panel("\n[green]1.[/green][red] Common Port Scan[/red] -[yellow] Scans the most commonly used ports: 0-1024.[/yellow]\n\n[green]2. [green][red]Full Port Scan[red] - [yellow]Scans all ports from 0 to 65,535 on the target system.[/yellow]\n\n[green]3.[/green][red] Custom Port Scan [/ red]-[yellow] Allows you to specify custom ports to scan.[/yellow]\n")

    # COMMON SCAN EXPLAINED
    common_panel = Panel(
    "\n[green]1.[/green][red] Domain Resolution[/red] -[yellow] Resolves hostname to IP Address:[/yellow] [bold blue]Upon entry of a valid domain name that domain name will be resolved into its IP Address and passed along to other program functions.[/bold blue]\n\n"
    "[red]Common Port Scan[/red] -[yellow] Scans the most commonly used ports:[/yellow][bold blue] 0-1024.[/bold blue]\n\n"
    "[red]Geo-IP Lookup[/red] - [yellow]Performs a lookup to determine the geographical location of an IP address[/yellow]:[bold blue] including country, city, region, and coordinates, helping identify the origin of traffic, detect malicious sources, and gain insights into network distribution.[/bold blue]\n\n"
    "[red]Sub-Domain Lookup[/red] - [yellow]Performs a threaded sub-domain lookup of:[/yellow][bold blue] www, api, admin, mail, blog, dev, shop, store, support, ftp, staging, docs, secure, mobile, test, m, vuln, login, cdn, www2, api1, api2, api3, intranet, webmail, portal, files, static, mail1, mail2, billing.[/bold blue]\n\n"
    "[red]Shodan Services[/red] - [yellow]An advanced search engine for internet-connected devices:[/yellow][bold blue] It provides detailed information about servers, IoT devices, and other internet-facing systems, including open ports, services, vulnerabilities, and configuration details. Shodan integration allows for efficient reconnaissance and improved vulnerability assessment by gathering publicly available data from its extensive database.[/bold blue]",
    border_style="bold purple", width=terminal_width, title="Common port scan"
)

   # FULL SCAN EXPLAINED
    full_panel = Panel(
    "\n[green]2.[/green][red] Domain Resolution[/red] -[yellow] Resolves hostname to IP Address:[/yellow] [bold blue]Upon entry of a valid domain name that domain name will be resolved into its IP Address and passed along to other program functions.[/bold blue]\n\n"
    "[red]Full Port Scan[/red] -[yellow] Scans all possible ports from :[/yellow][bold blue] 0 to 65,535.[/bold blue]\n\n"
    "[red]Geo-IP Lookup[/red] - [yellow]Performs a lookup to determine the geographical location of an IP address[/yellow]:[bold blue] including country, city, region, and coordinates, helping identify the origin of traffic, detect malicious sources, and gain insights into network distribution.[/bold blue]\n\n"
    "[red]Sub-Domain Lookup[/red] - [yellow]Performs a threaded sub-domain lookup of:[/yellow][bold blue] www, mail, webmail, smtp, imap, pop3, ftp, http, https, admin, dev, staging, api, cdn, static, cloud, files, assets, ssh, vpn, server, management, gateway, nms, monitor, sensor, scan, security, logs, test, backup, support, sales, marketing, hr, helpdesk, docs, portal, intranet, partners, shop, store, payment, cart, account, billing, order, checkout, cameras, sensors, monitoring, devices, iot, files, backup, sync, dropbox, drive, docs, db, mysql, mongodb, postgres, sql, redis, cache, data, help, test, docs, git, staging, www1, www2, web, public, api.v1, api.v2, app, apps, service, services, wordpress, joomla, drupal, shopify, magento, azure, aws, gcp, digitalocean, heroku, cassandra, hadoop, elasticsearch, kafka, iot1, iot2, devices, gadget, game, media, stream, cdn1, cdn2, mobile, video, chat, auth, files1, static1, cdn3, cdn4, private, testapi, adminpanel, demo, portal1, support1, user, helpdesk1, analytics, database, interface, version, webapp, public1.[/bold blue]\n\n"
    "[red]Shodan Services[/red] - [yellow]An advanced search engine for internet-connected devices:[/yellow][bold blue] It provides detailed information about servers, IoT devices, and other internet-facing systems, including open ports, services, vulnerabilities, and configuration details. Shodan integration allows for efficient reconnaissance and improved vulnerability assessment by gathering publicly available data from its extensive database.[/bold blue]",
    border_style="bold purple", width=terminal_width, title="Full port scan"
)
    
    
    # MY SOCIALS // CONTACTS
    s = pyfiglet.figlet_format("Contact INFO")
    s_panel = Panel(s, style="bold green", width=terminal_width, border_style="bold green")
    social_panel = Panel(
    "[bold green]Discord: [/bold green][bold blue] (discord here)[/bold blue]"
    "[bold green]Twitter: [/bold green][bold blue]NSM_Barii[/bold blue]\n\n"
    "[bold green]Reddit: [/bold green][bold blue]NSM Barii[/bold blue]\n\n"
    "[bold green]GitHub:[/bold green][bold blue] NSM Barii[/bold blue]\n\n"
    "[bold green]Shopify: [/bold green][bold blue]www.nsmbarii.com  //  (NOT YET SETUP)[/bold blue]\n\n"
    "[bold green]Linkedin: [/bold green][bold blue]www.linkedin.com/in/jlucien20[/bold blue]\n\n"
    #"[bold green]Email: [/bold green][bold blue]jabarilucien123@gmail.com[/bold blue]\n\n"
    "[bold red]Youtube: [/bold red][bold blue]NSM Barii[/bold blue]",
    style="bold green", title="Socials", width=terminal_width, border_style="bold green"                  
                        
    )


    # API'S // HOW TO WORK THEM
    a = pyfiglet.figlet_format("API' s")
    a_panel = Panel(a, style="bold red", border_style="bold red", width=terminal_width)
    api_panel = Panel(
    "\n\n[red]Ipinfo: [/red] [bold blue]ipinfo.com // you have the option of entering your api key for ipinfo if not program will default to a link that doesnt require one but comes with reduces usage on api calls for geo ip lookup info. With ipinfo's api key, u will be able to pull a total of 50,000 request per month with the free plan, more then enough even for heavy usage.[/bold blue]\n\n"
    "[red]Shodan: [/red] [bold blue]Shodan.io // you will have the option of entering your api key for shodan if no key is found then you will not be able to perform cve or any other type of lookups with this service until you provide a valid key. // If you are experiencing probelms with shodan make sure u have a valid amount of query credits if problem still pursist feel free to contact me for further support[/bold blue]\n\n"
    "[red]NVD: [/red] [bold blue]nvd.nist.gov/general //At the time of release for NetVuln 1.0, I have implemented the ability to use nvd's api for cve lookup but upon trial and error numerous times I coudnt get it to work even after trying to hardcode valid CVE ID's so for now this will be skipped, but I will continue to work towards trying to figure out a way to implement it. Until then if u have any ideas or recommendations feel free to let me know[/bold blue]\n",
     style="bold red", border_style="bold red", width=terminal_width, title="API Info"
    )




    # LIBARIES USED
    l = pyfiglet.figlet_format("Libaries")
    l_panel = Panel(l, style="yellow", border_style="yellow", width=terminal_width)
    lib_panel = Panel(
    "\n\n[yellow]1. [/yellow][red]rich:[/red][bold purple] For visually appealing CLI[/bold purple]\n\n"
    "[yellow]2. [/yellow][red]PyFiglet[/red][bold purple] For Ascii look alike visuals // (menu headers)[/bold purple]\n\n"
    "[yellow]3. [/yellow][red]Pyler[/red][bold purple] Used for Notifications (Primarily for windows // might use for emails in NetVuln 2.0) [/bold purple]\n\n"
    "[yellow]4. [/yellow][red]socket: [red][bold purple]Used for socket connections for Domain resoluton, Port scanning, Local IP & Host lookup [/bold purple]\n\n"
    "[yellow]5. [/yellow][red]platform[/red][bold purple] Used for system info lookup like os name, system version, etc. (This info is found in the settings menu) [/bold purple]\n\n"
    "[yellow]6. [/yellow][red]dns.resolver[/red][bold purple] Used to resolve predefined subdomains with resolved domain name to ip address[/bold purple]\n\n"
    "[yellow]7. [/yellow][red]threading[/red][bold purple] Used to significantly speed up port scanning and subdomain resolving[/bold purple]\n\n"
    "[yellow]8. [/yellow][red]json[/red][bold purple] Used to save user settings[/bold purple]\n\n"
    "[yellow]9. [/yellow][red]time[/red][bold purple] Used to delay certain sections in the script[/bold purple]\n\n"
    "[yellow]10. [/yellow][red]datetime[/red][bold purple] Used to produce timestamps[/bold purple]\n\n"
    "[yellow]11. [/yellow][red]subprocess[/red][bold purple] Used PURELY For linux/unix devices for dns resolving. (IF YOU ARE ON WINDOWS THIS WILL NOT BE USED FOR YOU)[/bold purple]\n\n"
    "[yellow]12. [/yellow][red]pathlib[/red][bold purple] Used to set default file path for setting and scan results for all os platforms dynamically[/bold purple]\n\n"
    "[yellow]13. [/yellow][red]shodan[/red][bold purple] Used for info lookup via the internet[/bold purple]\n\n",
    style="yellow", border_style="yellow", width=terminal_width, title="Libaries Used"
         
    

    )



    console.print(help_menu_title)
    print("\n")
    console.print(common_panel)
    print("")
    console.print(full_panel)
    print("\n")
    console.print(a_panel, api_panel)
    print("\n")
    console.print(l_panel, lib_panel)
    print("\n")
    console.print(s_panel, social_panel)
    
    
    time.sleep(.5)
    time.sleep(.5)
    console.print("\n\n[yellow]If your enjoying the program let me know by subcscribing to my YouTube Channel[/yellow]:[green] NSM Barii[/green]")
    console.input("[green]Press Enter Whenever Your[/green][red]ready [/red][yellow]to leave: [/yellow]")
    


# USED TO CLEARSCREEN // FOR SMOOTHER TRANSITIONS 
def clear_screen():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


# NOTIFICATIONS  
def noty(type,msg):
    
    if type == 1:
      if not hasattr(noty, "count"):
          noty.count = 0
      noty.count += 1   
      if noty.count < 2: 
        notification.notify(
        title = "NetVuln",
        app_name = "NetVuln",
        message = (msg),
        timeout = 8
        )
      else:
          pass
    
    if type == 2:
          try:
            with open(f"{file_path_setting}", "r") as file:
                content = json.load(file)
                noty_setting = content["noty_setting"]

                if noty_setting == "off":
                    pass   # NO ACTIONS WHEN NOTIFICATIONS ARE OFF
                
                elif noty_setting == "on":
                    notification.notify(
                        title = "NetVuln",
                        message = (msg),
                        app_name = "NetVuln",
                        timeout = 8
                    )

          except FileNotFoundError as e:
              console.print("[red]Error:[/red] [yellow]Settings file not found.[/yellow]")
              error_log(e)

          except json.JSONDecodeError as e:
              console.print("[red]Error:[/red] [yellow]Issue reading the settings file.[/yellow]")
              error_log(e)
              


# DATA HANDLING  // FILE SAVING AND PULLING
def data(type,letter):

    if type == 1:   # FOR TXT FILES // SCAN RESULTS

        try:
            with open(f"{file_path}", "a") as file:                            # SAVES THE RESULTS TO A TXT FILE
                file.write(f"{letter}")
                console.print("\n[green]Results successfully Saved[/green]")

        except FileNotFoundError as e:                                            # IF FILE DOESNT EXIST WELL MAKE IT THEN CONTINUE TO SAVE RESULTS
            console.print(f"[red]File not found: {e}[/red]")
            with open(f"{file_path}", "w") as file:
                file.write(f"{letter}")
                console.print("[green]File successfully created & Saved[/green]")
                error_log(e)

        except FileExistsError as e:                                            # EHH FURTHER ERROR HANDLING IG // LOL
            with open(f"{file_path}", "a") as file:
                file.write(f"{letter}")
                console.print("[green]File change Successful[/green]")
                error_log(e)

    elif type == 2:  # FOR TEXT FILES // SCAN RESULS

        try:
            with open(f"{file_path}", "r") as file:
                content = file.read()
                console.print(f"{content}")
                

        except FileNotFoundError as e:
            console.print("[red]Error:[/red] [yellow]File not found[/yellow],  [green]Perform your first scan in order to create one![/green]")
            error_log(e)

    elif type == 3:  # FOR JSON FILES // SETTING

        try:
            with open(f"{file_path_setting}", "r") as file:
                content = json.load(file)
                return(content)
                

        except FileNotFoundError as e:
            
            # CREATE DEFAULTS VALUSE FOR NOW
            data = {
                "display_name": "user",
                "noty_setting": "on",
                "scans": 0,
                "scan_show": "on",
                "api_key_geo": "",
                "api_key_shodan": "",
                "api_key_nvd": "",
                "api_setting": "off"
            }
   
            # SAVES THE DEFAULT SETTINGS TO A JSON FILE
            with open(f"{file_path_setting}", "w") as file:
                json.dump(data, file, indent=9)
                console.print("[green]File successfully created & Saved[/green]")
                return data
            
            error_log(e)


# SAVE RESULTS IN CLEAN TEXT // NO COLOR CODE // CAN THEN EXPORT RESULTS TO DESKTOP
def clean_text(type,clean_letter):

    # DEFINE DESKTOP DIS
    desk = Path.home() / "Desktop" 

    # TO WRITE // APPEND INFO
    if type == 1:
    
        try:
            with open(f"{file_path_clean}", "a") as file:
                file.write(clean_letter)
                console.print("[red]x[/red][green]2[/green]")
        
        except FileNotFoundError as e:
            with open(f"{file_path_clean}", "w") as file:
                file.write(clean_letter)
                error_log(e)
        
        except Exception as e:
            console.print(f"Error trying to save files please restart program to try and fix the issure", style="bold red")
            
            error_log(e)
    

    # TO PULL // READ INFO
    if type == 2:

        try:
            with open(f"{file_path_clean}", "r") as file:  # PULL FROM MAIN FILE FOLDER 
                content = file.read(file)
                try:
                    with open(f"{desk}", "w") as file:    # TO THEN PRINT TO NEW DIRECTORY ON THE DESKTOP
                        file.write(content)

                except FileNotFoundError as e:
                    with open(f"{desk}", "w") as file:
                        file.write(content)
                        console.print(f"\n\n[red]Error:[/red] [yellow]File path not found[/yellow],[green] will create new  directive....[/green]")
                        time.sleep(1.5)
                        console.print(f"\n\nScan Results Successfully Exported to {desk}")
                    error_log(e)

        
        except FileNotFoundError as e:
            console.print(f"[red]Error:[/red] [yellow]No scan results to show please perform your first scan[/yellow],[green] then try again[/green]")
            time.sleep(2)
            error_log(e)



# USER CAN CHOOSE HOW PROGRAM INTERACTS WITH UI
def setting():
    # SET TO FALSE FOR ERROR MESSAGES TO POP UP IN CLEANER WAY
    error = False
    # Load or create settings
    settings = data(3, "NA")

    # Extract current settings
    display_name = settings.get("display_name", "User")
    noty_setting = settings.get("noty_setting", "on")

    while True:
        # Display the welcome message with the current display name
        display = pyfiglet.figlet_format(f"Welcome\n{display_name}")
        panel = Panel(display, style="purple", border_style="bold purple", width=terminal_width)
        console.print(panel)
        print("\n")

        # Menu options for user to choose
        panel_choices = Panel(
            "[bold blue]1. Change Display Name\n2. Change Notification Setting\n\n3. API Key --> IPinfo\n4. API Key --> Shodan\n5. API Key --> NVD\n6. API Toggle \n\n7. Clear Scan Results\n8. Flush DNS Cache\n9. View Host Info\n10.Toggle Scan # display\n\n11. Error Logging\n\n12. EXIT[/bold blue]",
            border_style="green", width=terminal_width
        )
        console.print(panel_choices)

        if error:
            console.print(f"\n[red]Error:[/red] [bold blue]{choice}[/bold blue] [yellow]is a invalid option [yellow]please choose from options[/yellow] [green](1-12)[/green] ")

        choice = console.input("\n[green]Type your choice here: [/green]").strip()

        if choice == "1":
            error = False 
            # Change display name
            display_name = console.input("[yellow]Enter your new display name: [/yellow]").strip()
            settings["display_name"] = display_name
            # Save updated settings to the JSON file
            with open(f"{file_path_setting}", "w") as file:
                json.dump(settings, file, indent=9)
            time.sleep(.5)
            clear_screen()

        elif choice == "2":
            error = False                   # CHANGE ERROR BACK TO FALSE // IN CASE ITS NOT FROM ELSE STATEMENT
            # Change notification setting
            while True:
                noty_setting = console.input("[yellow]Set notifications to 'on' or 'off': [/yellow]").strip().lower()
                if noty_setting in ["on", "off"]:
                    settings["noty_setting"] = noty_setting
                    # Save updated settings to the JSON file
                    with open(f"{file_path_setting}", "w") as file:
                        json.dump(settings, file, indent=9)
                    console.print(f"[green]Notifications are now set to {noty_setting}.[/green]")
                    time.sleep(.5)
                    clear_screen()
                    break
                else:
                    console.print("[red]Error:[/red] [yellow]Invalid entry. Please type 'on' or 'off'.[/yellow]")

        
        # KEY FOR IPINFO
        elif choice == "3":
            
            show = False  # WEATHER TO SHOW API KEY OR NOT  // #DISCOUNTINUED
            error = False

            try:
                with open(f"{file_path_setting}", "r") as file:
                    content = json.load(file)
                    api_key_geo = content.get("api_key_geo", None)
                    show = True                                      # SHOW THE CURRENT API KEY SINCE ITS THERE
            
            except FileNotFoundError as e:
                error_log(e)
                pass

            except Exception as e:
                error_log(e)
                pass
        
            
            print("\n\n")
            console.print(f"Current API Key: {api_key_geo}")
        
            

            while True:
                choice = console.input(f"[yellow]Do you want to replace or add your own API key[/yellow][green](y/[/green][red]n):[/red] ").lower().strip()
                if choice == "y":

                    try:
                        
                        api_key_geo = console.input(f"[bold blue]Enter API Key: [/bold blue]")

                        url = "https://ipinfo.io/json"   # URL for validation (valid API endpoint)
                        headers = {"Authorization": f"Bearer {api_key_geo}"}        # Validate the API key by making a request
                        response = requests.get(url, headers=headers)   # Send a request to the API using the provided key

                        if response.status_code == 200:

                            console.print("[green]API Key successfully Validated![/green]")
                            settings["api_key_geo"] =  api_key_geo

                            with open(f"{file_path_setting}", "w") as file:
                                json.dump(settings, file, indent=9)
                                console.print(f"[green]API Key: {api_key_geo} Successfully updated[/green]")
                                time.sleep(1.5)
                                clear_screen()
                                break

                        else:
                            
                            console.print("[red]API Key Failed to validate, ensure you entered your key properly and try again![/red]")
                            console.print("[yellow]Refer to the help menu for more info if you have any questions [/yellow]")
                            time.sleep(3)
                            clear_screen()
                            break

                        

                    except Exception as e:
                        console.print(f"[red]Error:[/red] [yellow]{e}[/yellow]")
                        error_log(e)

                elif choice == "n":
                    console.print("Returning to setting menu")
                    time.sleep(1)
                    clear_screen()
                    break
                
                else:
                    console.print("[yellow]Please choose a valid option[/yellow][green](y/[/green][red]n)[/red]")

        
        # KEY FOR SHADON
        elif choice == "4":
            
            error = False

            try:
                with open(f"{file_path_setting}", "r") as file:
                    content = json.load(file)
                    api_key_shodan = content.get("api_key_shodan", False)
                    show = True                                      # SHOW THE CURRENT API KEY SINCE ITS THERE
            
            except FileNotFoundError as e:
                error_log(e)
                pass

            except Exception as e: 
                error_log(e)
                pass
        
            
            print("\n\n")
            console.print("Current INFO", style= "bold blue")
            console.print(f"Current Shodan API Key: {api_key_shodan}", style="bold green")
            if api_key_shodan:
                api = shodan.Shodan(api_key_shodan)
                status = api.info()
                #panel_status = Panel(status, title="Account Info",style="green on black", border_style="bold green", width=terminal_width)
                console.print(f"[bold green]{status} [/bold green]")
                print("")
        
            

            while True:

                choice = console.input(f"[yellow]Do you want to replace or add your own API key[/yellow][green](y/[/green][red]n):[/red] ").lower().strip()
                if choice == "y":

                    try:
                        
                        api_key_shodan = console.input(f"[bold blue]Enter API Key: [/bold blue]")

                        api = shodan.Shodan(api_key_shodan)
                        account_info = api.info()

                        if account_info:

                            console.print("[green]API Key successfully Validated![/green]")
                            settings["api_key_shodan"] =  api_key_shodan

                            with open(f"{file_path_setting}", "w") as file:
                                json.dump(settings, file, indent=8)
                                console.print(f"[green]API Key: {api_key_shodan} Successfully updated[/green]")
                                time.sleep(1.5)
                                clear_screen()
                                break

                        else:
                            
                            console.print("[red]API Key Failed to validate, ensure you entered your key properly and try again![/red]")
                            console.print("[yellow]Refer to the help menu for more info if you have any questions [/yellow]")
                            time.sleep(3)
                            clear_screen()
                            break

                    except Exception as e:
                        console.print(f"[red]Error:[/red] [yellow]{e}[/yellow]")
                        console.print("[red]API Key Failed to validate, ensure you entered your key properly and try again![/red]")
                        console.print("[yellow]Refer to the help menu for more info if you have any questions [/yellow]")
                        error_log(e)
                        time.sleep(3)
                        clear_screen()
                        break

                elif choice == "n":
                    console.print("Returning to setting menu")
                    time.sleep(1)
                    clear_screen()
                    break
                
                else:
                    console.print("[yellow]Please choose a valid option[/yellow][green](y/[/green][red]n)[/red]")


        # KEY FOR NVD
        elif choice == "5":
            
            show = False  # WEATHER TO SHOW API KEY OR NOT
            error = False
            setting = ""

            try:
                with open(f"{file_path_setting}", "r") as file:
                    content = json.load(file)
                    api_key_nvd = content.get("api_key_nvd", None)
                    show = True                                      # SHOW THE CURRENT API KEY SINCE ITS THERE
            
            except FileNotFoundError as e:
                error_log(e)
                pass

            except Exception as e:
                error_log(e)
                pass
        
            
            console.print(" ")
            console.print(f"Current API Key: {api_key_nvd}")
        
            

            while True:
                choice = console.input(f"[yellow]Do you want to replace or add your own API key[/yellow][green](y/[/green][red]n):[/red] ").lower().strip()
             
                if choice == "y":

                    try:
                        
                        api_key_nvd = console.input(f"[bold blue]Enter NVD API Key: [/bold blue]")

                        #url = "https://services.nvd.nist.gov/rest/json/cves/2.0"   # URL for validation (valid API endpoint)
                       # params = {"apikey": api_key_nvd}        # Validate the API key by making a request
                        #response = requests.get(url, params=params)   # Send a request to the API using the provided key

                        #if response.status_code == 200:

                       # console.print("[green]API Key successfully Updated![/green]")
                        settings["api_key_nvd"] =  api_key_nvd
                        
                        
                        with open(f"{file_path_setting}", "w") as file:
                            json.dump(settings, file, indent=8)
                            console.print(f"[green]API Key: {api_key_nvd} Successfully updated[/green]")
                            time.sleep(1.5)
                            clear_screen()
                            break

                       # else:
                            
                           # console.print("[red]API Key Failed to validate, ensure you entered your key properly and try again![/red]")
                           # console.print("[yellow]Refer to the help menu for more info if you have any questions [/yellow]")
                           # time.sleep(3)
                           # clear_screen()
                            #break

                    except Exception as e:
                        console.print(f"[red]Error:[/red] [yellow]{e}[/yellow]")
                        error_log(e)

                elif choice == "n":
                    console.print("Returning to setting menu")
                    time.sleep(1)
                    clear_screen()
                    break
                
                else:
                    console.print("[yellow]Please choose a valid option[/yellow][green](y/[/green][red]n)[/red]")
        

        # TURN API'S ON  //  OFF
        elif choice == "6":

            try:

                with open(f"{file_path_setting}", "r") as file:
                    content = json.load(file)
                    setting = content.get("api_setting")
                    
                    print("\n")
                    console.print(f"[bold blue]API's currently set to:[/bold blue] [yellow]{setting}[/yellow]")
                  
                    while True:

                        choice = console.input("[bold blue]Do you want API's On or Off: [/bold blue]").strip().lower()
                        
                        if choice == "off" or choice == "on":

                            content["api_setting"] = choice  # RETURN USER CHOICE TO JSON FILE

                            with open(f"{file_path_setting}", "w") as file:
                                json.dump(content, file, indent=8)
                                print("")
                                console.print(f"[yellow]API's Configuration now set to:[/yellow] [green]{choice}[/green]")
                                time.sleep(1.7)
                                clear_screen()
                                break

                        else:
                            console.print("[red]Error:[/red] [yellow]invalid choice, please try again[/yellow]")
            
            except FileNotFoundError as e:
                console.print(F"{e}, please try again by restarting the program.", style="yellow")
                time.sleep(1.5)
                error_log(e)
                
            
            except Exception as e:
                console.print(e)
                error_log(e)



            
                                
        elif choice == "7":
            error = False 
            try:
                with open(f"{file_path}", "w") as file:
                    file.write("")
                console.print(f"Scan results at {file_path} successfully cleared", style="bold green")
                time.sleep(2)
                clear_screen()
               
            except Exception as e:
                console.print(f"[red]Unexpected error:[/red] [yellow]{e}[/yellow]")
                error_log(e)

        elif choice == "8":
            error = False 
            # Flush DNS cache (Windows only)
            if os.name == "nt":
                os.system("ipconfig /flushdns")
                console.print("[green]DNS cache successfully flushed.[/green]")
         
            else:
                flush_dns()  #  calling the function for non-Windows operating systems.

            console.input("\n[bold blue]Press enter to continue: [/bold blue]")
            clear_screen()
        

        elif choice == "9":
            error = False
            # FOR LOCAL IP // HOST NAME
            host = socket.gethostname()
            host = str(host)
            local_ip = socket.gethostbyname(host)
             
            # SYSTEM INFO
            try:                                                                   # RETURNS UNKOWN IF IT RETURNS A EMPTY STRING 
                os_name = platform.system() if platform.system() else "Unknown"
                os_release = platform.release() if platform.release() else "Unknown"
                os_version = platform.version() if platform.version() else "Unknown"
                os_node = platform.node() if platform.node() else "Unknown"
                os_processor = platform.processor() if platform.processor() else "Unknown"

            except Exception as e:
                 console.print(f"[red]Error retrieving system information: {e}[/red]")
                 error_log(e)

            
            # TABLE FOR OUTPUT
            table = Table(title="Host Info", style="bold purple", header_style="red", title_style="red")
            table.add_column("Variable", style="bold blue")
            table.add_column("Value", style="bold green")
            table.add_row("Host Name", f"{host}")
            table.add_row("Local IP", f"{local_ip}")
            table.add_row("OS Name", f"{os_name}")
            table.add_row("OS Release", f"{os_release}")
            table.add_row("OS Version", f"{os_version}")
            table.add_row("OS Node", f"{os_node}")
            table.add_row("OS Processor", f"{os_processor}")

            print("\n")  # SPACE FOR TABLE
            console.print(table)
    
            console.input("\n[bold blue]Press enter to continue: [/bold blue]")
            clear_screen()
            
        
        elif choice == "10":

            sett = data(3, "N/A")
            
            scan_show = sett.get("scan_show", "on")
            scans = sett.get("scans", None)
            
            print("\n")
            console.print("SCAN INFO\n", style="bold green")
            console.print(f"[bold green]You currently have scan_show set to: {scan_show}.[/bold green]\n[bold blue]You have completed a total of:[/bold blue] [bold green]{scans} scan(s).[/bold green] ")
            print("")
            
            while True:
                try:
                    choice = console.input("[bold blue]Do you want to change scan_show to:[bold blue] [bold green](on/[/bold green][bold red]off):[/bold red] ").lower().strip()

                    if choice == "on":
                        sett["scan_show"] = "on"
                        with open(f"{file_path_setting}", "w") as file:
                            json.dump(sett, file, indent=9)
                        console.print(f"\nScan_show now set to: {choice}", style="bold green")
                        time.sleep(1)
                        clear_screen()
                        break
                    
                    elif choice == "off":
                        sett["scan_show"] ="off"
                        with open(f"{file_path_setting}", "w") as file:
                            json.dump(sett, file, indent=9)
                        console.print(f"\nScan_show now set to: {choice}", style="bold red")
                        time.sleep(1)
                        clear_screen()
                        break

                    else:
                        console.print("Please choose a valid option", style="yellow")
            
                except Exception as e:
                    console.print(e, style="bold red")
                    error_log(e)
            

        elif choice == "11":

            # DEFINE TABLE VARIABLES
            #console.print("ERROR LOGGING CURRENTLY UNDER CONSTRUCTION!",style="bold red")
            clear_screen()
            ee = pyfiglet.figlet_format("Error Logging")
            ee_panel = Panel(ee, style="bold red", border_style="bold red", width=terminal_width)
            console.print(ee_panel) # PRINT PANEL
            print("\n\n")

            try:
                with open(f"{file_path_error_log}", "r") as file:
                    content = file.read()
                    console.print(content)
                    print("\n\n")
                    choice = console.input("[bold red]clear log == 101 or enter to leave: [/bold red]")

                    if choice == "101":
                        with open(f"{file_path_error_log}", "w") as file:
                            file.write("")
                        console.print("Error LOG Successfully Cleared!", style="bold green")
            
            except FileNotFoundError as e:
                with open(f"{file_path_error_log}", "w") as file:
                    file.write("")
                    console.print("Error log succesfully created", style="bold green")
                error_log(e)

            except FileExistsError as e:
                error_log(e)

            except Exception as e:
                error_log(e)
            
            time.sleep(.3)
            clear_screen()
        
        
        #elif choice == "12":
           # clean_text(2,"N/A")
            
 



        elif choice == "12":            
            error = False 
            # Exit to main menu
            console.print("[yellow]Exiting to Main Menu...[/yellow]")
            time.sleep(0.5)
            break 

        else:
            error = True
            clear_screen()
            # Invalid choice handling
            #console.print("[red]Error:[/red] [yellow]Invalid choice. Please select an option between 1 and 4.[/yellow]")


# FUNCTION SEPECIFICALLY FOR LINUX SYSTEMS
def flush_dns():
   
    
    if os.name == "posix":  # For Linux or MacOS

        try:
            # Check if system uses systemd
            if subprocess.call(["systemctl", "is-active", "--quiet", "systemd-resolved"]) == 0:
                subprocess.check_call(["sudo", "systemd-resolve", "--flush-caches"])
                console.print("[green]DNS cache successfully flushed using systemd.[/green]")
                time.sleep(2)
            
            # Check if system uses dnsmasq
            elif subprocess.call(["systemctl", "is-active", "--quiet", "dnsmasq"]) == 0:
                subprocess.check_call(["sudo", "systemctl", "restart", "dnsmasq"])
                console.print("[green]DNS cache successfully flushed using dnsmasq.[/green]")
                time.sleep(2)
            
            # Check if system uses nscd
            elif subprocess.call(["systemctl", "is-active", "--quiet", "nscd"]) == 0:
                subprocess.check_call(["sudo", "/etc/init.d/nscd", "restart"])
                console.print("[green]DNS cache successfully flushed using nscd.[/green]")
                time.sleep(2)
            
            else:
                console.print("[red]Unable to detect DNS cache service.[/red]")
        
        except subprocess.CalledProcessError as e:
            # Handle errors during the command execution (e.g., sudo issues, missing services)
            console.print(f"[red]Error occurred while flushing DNS cache: {e}[/red]")
            error_log(e)
        except PermissionError:
            # Handle cases where user doesn't have sudo privileges
            console.print("[red]Error: Insufficient privileges. Please run the script as a user with sudo privileges.[/red]")
            error_log(e)
        except Exception as e:
            # Generic exception handler for unexpected errors
            console.print(f"[red]An unexpected error occurred: {e}[/red]")
            error_log(e)

    else:
        console.print("[red]This operating system is not supported for DNS flush.[/red]")


# STRICTLY FOR TROLLING   // OR A LOADING SCREEN // LOL
def troll():      
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Loading...", total = 100)
            for _ in range(1):
                time.sleep(.1)
                progress.update(task, advance=1)
        #panel2 = Panel
        #console.print(panel2("LOADING....", style="Yellow on black", border_style="yellow"))
        #time.sleep(.8)


# COUNTS THE AMOUNT OF SCANS THE USER PERFORMED
def scan_tracker():
        
    try:
        with open(f"{file_path_setting}", "r") as file:
            content = json.load(file)
            scans = content.get("scans", 0)
            scans += 1
            with open(f"{file_path_setting}", "w") as file:
                content["scans"] = scans
                json.dump(content, file, indent=9)
               # console.print(f"[bold red]Completed:[/bold red][bold green] {scans} Scan(s)![bold green]")

    except FileNotFoundError as e:
        error_log(e)
        pass

    except json.JSONDecodeError as e:
        error_log(e)
        pass

    except Exception as e:
        error_log(e)
        #console.print(e)
        pass


# TAKES THE ERROR AND LOGS IT
def error_log(e):
    
    #sett = data(3,"N/A")
    
    timestamp = datetime.now().strftime("%m-%d-%Y - %I:%M %p")
      
    error = (f"TimeStamp {timestamp} //[red] Error: {e}[/red]\n")
    
    try:
        with open(f"{file_path_error_log}", "a") as file:
            file.write(error)
           # console.print("Error Successfully Logged", style="bold red")

            
    except FileNotFoundError:
        with open(f"{file_path_error_log}", "w") as file:
            file.write(error)
        console.print("Error File Pathway Successfully created & Logged", style="bold red")
        
    except Exception as unexpected_error:
        console.print(f"Failed to log error: {unexpected_error}", style="bold red")
    

# THIS IS STRICITYL FOR TROLLING AND FUN PURPOSES / NOBODY SHOULD BE GETTING THERE FEELINGS HURT
def troll_2(amount_of_errors):      

    # THIS WILL PRINT IF THE USER HAS OVER 3 OR MORE INVALID INPUTS / JUST A LITTLE TROLL
    if amount_of_errors > 2:

        troll_text = pyfiglet.figlet_format(f"{amount_of_errors} FAILED ATTEMPTS.\nLETS DO BETTER!")
        panel_failed = Panel(troll_text,style="red", border_style="bold red" )
        #console.print(f"[red]{troll_text}[/red]")
        console.print(panel_failed)
        time.sleep(2.3)
        clear_screen()
    

# MAIN MENU
def main(): 
    while True:
        welcome()            # WELCOME SCREEN // NSM BARI 
        connection_status()   # CHECKS AFTER EACH SELECTION TO MAKE SURE USER IS CONNECTED TO INTERNET
        User_choose()        # USER CHOOSES WHAT THEY WANT TO DO 
        troll()             # LOADING SCREEN
        clear_screen()     # CLEARS EVERTHING UP BEFORE TRANSITION


# USER INPUT CHOOSES BETWEEN 7 OPTIONS         
def User_choose():

    show = False
    global open_ports, closed_fit, results_open_ports, results_subs_ports, shodan_results

    amount_of_errors = 0     # COUNTS THE AMOUNT OF INVALID INPUTS
    error = False          # SETS ERROR TO FALSE AS A DEFAULT IF ERROR = TRUE THEN CONSOLE OUTPUTS ERROR AND TELLS USER TO CHOOSE VALID CHOICE 1-6
    
    # PANEL FOR SELECTION 1 AND 2    // CURRENTLY NOT IN USE WILL POTENTIALLY COME BACK TO THIS ONE DAY
    figlet_for_scan = pyfiglet.figlet_format("Welcom to\nNet Vuln")
    panel_for_scan = Panel(figlet_for_scan, style="bold purple on black", border_style="bold purple")
    menu = Panel("What type of Scan would u like to do\n\n1. Common scan\n2. Full scan\n\n3. Scan results\n\n4. Setting\n5. About\n6. Help\n\n7. Exit",title="NSM MENU" ,style="green", border_style="bold green", width=min(130, terminal_width - 2), padding=(1, 2))

    console.print(menu)
    while True:

        try:
            #if error:
             # welcome()
            #print("")
            
            if error:
                console.print(f"\n\n[red]Error:[/red] {choice} is a invalid choice![yellow] Please Try Again With Choices:[/yellow][bold green ] (1-7)[/bold green]")
                if os.name == "nt":
                    os.system(f"title Failed Attempt #{amount_of_errors}, Take Your time and choose carefully -_-")

            if error == False:  # MAKES A BIT OF ROOM SO THAT WAY WE DONT GOT TO STORE THE \n BY DEFAULT IN THE CHOICE LINE.
                print("\n\n")
          
            error = False  # SWITCHES ERROR BACK TO FALSE SO NO BUGS HAPPENS 

            choice = console.input(f"[bold red]Type Your Choice Here: [/bold red]")
            choice = int(choice)
                                        
            choices = [0, 1, 2, 3, 4, 5, 6, 7, 8]  # NOT NEEDED // BUT I WANTED TO BETTER UNDERSTAND LISTS // LOL
            
            if choice == choices[1]:                # COMMON SCAN
                clear_screen()
                troll_2(amount_of_errors)
                welcome()
                domain_resolver()
                threader(1,port_scan)
                geo_lookup()
                threader2(1,sub_resolver)
                version_lookup()
                
                
                #BANNER GRABBING
                #CVE
                
                # VARIABLES FOR CURRENT DATE AND TIME // PRINTS THEM 
                timestamp = datetime.now().strftime("%m-%d-%Y - %I:%M %p")
                time_took = time.time() - start_time                                                              # COUNTS HOW LONG SCAN TOOK
                console.print(f"\n[bold blue]Port Scan Completed in: {time_took:.2f} Seconds[/bold blue]")
                scan_tracker()                                                                              # KEEPS TRACK OF THE AMOUNT OF SCANS PERFORMED // TO THEN DISPLAY ALONG SIDE THE WELCOME MSG
                
                # VARIABLES FOR NOTIFICATION AND SAVE DATA RESULTS
                msg = f"----- Scan Results -----\nOpen Ports: {open_ports}\nClosed/Filtered Ports: {closed_fit}"
                letter = (f"\n\n----------------------------------------------------------\n[dim grey]TimeStamp:[/dim grey] {timestamp}\n\n[bold green]Open Ports:[/bold green] {results_open_ports}\n\n[yellow]Geographical Info:[/yellow] {geo_info}\n\n[yellow]Resolved Sub-Domains:[/yellow] {results_subs_ports}\n\n[red]Shodan Results:[/red] {shodan_results}\n\n[bold blue]Domain name:[/bold blue] {domain_name}\n[bold blue]IP Address:[/bold blue] {ip_address}\n[bold green]Amount of Open Ports:[/bold green] {open_ports}\n[red]Amount of Closed Ports:[/red] {closed_fit}\n----------------------------------------------------------")
                
                # FUNCTION THAT SAVES SCAN RESULTS IN PURE CLEAR TEXT // CAN USE THE SAME FUNCTION TO PRINT SCAN RESULTS TO DESKTOP
               # clear_text = (f"\n\n----------------------------------------------------------\nTimeStamp:{timestamp}\n\nOpen Ports:{results_open_ports}\n\nGeographical Info: {geo_info}\n\nResolved Sub-Domains:{results_subs_ports}\n\nShodan Results:{shodan_results}\n\nDomain name: {domain_name}\nIP Address: {ip_address}\nAmount of Open Ports: {open_ports}\nAmount of Closed Ports: {closed_fit}\n----------------------------------------------------------")
                #clean_text(1, clear_text)

                # OUTPUT TO NOTIFCIATION AND DATA HANDLING
                data(1,letter)
                noty(2,msg)
                

                # END OF VULN SCAN
                console.input("\n\n[bold red]Press Enter To Exit: [/bold red]")
                open_ports = 0  # REVERTS DEFAULT BACK TO 0
                closed_fit = 0  # PUTS IT BACK TO DEFAULT FOR NEXT SCAN
                results_subs_ports = []  
                results_open_ports = []  # RESET TO DEFAULT VALUE FOR NEXT SCAN
                break


            elif choice ==choices[2]:         # FULL SCAN
                clear_screen()
                troll_2(amount_of_errors)
                welcome()
                domain_resolver()
                threader(2,port_scan)
                geo_lookup()
                threader2(2,sub_resolver)
                version_lookup()
                #BANNER GRABBING
                #CVE
                
                # VARIABLES FOR CURRENT DATE AND TIME // PRINTS THEM     
                timestamp = datetime.now().strftime("%m-%d-%Y - %I:%M %p")
                time_took = time.time() - start_time                                                              # COUNTS HOW LONG SCAN TOOK
                console.print(f"\n[bold blue]Port Scan Completed in: {time_took:.2f} Seconds[/bold blue]")
                scan_tracker()                                                                              # KEEPS TRACK OF THE AMOUNT OF SCANS PERFORMED // TO THEN DISPLAY ALONG SIDE THE WELCOME MSG
                
                
                # VARIABLES FOR NOTIFICATION AND SAVE DATA RESULTS
                msg = f"----- Scan Results -----\nOpen Ports: {open_ports}\nClosed/Filtered Ports: {closed_fit}"
                letter = (f"\n\n----------------------------------------------------------\n[dim grey]TimeStamp:[/dim grey] {timestamp}\n\n[bold green]Open Ports:[/bold green] {results_open_ports}\n\n[yellow]Geographical Info:[/yellow] {geo_info}\n\n[yellow]Resolved Sub-Domains:[/yellow] {results_subs_ports}\n\n[red]Shodan Results:[/red] {shodan_results}\n\n[bold blue]Domain name:[/bold blue] {domain_name}\n[bold blue]IP Address:[/bold blue] {ip_address}\n[bold green]Amount of Open Ports:[/bold green] {open_ports}\n[red]Amount of Closed Ports:[/red] {closed_fit}\n----------------------------------------------------------")
                
                # OUTPUT TO NOTIFCIATION AND DATA HANDLING
                data(1,letter)
                noty(2,msg)

                # END OF VULN SCAN
                console.input("\n\n[bold red]Press Enter To Exit: [/bold red]")
                open_ports = 0  # REVERTS DEFAULT BACK TO 0
                closed_fit = 0  # PUTS IT BACK TO DEFAULT FOR NEXT SCAN
                results_subs_ports = []  
                results_open_ports = []  # RESET TO DEFAULT VALUE FOR NEXT SCAN
                break



            elif choice == choices[3]:    # SCAN RESULTS
                clear_screen()
                troll_2(amount_of_errors)
                scan_welcome = pyfiglet.figlet_format("Scan Results        ")
                scan_panel = Panel(scan_welcome, style="bold blue on black", border_style="bold blue", expand=False)
                console.print(scan_panel)
               # welcome()
                data(2,letter="N/A")
                console.input("\n\n[yellow]Press[/yellow] [green]Enter[/green][yellow] to[/yellow][red] EXIT:[/red] ")

                break    
            

            elif choice == choices[4]:       # SETTINGS // USER CAN CHOOSE HOW THEY WANT THE PROGRAM TO INTERACT WITH PC
                troll() 
                clear_screen()                       
                setting()
                break
               
            elif choice == choices[5]:     # ABOUT THE SCRIPT
                troll()
                about_me()
                break

            elif choice == choices[6]:       # HELP / INSTRUCTIONS
                troll()
                show_help_menu()

                break
             
          

            elif choice == choices[7]:      # EXIT
                troll()
                clear_screen()
                console.print("[bold purple]I Hope you have enjoyed my scipt if so please leave some feedback on my YouTube channel [/bold purple][bold green]@ NSM_Barii[/bold green]")
                time.sleep(2.8)
                #s.close()
                exit()
 
            elif choice == 101:
                clear_screen()

            else:
                error = True
                amount_of_errors += 1
                #console.print("[red]Error:[/red] [yellow]Input A Valid Choice[/yellow][bold green ] (1-6)[/bold green]")
                continue

           
                                

        except Exception as e:
            #print(e)        # USE THIS FOR DEBUGGING
            error = True
           # console.input(f"[red]Press enter after u red the error message: [/red]")
            amount_of_errors += 1
            #console.print("[red]Error:[/red] [yellow]Input A Valid Choice[/yellow][bold green ] (1-6)[/bold green]")
            #clear_screen()
            #error_log(e)
            continue






if __name__ == "__main__":
  main()



# ---------------- VERSION CONTROL ----------------
# CURRENTLY ON VERSION  1.8
# THREADING == NSM PORT SCANNER V.1.3
# FULL NOTIFICATION SUPPORT == NSM PORT SCANNER V.1.4       
# SUB DOMAIN LOOKUP == NSM PORT SCANNER V.1.5
# CVE / BANNER GRABBING  == NSM PORT SCANNER V.1.6
# FULL FILE HANDLING SUPPORT == NSM PORT SCANNER // FULLY FUNCTIONAL MAIN MENU (OPTIONS) == V.1.7
# FULLY SETUP THE SETTING OPTION == NSM PORT SCANNER V.1.8
# ERROR LOGGING == 1.V.7 // MIGHT DO IT IDK  // EXTENSION OF V.1.7 ORIGINAL
# KEY VERIFICATION // CONNECTION TO BACKEND == V.1.9