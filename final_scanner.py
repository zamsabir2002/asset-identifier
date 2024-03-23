import nmap
import json
import os


def callback_initial_scan(host, scan_result):
    if scan_result['scan'] == {}:
        print(host, "DOWN NOW")
    else:
        print(scan_result)
        with open("scan_results.txt", 'a') as file:
            file.write(f"{host}\n")


def second_scan_callback(host, scan_result):
    print(json.dumps(scan_result))
    if os.path.exists('./json_output.json'):
        try:
            with open("json_output.json", "r+") as file:
                data = json.load(file)
                data[host] = scan_result
                file.seek(0)
                json.dump(data, file, indent=4)
        except:
            with open("json_output.json", "w") as file:
                data = {host: scan_result}
                file.seek(0)
                json.dump(data, file, indent=4)
                file.close()
    else:
        with open("json_output.json", "w") as file:
            data = {host: scan_result}
            file.seek(0)
            json.dump(data, file, indent=4)
            file.close()


def run_nmap_scan(hosts, flags, callback):
    nma = nmap.PortScannerAsync()
    try:
        nma.scan(hosts=hosts, arguments=flags,
                 callback=callback)
        while nma.still_scanning():
            nma.wait(2)
            print("<< Scanning >>")
    except KeyboardInterrupt:
        print("Scan stopped by user.")
    except Exception as e:
        print("An error occurred during scanning:", e)
    finally:
        try:
            if nma:
                nma.stop()
        except Exception as e:
            print("Error occurred during cleanup:", e)


def save_results_to_json(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)


def get_up_ip():
    ip_list = []
    with open('scan_results.txt', "r") as f:
        for line in f:
            ip = line.split()[0]
            ip_list.append(ip)
    return ip_list

    # ips = ''
    # with open('scan_results.txt', "r") as f:
    #     for line in f:
    #         # ips += f'{line} '
    #         print(line, line.split()[0])
    #         ips += f'{line.split()[0]} '
    # return ips


if __name__ == "__main__":
    
    # Taking input ip address subnet
    ip_range = input("Enter Network Range(e.g. 192.168.1.0/24): ")

    # Initial Scan with -sP
    # To discover majority of the devices
    run_nmap_scan(ip_range, '-sP', callback_initial_scan)

    # Extract IP addresses of hosts that are up
    up_ips = get_up_ip()
    print(up_ips)

    # Run second scan with specified flags on currently up IP addresses
    for ip in up_ips:
        run_nmap_scan(ip, '-sS -sV --version-intensity 5 -T3 -O --osscan-guess --fuzzy --max-os-tries 8 --max-retries 4 -PE -Pn -PP --top-port 15 --min-hostgroup 64', callback=second_scan_callback)
    # run_nmap_scan(up_ips, '-sS -sV --version-intensity 5 -T3 -O --osscan-guess --fuzzy --max-os-tries 8 --max-retries 4 -PE -Pn -PP --top-port 15 --min-hostgroup 64', callback=second_scan_callback)

    # # Combine results, removing duplicate IP addresses
    # combined_results = initial_results.copy()
    # for result in second_scan_results:
    #     ip = result['ip']
    #     if ip not in up_hosts:
    #         combined_results.append(result)

    # # Save combined results to JSON file
    # save_results_to_json(combined_results, 'scan_results.json')
