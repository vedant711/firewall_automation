from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException
from datetime import datetime
import getpass
import csv


def find_ip(net_connect, ips):
    flag, conf_ip = 0, []
    for ip in ips:
        op1 = net_connect.send_command(f'show run | i {ip}')
        arr1, arr2 = op1.split('\n'), []
        for row in arr1:
            col = str(row).split()
            arr2.append(col)

        for row in arr2:
            if ip not in row: pass
            else:
                if ip not in conf_ip:
                    print(f'{ip} already configured')
                    conf_ip.append(ip)
                    break
    for i in conf_ip: ips.remove(i)
    if len(ips) != 0 or ips != []: flag = 0
    else: flag = 1
    return flag, ips


if __name__ == '__main__':
    today = datetime.now().strftime("log_%d_%m_%Y.txt")
    check_ip = input(
        "Enter malicious IP addresses(to check or add to malicious list)(comma separated): ").split(',')
    device_info = []
    with open('device_info.csv', encoding='utf-8') as file1:
        read1 = csv.reader(file1)
        for row in read1: device_info.append(row)

    username = ''
    for r in device_info:
        ip, username, device_type = r[1], r[2], r[4]
        password = getpass.getpass(
            f"Enter Password for {ip}: ")

        cisco_7200 = {
            'device_type': device_type,
            'host':   ip,
            'username': username,
            'password': password,
            'port': 22,
            'secret': '1234@Organization',
            'verbose': False,
        }

        try:
            net_connect = ConnectHandler(**cisco_7200)
            net_connect.enable()
            flag, ips = find_ip(net_connect, check_ip)
            print(f'IPs left for configuration {ips}')
            if flag == 1: print('All the IPs already in the malicious list')
            else:
                change_number = input('Enter the change number')
                cmd1 = f'''conf t
                object-group network {change_number}
                description Administrator Addresses'''
                for single_ip in ips: cmd1 += f'\nnetwork-object host {single_ip}'
                commands = [cmd1]
                cont = input('Do you want to execute the above command:(y/n) ')
                if cont.lower() == 'y':
                    for cmd in commands:
                        print(cmd)
                        output = net_connect.send_command_timing(
                            command_string=cmd)
                        print(output)
                        print(
                            '\n ----------------------------------------------------------------- \n')
                        f = open(today, 'a')
                        f.write(f'{output}\n')
                        f.close()
                    net_connect.disconnect()
                else:
                    net_connect.disconnect()
                    continue
        except NetMikoAuthenticationException:
            try:
                password = getpass.getpass(
                    'Incorrect Password! Re-enter: ')
                cisco_7200['password'] = password
                net_connect = ConnectHandler(**cisco_7200)
                net_connect.enable()
                flag, ips = find_ip(net_connect, check_ip)
                print(f'IPs left for configuration {ips}')
                if flag == 1: print('All the IPs already in the malicious list')
                else:
                    change_number = input('Enter the change number')
                    cmd1 = f'''conf t
                    object-group network {change_number}
                    description Administrator Addresses'''
                    for single_ip in ips: cmd1 += f'\nnetwork-object host {single_ip}'
                    commands = [cmd1]
                    cont = input('Do you want to execute the above command:(y/n) ')
                    if cont.lower() == 'y':
                        for cmd in commands:
                            print(cmd)
                            output = net_connect.send_command_timing(
                                command_string=cmd)
                            print(output)
                            print(
                                '\n ----------------------------------------------------------------- \n')
                            f = open(today, 'a')
                            f.write(output)
                            f.close()
                        net_connect.disconnect()
                    else:
                        net_connect.disconnect()
                        continue
            except: print('Incorrect password')
        except: print(f'Could not connect to {ip}')