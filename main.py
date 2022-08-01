import socket
from IPy import IP


class scanning:
    def __init__(self, target):
        self.target = target
        self.open_ports = []

    def check_ip(self, ip):
        try:
            IP(ip)
            return ip
        except ValueError:
            return socket.gethostbyname(ip)

    def scan(self, port_number):
        print("Scanning {}...".format(str(self.target)))
        converted_ip = self.check_ip(self.target)
        for port in range(port_number[0], port_number[1] + 1):
            self.scan_port(converted_ip, port)

    def scan_port(self, ipaddress, port):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ipaddress, port))
            try:
                print(
                    "[+] Port {} is open : {}".format(str(port), str(sock.recv(sock)))
                )
                self.add_to_open_ports(str(port))
            except:
                print("[+] Port {} is open.".format(str(port)))
                self.add_to_open_ports(str(port))
        except:
            print("[-] Port {} is closed.".format(str(port)))

    def add_to_open_ports(self, *args):  # optional argument
        for i in args:
            self.open_ports.append(i)
        return self.open_ports

    def print_attributes(self):
        if not self.add_to_open_ports():
            print("There is no open port.")
        else:
            print("Open ports for {}: \n {}".format(self.target, self.add_to_open_ports()))


if __name__ == "__main__":
    targets = input(
        "Enter Target/s Domain/s (without https) or IP Adress/'s to Scan (split multiple targets with comma):"
    )
    port_nums = input(
        'Enter the Interval of the Ports That You Want to Scan like "60-100" without quotes:'
    )
    converted_port_nums = [int(x) for x in port_nums.split("-")]

    if "," in targets:
        y = 0
        objectList = []
        for ips in targets.split(","):
            objectList.append(scanning(ips))
            objectList[y].scan(converted_port_nums)
            y += 1
        for i in range(len(objectList)):
            objectList[i].print_attributes()

    else:
        newObj = scanning(targets)
        newObj.scan(converted_port_nums)
        newObj.print_attributes()
