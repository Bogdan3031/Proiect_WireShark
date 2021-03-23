from tkinter import *
from scapy.all import *
import json
import os
import matplotlib.pyplot as plt


class Captura():
    _captura = None

    @staticmethod
    def getCaptura(self):
        if Captura._captura == None:
            Captura(self)
        return Captura._captura

    def __init__(self, master):
        frame = Frame(master)
        frame.grid()
        self.nr_TCP = 0
        self.nr_UDP = 0

        self.buton_pornire = Button(frame, command=self.sniffing, text='Porneste captura', height=3, width=20,
                                    bg='#90EE90')
        self.buton_pornire.grid(row=0, column=2, padx=20, pady=10)

        self.buton_save = Button(frame, command=self.save_as_json, text='Save as JSON', height=3, width=20,
                                 bg='#ffcccb')
        self.buton_save.grid(row=2, column=2, padx=20, pady=10)

        self.buton_statistici = Button(frame, command=self.show_statistics, text='Show Statistics', height=3, width=20,
                                       bg='#add8e6')
        self.buton_statistici.grid(row=3, column=2, padx=20, pady=10)

        self.save_label = Label(frame, text='Introduceti locatia pentru salvare: ')
        self.save_label.grid(row=2, column=0)
        self.save_entry = Entry(frame, width=30)
        self.save_entry.grid(row=2, column=1)

        self.pachete_label = Label(frame, text='Introduceti numarul de pachete: ')
        self.pachete_label.grid(row=0, column=0)
        self.entry = Entry(frame)
        self.entry.grid(row=0, column=1)

        if Captura._captura != None:
            raise Exception('This class is a singleton!')
        else:
            Captura._captura = self

    def sniffing(self):
        global pachete
        self.nr_UDP = 0
        self.nr_TCP = 0
        nr_pachete = int(self.entry.get())
        pachete = sniff(count=nr_pachete, filter='tcp or udp')

        for pachet in pachete:
            if 'TCP' in pachet:
                self.nr_TCP += 1
            elif 'UDP' in pachet:
                self.nr_UDP += 1

        label1 = Label(root,
                       text='Pachetele capturate sunt %s de tip TCP si %s de tip UDP ' % (self.nr_TCP, self.nr_UDP))
        label1.grid(row=3, column=0)

        return pachete

    def save_as_json(self):

        save_path = self.save_entry.get()
        file_name = 'JSON_capturi.txt'
        complete_name = os.path.join(save_path, file_name)

        pachete_json = []
        for i in range(0, len(pachete)):
            if pachete[i].haslayer('UDP') and not pachete[i].haslayer('TCP'):
                pachete_json.append(Pachet(pachete[i]['Ether'].dst,
                                           pachete[i]['Ether'].src,
                                           pachete[i]['IP'].src,
                                           pachete[i]['IP'].dst,
                                           pachete[i]['IP'].version,
                                           pachete[i]['IP'].proto,
                                           '',
                                           '',
                                           pachete[i]['UDP'].sport,
                                           pachete[i]['UDP'].dport,
                                            ))
            elif pachete[i].haslayer('TCP') and not pachete[i].haslayer('UDP'):
                pachete_json.append(Pachet(pachete[i]['Ether'].dst,
                                           pachete[i]['Ether'].src,
                                           pachete[i]['IP'].src,
                                           pachete[i]['IP'].dst,
                                           pachete[i]['IP'].version,
                                           pachete[i]['IP'].proto,
                                           pachete[i]['TCP'].sport,
                                           pachete[i]['TCP'].dport,
                                           '',
                                           ''))

        for j in range(0, len(pachete_json)):
            print(pachete_json[j].__str__())

        final_json = []
        with open(complete_name, 'w', encoding='utf-8') as f:
            for i in range(0, len(pachete_json)):
                final_json.append(json.dump(pachete_json[i].__str__().split("\n"), f, ensure_ascii=False, indent=4))

    def show_statistics(self):
        slices = [self.nr_TCP, self.nr_UDP]
        packages = ['TCP', 'UDP']
        cols = ['gold', 'yellowgreen']
        plt.pie(slices, labels=packages, colors=cols, startangle=90, autopct='%.2f%%', shadow=True)
        plt.title('Package Statistics')
        plt.axis('equal')
        plt.show()


class Pachet(Captura):
    def __init__(self, Ethernet_dst, Ethernet_src, IP_src, IP_dst, IP_version, IP_proto, TCP_sport, TCP_dport,
                 UDP_sport, UDP_dport):
        self.Ethernet_dst = Ethernet_dst
        self.Ethernet_src = Ethernet_src
        self.IP_src = IP_src
        self.IP_dst = IP_dst
        self.IP_version = IP_version
        self.IP_proto = IP_proto
        self.TCP_sport = TCP_sport
        self.TCP_dport = TCP_dport
        self.UDP_sport = UDP_sport
        self.UDP_dport = UDP_dport

    def __str__(self):
        return "{'Ethernet':{src:'" + str(self.Ethernet_src) + "',\n\t\t\t dst:'" + str(self.Ethernet_dst) + "',\n\t\t" \
            "\t} \n 'IP':{src:'" + str(
            self.IP_src) + "',\n\t   dst:'" + str(self.IP_dst) + "',\n\t   version:" \
                             "'" + str(self.IP_version) + "',\n\t   proto:'" + str(
            self.IP_proto) + "',\n\t  }\n'TCP':{TCP_sport:" \
                             "'" + str(self.TCP_sport) + "',\n\t  TCP_dport:'" + str(
            self.TCP_dport) + "',\n\t  }\n'UDP':{UDP_sport:" \
                              "'" + str(self.UDP_sport) + "', \n\t  UDP_dport:'" + str(
            self.UDP_dport) + "',\n\t  }\n }'"


root = Tk()
root.title('Captura Pachete')
root.geometry('720x400')
c = Captura(root)

root.mainloop()
