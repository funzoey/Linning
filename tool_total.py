# cmh方法，按照类分，流十折
from pathlib import Path
import os
import click
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scapy.compat import raw
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP,TCP
from scapy.layers.l2 import Ether
from scapy.packet import Padding
from scipy import sparse
from tqdm import tqdm, trange
import dpkt
from packet_utils import should_omit_packet,read_pcap, PREFIX_TO_TRAFFIC_ID_VPN, ID_TO_TRAFFIC_VPN
import random
import pickle


#读取pcap的数据包的文件夹，会扫描文件夹下所有的pcap文件并进行处理
path = Path("../../vpn_test/")
max_byte_len = 50
traffics_total = ['NonVPN', 'VPN', 'TOR']
traffics_vpn = ['VPN: Chat', 'VPN: File Transfer', 'VPN: Streaming', 'VPN: Voip']
traffics_tor = ['TOR: Chat', 'TOR: File Transfer', 'TOR: Streaming', 'TOR: Voip', 'TOR: Browsing']
traffics_nonvpn = ['Chat', 'File Transfer', 'Streaming', 'Voip', 'Browsing']

def load_epoch_data(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, y, label = [], [], []

	for t in traffics_total:
		pkts = flow_dict[t]
		for byte, pos in pkts:
			x.append(byte)
			y.append(pos)
			label.append(traffics_total.index(t))

	return np.array(x), np.array(y), np.array(label)[:, np.newaxis]


def load_epoch_data_flow(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, label = [], [] #没有包长度信息


	for t in traffics_total:
		flows = flow_dict[t]
		for i in range(len(flows)):
			x.append(flows[i]) #没有包长度信息
			label.append(traffics_total.index(t))

	return np.array(x), np.array(label)[:, np.newaxis] #没有包长度信息
	

def load_epoch_data_flow_len(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, y, label = [], [], []

	for t in traffics_total:
		flows = flow_dict[t]
		for flow, length in flows:
			print('flow shape: ', flow.shape)
			print('length shape: ', length.shape)
			x.append(flow)
			y.append(length)
			label.append(traffics_total.index(t))
	
	return np.array(x), np.array(y), np.array(label)[:, np.newaxis] 



def total_pkt(i):
    nonvpn_pkt_count = 0
    vpn_pkt_count = 0
    tor_pkt_count = 0
    flow_dict = {'train':{}, 'test':{}}
    for name in traffics_total:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
    with open('./dataset/data_nonvpn/session/lessdetail/pkt/len/session2pkts_len_50_500/nonvpn_pkt_50_500_%d.pkl'%i, 'rb') as f:
        nonvpn_flow_dict = pickle.load(f)
    with open('./dataset/data_vpn/session/lessdetail/session2pkts_len_50_1000/vpn_pkt_50_1000_%d.pkl'%i, 'rb') as f1:
        vpn_flow_dict = pickle.load(f1)
    with open('./dataset/data_tor/session/lessdetail/pkt/len/session2pkts_len_50_5000/tor_pkt_50_5000_%d.pkl'%i, 'rb') as f2:
        tor_flow_dict = pickle.load(f2)
    for name0 in traffics_nonvpn:
        flow_dict['train']['NonVPN'] += nonvpn_flow_dict['train'][name0]
        nonvpn_pkt_count += len(nonvpn_flow_dict['train'][name0])
        flow_dict['test']['NonVPN'] += nonvpn_flow_dict['test'][name0]
        nonvpn_pkt_count += len(nonvpn_flow_dict['test'][name0])

    for name1 in traffics_vpn:
        flow_dict['train']['VPN'] += vpn_flow_dict['train'][name1]
        vpn_pkt_count += len(vpn_flow_dict['train'][name1])
        flow_dict['test']['VPN'] += vpn_flow_dict['test'][name1]
        vpn_pkt_count += len(vpn_flow_dict['test'][name1])

    for name2 in traffics_tor:
        flow_dict['train']['TOR'] += tor_flow_dict['train'][name2]
        tor_pkt_count += len(tor_flow_dict['train'][name2])
        flow_dict['test']['TOR'] += tor_flow_dict['test'][name2]
        tor_pkt_count += len(tor_flow_dict['test'][name2])

    print('nonvpn_pkt_count:', nonvpn_pkt_count, 'vpn_pkt_count:', vpn_pkt_count, 'tor_pkt_count:', tor_pkt_count)
    print('total_pkt_count', len(flow_dict['test']['TOR']) + len(flow_dict['train']['TOR']) + len(flow_dict['test']['VPN']) + len(flow_dict['train']['VPN']) + len(flow_dict['test']['NonVPN']) + len(flow_dict['train']['NonVPN']))

    with open('./dataset/data_total/session/pkts/len/session2pkts_len_50/total_pkt_50_%d.pkl'%i,'wb') as f3:
        pickle.dump(flow_dict, f3)


def total_flow(i):
    nonvpn_flow_count = 0
    vpn_flow_count = 0
    tor_flow_count = 0
    flow_dict = {'train':{}, 'test':{}}
    for name in traffics_total:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
       
    with open('./dataset/data_nonvpn/session/lessdetail/flow/len/3/session2flows_len_3_50_500/nonvpn_flow_3_50_500_%d.pkl'%i, 'rb') as f:
        nonvpn_flow_dict = pickle.load(f)
    with open('./dataset/data_vpn/session/lessdetail/session2flows_len_3_50_1000/vpn_flow_3_50_1000_%d.pkl'%i, 'rb') as f1:
        vpn_flow_dict = pickle.load(f1)
    with open('./dataset/data_tor/session/lessdetail/flow/len/session2flows_len_3_50_5000/tor_flow_3_50_5000_%d.pkl'%i, 'rb') as f2:
        tor_flow_dict = pickle.load(f2)
    for name0 in traffics_nonvpn:
        flow_dict['train']['NonVPN'] += nonvpn_flow_dict['train'][name0]
        nonvpn_flow_count += len(nonvpn_flow_dict['train'][name0])
        flow_dict['test']['NonVPN'] += nonvpn_flow_dict['test'][name0]
        nonvpn_flow_count += len(nonvpn_flow_dict['test'][name0])

    for name1 in traffics_vpn:
        flow_dict['train']['VPN'] += vpn_flow_dict['train'][name1]
        vpn_flow_count += len(vpn_flow_dict['train'][name1])
        flow_dict['test']['VPN'] += vpn_flow_dict['test'][name1]
        vpn_flow_count += len(vpn_flow_dict['test'][name1])

    for name2 in traffics_tor:
        flow_dict['train']['TOR'] += tor_flow_dict['train'][name2]
        tor_flow_count += len(tor_flow_dict['train'][name2])
        flow_dict['test']['TOR'] += tor_flow_dict['test'][name2]
        tor_flow_count += len(tor_flow_dict['test'][name2])

    print('nonvpn_flow_count:', nonvpn_flow_count, 'vpn_flow_count:', vpn_flow_count, 'tor_flow_count:', tor_flow_count)
    print('total_flow_count', len(flow_dict['test']['TOR']) + len(flow_dict['train']['TOR']) + len(flow_dict['test']['VPN']) + len(flow_dict['train']['VPN']) + len(flow_dict['test']['NonVPN']) + len(flow_dict['train']['NonVPN']))

    with open('./dataset/data_total/session/flows/len/session2flows_len_3_50/total_flow_3_50_%d.pkl'%i,'wb') as f3:
        pickle.dump(flow_dict, f3)
    

if __name__ == '__main__':
    for i in trange(1,6, mininterval=2, desc='  - (Building fold dataset)   ', leave=False):
        # total_flow(i)
        total_pkt(i)
