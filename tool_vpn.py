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
path = Path("../../session/")
max_byte_len = 50
traffics_vpn = ['VPN: Chat', 'VPN: File Transfer', 'VPN: Streaming', 'VPN: Voip']


def getFiles(dir, suffix): # 查找根目录，文件后缀
    res = []
    for root, directory, files in os.walk(dir):  # =>当前根,根下目录,目录下的文件
        for filename in files:
            name, suf = os.path.splitext(filename) # =>文件名,文件后缀
            if suf == suffix:
                res.append(os.path.join(root, filename)) # =>把一串字符串组合成路径
    return res #文件夹下所有文件的文件名


def mask(p):  # p指一个完整的包
	if Ether in p:
		#print(packet[Ether].dst)
		p = p[Ether].payload  # p指一个包的ip头+ip负载
	if IP in p:    
		p[IP].src = '0.0.0.0' #mask源ip
		p[IP].dst = '0.0.0.0' #mask目的ip
		p[IP].sum = 0
		p[IP].id = 0
		p[IP].offset = 0

	if TCP in p: #如果是tcp的
		p[TCP].sport = 0
		p[TCP].dport = 0
		p[TCP].seq = 0
		p[TCP].ack = 0
		p[TCP].sum = 0

	elif UDP in p: #如果是udp的
		p[UDP].sport = 0
		p[UDP].dport = 0
		p[UDP].sum = 0

	return p


def File_Accept(packets): #过滤会话
    packet_1 = packets[0]
    if TCP in packet_1 or DNS in packet_1:
        if TCP in packet_1 and len(packets) < 4:
            #print("没达到握手次数的TCP包")
            return False
        elif DNS in packet_1:
            #print("DNS包")
            return False
        else:
           return True
    else:
        #过滤LLMNR协议，该协议通过UDP传输到224.0.0.252:5355 目的ＩＰ是224.0.0.252，目的端口是5355
        if UDP in packet_1:

            if IP in packet_1:
                ip_dst = packet_1[IP].dst
                # print(ip_dst)
                port_dst = packet_1[UDP].dport
                # print(port_dst)
                if ip_dst == "224.0.0.252" and port_dst == 5355:
                    #print("LLMNR协议包")
                    return False
        return True


def flowid2trafficid(id):
    if id >= 0 and id <= 10:
        return 0
    elif id >= 11 and id <= 16:
        return 1
    elif id >= 17 and id <= 21:
        return 2
    elif id >= 22 and id <= 28:
        return 3
    else:
        return -1


def pcap2feature(path):
    flow_dict = {} #每个类型的流分开
    for name in traffics_vpn:
        flow_dict[name] = []
    file_count = 0
    # pkt_count = 0
    flow_num =[0]*4
    for file in tqdm(getFiles(path, '.pcap')):
        prefix = os.path.basename(file).split('.')[0].lower() 
        if prefix in PREFIX_TO_TRAFFIC_ID_VPN.keys():
            # 获得类型编号，然后把train_label中对应位置取1
            flow_id = PREFIX_TO_TRAFFIC_ID_VPN.get(prefix) #0~10
            traffic_id = flowid2trafficid(flow_id) #0
            # print(traffic_id)            
            traffic_label = ID_TO_TRAFFIC_VPN.get(traffic_id) #'VPN-Chat'
            # print(traffic_label)
            file_count+=1
            flow_num[traffic_id]+=1
            flow_dict[traffic_label].append(file)
            # pkt_num=0
    for name in traffics_vpn:        
        random.Random(2048).shuffle(flow_dict[name])
    print('total file count in pcap2feature: ', file_count)
    print('flow_num: ', flow_num)
    return flow_dict, flow_num


def split_data(data, flow_num, n):
    flow_dict = {'train':{}, 'test':{}}

    # train->protocol->flowid->[pkts]
    for name in traffics_vpn:
        flow_dict['train'][name] = []
        flow_dict['test'][name] = []
        flow_id = traffics_vpn.index(name)
        for count in range(flow_num[flow_id]):
            if count in range(n*int(flow_num[flow_id]*0.1), (n+1)*int(flow_num[flow_id]*0.1)): #十折  通过改n
                flow_dict['test'][name].append(data[name][count])
            else:
                flow_dict['train'][name].append(data[name][count])
        print('train',name,len(flow_dict['train'][name]))
        print('test',name,len(flow_dict['test'][name]))       

    return flow_dict


def continusPkt2Flow(pcap, start_idx = 0, count = 3):
    flow_dict = []
    tmp = []
    pkt_count = 0
    for i,packet in enumerate(pcap):
        if pkt_count >1000:
            break
        pkt_len = len(packet)
        pkt = mask(packet) #对包进行mask
        raw_byte = np.frombuffer(raw(pkt), dtype=np.uint8)
        byte = [] #byte=[] 前50个字节
        # pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
        leng = [pkt_len for j in range(max_byte_len)]
        for x in range(min(len(raw_byte),max_byte_len)):
            byte.append(int(raw_byte[x]))
            # pos.append(x)

        byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
        # pos.extend([0]*(max_byte_len-len(pos)))
        # tmp.append(((byte, pos), pkt_len))
        # tmp.append((byte, pos)) #没有包长度信息
        tmp.append((byte, leng))
        pkt_count += 1
    length = len(tmp)
    if length - count + 1 <= start_idx:
        return flow_dict
    # print('total valid pkts in flow: ', length)
    for i in range(start_idx, length - count + 1):
        # flow_dict.append(([tmp[i][0], tmp[i + 1][0], tmp[i + 2][0]], [tmp[i][1], tmp[i + 1][1], tmp[i + 2][1]]))
        flow_dict.append([tmp[i], tmp[i + 1], tmp[i + 2]]) #没有包长度信息
    # print('total flow count after expand: ', len(flow_dict))
    return flow_dict


def flowExpand(data):
    flow_dict = {'train':{}, 'test':{}}
    train_flow_cnt_before = 0
    train_flow_cnt_after = 0
    test_flow_cnt_before = 0
    test_flow_cnt_after = 0
    for name in traffics_vpn:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
        train_pkt_count = 0
       
        for i in range (len(data['train'][name])):
            file_name = data['train'][name][i]
            pcap = read_pcap(path=file_name)
            train_flow_cnt_before += 1
            flow2flows = continusPkt2Flow(pcap)
            if len(flow2flows) > 0:
                flow_dict['train'][name] = flow_dict['train'][name] + flow2flows
                train_flow_cnt_after += len(flow2flows)

        test_pkt_count = 0
        
        for i in range (len(data['test'][name])):
            file_name = data['test'][name][i]
            pcap = read_pcap(path=file_name)
            test_flow_cnt_before += 1
            flow2flows = continusPkt2Flow(pcap)
            if len(flow2flows) > 0:
                flow_dict['test'][name] = flow_dict['test'][name] + flow2flows
                test_flow_cnt_after += len(flow2flows)

    for name in traffics_vpn:
        random.Random(2048).shuffle(flow_dict['train'][name]) 
        random.Random(2048).shuffle(flow_dict['test'][name]) 
        print('train after',name,len(flow_dict['train'][name]))
        print('test after',name,len(flow_dict['test'][name]))


    print('total train flow count, before ', train_flow_cnt_before, ', after: ', train_flow_cnt_after)
    print('total test flow count, before ', test_flow_cnt_before, ', after: ', test_flow_cnt_after)
    return flow_dict


def flow2pkt(data):
    flow_dict = {'train':{}, 'test':{}}
    train_file_count = 0
    test_file_count = 0
    total_pkt_count = 0
    for name in traffics_vpn:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
        train_pkt_count = 0
        
        for i in range (len(data['train'][name])):
            file_name = data['train'][name][i]        
            packets_scapy = read_pcap(path=file_name) #packets_scapy 是[]，里面是所有包
            train_file_count += 1
            pkt_num=0
            for i,packet in enumerate(packets_scapy):
                if pkt_num >1000:
                    break
                pkt_len = len(packet)
                pkt = mask(packet) #对包进行mask
                raw_byte = np.frombuffer(raw(pkt), dtype=np.uint8)
                byte = [] #byte=[] 前50个字节
                # pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
                leng = [pkt_len for j in range(max_byte_len)]
                for x in range(min(len(raw_byte),max_byte_len)):
                    byte.append(int(raw_byte[x]))
                    # pos.append(x)

                byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
                # pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
                # flow_dict['train'][name].append((byte,pos))
                flow_dict['train'][name].append((byte, leng))
                train_pkt_count+=1
                pkt_num+=1
                total_pkt_count+=1
        print(name,' train_pkt_count: ', train_pkt_count)

        test_pkt_count = 0
        
        for i in range (len(data['test'][name])):
            file_name = data['test'][name][i]        
            packets_scapy = read_pcap(path=file_name) #packets_scapy 是[]，里面是所有包
            test_file_count += 1
            pkt_num=0
            for i,packet in enumerate(packets_scapy):
                if pkt_num >1000:
                    break
                pkt_len = len(packet)
                pkt = mask(packet) #对包进行mask
                raw_byte = np.frombuffer(raw(pkt), dtype=np.uint8)
                byte = [] #byte=[] 前50个字节
                # pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
                leng = [pkt_len for j in range(max_byte_len)]
                for x in range(min(len(raw_byte),max_byte_len)):
                    byte.append(int(raw_byte[x]))
                    # pos.append(x)

                byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
                # pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
                # flow_dict['test'][name].append((byte,pos))
                flow_dict['test'][name].append((byte,leng))
                test_pkt_count+=1
                pkt_num+=1
                total_pkt_count+=1
        print(name,' test_pkt_count: ', test_pkt_count)
    for name in traffics_vpn:
        random.Random(2048).shuffle(flow_dict['train'][name]) 
        random.Random(2048).shuffle(flow_dict['test'][name]) 
        print('train',name,len(flow_dict['train'][name]))
        print('test',name,len(flow_dict['test'][name]))


    print('total train file count: ', train_file_count)
    print('total test file count: ', test_file_count)
    print('total pkt count: ', total_pkt_count)
    return flow_dict



def load_epoch_data(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, y, label = [], [], []

	for t in traffics_vpn:
		pkts = flow_dict[t]
		for byte, pos in pkts:
			x.append(byte)
			y.append(pos)
			label.append(traffics_vpn.index(t))

	return np.array(x), np.array(y), np.array(label)[:, np.newaxis]


def load_epoch_data_flow(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, label = [], [] #没有包长度信息


	for t in traffics_vpn:
		flows = flow_dict[t]
		for i in range(len(flows)):
			x.append(flows[i]) #没有包长度信息
			label.append(traffics_vpn.index(t))

	return np.array(x), np.array(label)[:, np.newaxis] #没有包长度信息
	


def load_epoch_data_flow_len(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, y, label = [], [], []

	for t in traffics_vpn:
		flows = flow_dict[t]
		for flow, length in flows:
			print('flow shape: ', flow.shape)
			print('length shape: ', length.shape)
			x.append(flow)
			y.append(length)
			label.append(traffics_vpn.index(t))
	
	return np.array(x), np.array(y), np.array(label)[:, np.newaxis] 




if __name__ == '__main__':
   
    data, flow_num = pcap2feature(path) 
    for i in trange(10, mininterval=2, desc='  - (Building fold dataset)   ', leave=False):
        flow_dict1 = split_data(data, flow_num, i)
        flow_dict2 = flowExpand(flow_dict1)
        with open('./dataset/data_vpn/session/lessdetail/session2flows_len_3_50_1000/vpn_flow_3_50_1000_%d.pkl'%i, 'wb') as f:
        # flow_dict2 = flow2pkt(flow_dict1)
        # with open('./dataset/data_vpn/session/lessdetail/session2pkts_len_50_1000/vpn_pkt_50_1000_%d.pkl'%i, 'wb') as f:
            pickle.dump(flow_dict2, f) #划分成十折数据
        # with open('test_%d.txt'%i, 'w') as f:
        #     f.write(str(flow_dict2)) #划分成十折数据
    
