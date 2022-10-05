#清华方法，按照类分，流十折
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
from packet_utils import should_omit_packet, PREFIX_TO_TRAFFIC_ID_TOR, ID_TO_TRAFFIC_TOR
import random
import pickle


#读取pcap的数据包的文件夹，会扫描文件夹下所有的pcap文件并进行处理
path = Path("../../session/")
max_byte_len = 50
traffics_tor = ['TOR: Chat', 'TOR: File Transfer', 'TOR: Streaming', 'TOR: Voip', 'TOR: Browsing']

def getFiles(dir, suffix): # 查找根目录，文件后缀
    res = []
    for root, directory, files in os.walk(dir):  # =>当前根,根下目录,目录下的文件
        for filename in files:
            name, suf = os.path.splitext(filename) # =>文件名,文件后缀
            if suf == suffix:
                res.append(os.path.join(root, filename)) # =>把一串字符串组合成路径
    return res #返回：文件夹下所有文件的文件名


def mask(p): #p：ip头+ip负载
    #mask头的一部分
	p.src = b'\x00\x00\x00\x00'
	p.dst = b'\x00\x00\x00\x00' 
	p.sum = 0
	p.id = 0
	p.offset = 0

	if isinstance(p.data, dpkt.tcp.TCP):
		p.data.sport = 0
		p.data.dport = 0
		p.data.seq = 0
		p.data.ack = 0
		p.data.sum = 0

	elif isinstance(p.data, dpkt.udp.UDP):
		p.data.sport = 0
		p.data.dport = 0
		p.data.sum = 0

	return p #返回：头被mask后的p


def File_Accept(packets): #过滤会话，没用到
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
    if id >= 0 and id <= 9:
        return 0
    elif id >= 10 and id <= 12:
        return 1
    elif id >= 13 and id <= 15:
        return 2
    elif id >= 16 and id <= 21:
        return 3
    elif id >= 22 and id <= 27:
        return 4
    else:
        return -1


def pcap2feature(path):
    flow_dict = {} #每个类型的会话分开 key是类型，value是对应类别的所有会话的文件名
    for name in traffics_tor:
        flow_dict[name] = []
    file_count = 0
    # pkt_count = 0
    flow_num =[0]*5 #每种类型的会话数量
    for file in tqdm(getFiles(path, '.pcap')):
        prefix = os.path.basename(file).split('.')[0].lower()
        if prefix in PREFIX_TO_TRAFFIC_ID_TOR.keys():
            # 获得类型编号，然后把train_label中对应位置取1
            flow_id = PREFIX_TO_TRAFFIC_ID_TOR.get(prefix)#0~16
            traffic_id = flowid2trafficid(flow_id) #0
            # print(traffic_id)
            traffic_label = ID_TO_TRAFFIC_TOR.get(traffic_id) #'Chat'
            # print(traffic_label)
            file_count += 1
            flow_num[traffic_id] += 1
            flow_dict[traffic_label].append(file)
            # pkt_num=0
    for name in traffics_tor:              
        random.Random(2048).shuffle(flow_dict[name])
    print('total file count in pcap2feature: ', file_count)
    print('flow_num: ', flow_num)
    return flow_dict, flow_num


def split_data(data, flow_num, n): #第n折划分train、test 存的是文件名
    flow_dict = {'train':{}, 'test':{}}

    # train->protocol->flowid->[pkts]
    for name in traffics_tor:
        flow_dict['train'][name] = []
        flow_dict['test'][name] = []
        flow_id = traffics_tor.index(name)
        for count in range(flow_num[flow_id]):
            if count in range(n*round(flow_num[flow_id]*0.1), (n+1)*round(flow_num[flow_id]*0.1)): #十折  通过改n
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
    # pkt_len_max = 0
    for _, buff in pcap:
        if pkt_count > 2500:
            break
        pkt_len = len(buff)
        # if pkt_len>pkt_len_max:
        #     pkt_len_max = pkt_len
        eth = dpkt.ethernet.Ethernet(buff)
        if isinstance(eth.data, dpkt.ip.IP) and (
        isinstance(eth.data.data, dpkt.udp.UDP)
        or isinstance(eth.data.data, dpkt.tcp.TCP)):
            # tcp or udp packet
            ip = eth.data
            pkt = mask(ip) #对包进行mask
            raw_byte = pkt.pack()
            byte = [] #byte=[] 前50个字节
            pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
            # leng = [pkt_len for j in range(max_byte_len)]
            for x in range(min(len(raw_byte),max_byte_len)):
                byte.append(int(raw_byte[x]))
                pos.append(x)
            # if pkt_len>1500:
            #     print('pkt_len:',pkt_len)
            byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
            pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
            # tmp.append(((byte, pos), pkt_len))
            tmp.append((byte, pos))
            # tmp.append((byte, leng)) #没有包长度信息	    
            pkt_count += 1
    # print('max_pkt_len:', pkt_len_max)
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
    for name in traffics_tor:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
        train_pkt_count = 0
   
        for i in range (len(data['train'][name])):
            file_name = data['train'][name][i]
            pcap = dpkt.pcap.Reader(open(file_name, 'rb'))
            train_flow_cnt_before += 1
            flow2flows = continusPkt2Flow(pcap)
            if len(flow2flows) > 0:
                flow_dict['train'][name] = flow_dict['train'][name] + flow2flows
                train_flow_cnt_after += len(flow2flows)

        test_pkt_count = 0
        
        for i in range (len(data['test'][name])):
            file_name = data['test'][name][i]
            pcap = dpkt.pcap.Reader(open(file_name, 'rb'))
            test_flow_cnt_before += 1
            flow2flows = continusPkt2Flow(pcap)
            if len(flow2flows) > 0:
                flow_dict['test'][name] = flow_dict['test'][name] + flow2flows
                test_flow_cnt_after += len(flow2flows)

    for name in traffics_tor:
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
    for name in traffics_tor:
        flow_dict['train'][name]=[]
        flow_dict['test'][name]=[]
        train_pkt_count = 0
        for i in range (len(data['train'][name])):
            file_name = data['train'][name][i] #某一条流
            pcap = dpkt.pcap.Reader(open(file_name, 'rb'))
            train_file_count += 1
            pkt_num = 0
            for _, buff in pcap:
                if pkt_num>=2500: #一条流不能超过2500个包
                    break
                pkt_len = len(buff)
                eth = dpkt.ethernet.Ethernet(buff)
                if isinstance(eth.data, dpkt.ip.IP) and (
                isinstance(eth.data.data, dpkt.udp.UDP)
                or isinstance(eth.data.data, dpkt.tcp.TCP)):
                    # tcp or udp packet
                    ip = eth.data
                    pkt = mask(ip) #对包进行mask
                    raw_byte = pkt.pack()
                    byte = [] #byte=[] 前50个字节
                    pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
                    # leng = [pkt_len for j in range(max_byte_len)]
                    for x in range(min(len(raw_byte),max_byte_len)):
                        byte.append(int(raw_byte[x]))
                        pos.append(x)

                    byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
                    pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
                    # flow_dict['train'][name].append((byte,leng))
                    flow_dict['train'][name].append((byte,pos))
                    train_pkt_count+=1
                    pkt_num+=1
                    total_pkt_count+=1
        print(name,' train_pkt_count: ', train_pkt_count)

        test_pkt_count = 0
        for i in range (len(data['test'][name])):
            file_name = data['test'][name][i]
            pcap = dpkt.pcap.Reader(open(file_name, 'rb'))
            test_file_count += 1
            pkt_num = 0
            for _, buff in pcap:
                if pkt_num>=2500: #一条流不能超过1000个包
                    break
                pkt_len = len(buff)
                eth = dpkt.ethernet.Ethernet(buff)
                if isinstance(eth.data, dpkt.ip.IP) and (
                isinstance(eth.data.data, dpkt.udp.UDP)
                or isinstance(eth.data.data, dpkt.tcp.TCP)):
                    # tcp or udp packet
                    ip = eth.data
                    pkt = mask(ip) #对包进行mask
                    raw_byte = pkt.pack()
                    byte = [] #byte=[] 前50个字节
                    pos = [] #pos=[0,1,2,3,4,...,50] 位置信息
                    # leng = [pkt_len for j in range(max_byte_len)]
                    for x in range(min(len(raw_byte),max_byte_len)):
                        byte.append(int(raw_byte[x]))
                        pos.append(x)

                    byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
                    pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
                    # flow_dict['test'][name].append((byte,leng))
                    flow_dict['test'][name].append((byte,pos))
                    test_pkt_count+=1
                    pkt_num+=1
                    total_pkt_count+=1
        print(name,' test_pkt_count: ', test_pkt_count)
    for name in traffics_tor:
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

	for t in traffics_tor:
		pkts = flow_dict[t]
		for byte, pos in pkts:
			x.append(byte)
			y.append(pos)
			label.append(traffics_tor.index(t))

	return np.array(x), np.array(y), np.array(label)[:, np.newaxis]


def load_epoch_data_flow(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, label = [], [] #没有包长度信息

	for t in traffics_tor:
		flows = flow_dict[t]
		# print(flows)
		for i in range(len(flows)):
			x.append(flows[i]) #没有包长度信息
			label.append(traffics_tor.index(t))

	# return np.array(x), np.array(label)[:, np.newaxis] #没有包长度信息
	return np.array(x), np.array(label)[:, np.newaxis] 


def load_epoch_data_flow_len(flow_dict, train='train'):
	flow_dict = flow_dict[train]
	x, y, label = [], [], []

	for t in traffics_tor:
		flows = flow_dict[t]
		# print(flows)
		for i in range(len(flows)):
			x.append(flows[i][0])
			y.append(flows[i][1])
			label.append(traffics_tor.index(t))

	# return np.array(x), np.array(label)[:, np.newaxis] #没有包长度信息
	return np.array(x), np.array(y), np.array(label)[:, np.newaxis] 



    

if __name__ == '__main__':
    
    data, flow_num = pcap2feature(path)
    
    for i in trange(1,6, mininterval=2, desc='  - (Building fold dataset)   ', leave=False):
        flow_dict1 = split_data(data, flow_num, i)
        # flow_dict2 = flowExpand(flow_dict1)
        # with open('./dataset/data_tor/session/lessdetail/session2flows_len_3_50_2500/tor_flow_3_50_2500_%d.pkl'%i,'wb') as f1:
        flow_dict2 = flow2pkt(flow_dict1)
        with open('./dataset/data_tor/session/lessdetail/session2pkts_50_2500/tor_pkt_50_2500_%d.pkl'%i,'wb') as f1:
            pickle.dump(flow_dict2, f1)
        # with open('test%d.txt'%i,'w') as f1:
        #     f1.write(str(flow_dict2))
    