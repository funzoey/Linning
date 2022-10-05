# -*- coding: utf-8 -*-
# @Author: xiegr
# @Date:   2020-09-06 18:07:51
# @Last Modified by:   xiegr
# @Last Modified time: 2021-06-03 17:16:25
import torch
import torch.nn.functional as F
import torch.utils.data
import torch.optim as optim
import torch.nn as nn
import argparse
import time
from tqdm import tqdm, trange
from SAM import SAM
import dpkt
# from tool import protocols, load_epoch_data, max_byte_len
from tool_nonvpn_flowpkt_bytes_gai import traffics_nonvpn,load_epoch_data_flow,max_byte_len, mask

from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import pickle
import numpy as np
import os
from Transformer import Transformer_flow

os.environ["CUDA_VISIBLE_DEVICES"] = "1"

parser = argparse.ArgumentParser(description='Encrypted Traffic Classification')
# parser.add_argument("--mode", type=str, default='transformer_flow')
parser.add_argument('--num_classes',type=int, default=6, help='Number of Classes')
# parser.add_argument('--num_epochs', type=int, default=25, help='Number of epochs to train.')
parser.add_argument('--dropout', type=int, default=0.1, help='dropout.')
parser.add_argument('--sentence_max_len', type=int, default=50, help='The max length of payload.')
parser.add_argument('--num_pkt', type=int, default=3, help='Numbers of packet.')
parser.add_argument('--input_len', type=int, default=500, help='The length of payload.')
# parser.add_argument('--batch_size', type=int, default=128, help='Batch Size.')
# parser.add_argument('--learning_rate', type=int, default=0.001, help='Learning Rate.')
parser.add_argument('--dim_model', type=int, default=256, help='Embedding Size.')
parser.add_argument('--d_ff', type=int, default=1024, help='Hidden Size.')
parser.add_argument('--num_head', type=int, default=2, help='Numbers of heads.')
parser.add_argument('--num_encoder', type=int, default=2, help='Numbers of Encoders.')
# parser.add_argument("--log_path", type=str, default='./log/')
# parser.add_argument("--save_path", type=str, default='./saved_dict')
# parser.add_argument("--require_improvement", type=int, default=20000)
args = parser.parse_args()


def allPkt2Flow(pcap):
    tmp = []
    # pkt_len_max = 0
    for _, buff in pcap:
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
            for x in range(min(len(raw_byte),max_byte_len)):
                byte.append(int(raw_byte[x]))
                pos.append(x)
            # if pkt_len>1500:
            #     print('pkt_len:',pkt_len)
            byte.extend([0]*(max_byte_len-len(byte)))#如果不够50就补0
            pos.extend([0]*(max_byte_len-len(pos))) # 如果不够50就补0
            tmp.append((byte, pos))
            # tmp.append((byte, pos)) #没有包长度信息
    # print('max_pkt_len:', pkt_len_max)
    return tmp

def flowAllPkt(data, model):
	flow_dict = {}
	total_true_num = 0
	total_false_num = 0
	total_num = 0 
	for name in traffics_nonvpn:
		flow_dict[name]=[]
		true_num = 0
		false_num = 0
		class_num = 0
		test_pkt_count = 0
		for k in data['test'][name].keys():
			for i in range (len(data['test'][name][k])):
				file_name = data['test'][name][k][i]
				pcap = dpkt.pcap.Reader(open(file_name, 'rb'))
				flow2flows = allPkt2Flow(pcap)
				if len(flow2flows) > 2:
					# flow_dict[name].append(flow2flows)
					#TODO
					pred = test(model, flow2flows, traffics_nonvpn.index(name))
					if pred:
						true_num +=1
					else:
						false_num +=1 
					class_num += 1
		if class_num > 0:
			print('{0}_true_num:{1}, {0}_false_num: {2}, {0}_num:{3}, acc:{4}'.format(name, true_num,false_num, class_num, true_num/class_num))
		total_true_num += true_num
		total_false_num += false_num
		total_num += class_num
	if total_num > 0:
		print('total_true_num:{0}, total_false_num: {1}, total_num:{2}, acc:{3}'.format(total_true_num,total_false_num, total_num, total_true_num/total_num))


	for name in traffics_nonvpn:
		random.Random(2048).shuffle(flow_dict['train'][name]) 
		random.Random(2048).shuffle(flow_dict['test'][name]) 
		print('train flows after',name,len(flow_dict['train'][name]))
		print('test flows after',name,len(flow_dict['test'][name]))

	return flow_dict


def cal_loss(pred, gold, cls_ratio=None):
	gold = gold.contiguous().view(-1)
	# By default, the losses are averaged over each loss element in the batch. 
	loss = F.cross_entropy(pred, gold)

	# torch.max(a,0) 返回每一列中最大值的那个元素，且返回索引
	pred = F.softmax(pred, dim = -1).max(1)[1]
	
	# 相等位置输出1，否则0
	n_correct = pred.eq(gold)
	acc = n_correct.sum().item() / n_correct.shape[0]

	return loss, acc*100

def test(model1, test_x, test_label):
	''' Epoch operation in training phase'''
	model1.eval()
	
	src_seq, gold = torch.tensor(np.array(test_x)).cuda(), torch.tensor(np.array(test_label)).cuda()
	votes = [0]*6
	# print('src_seq.shape', src_seq.shape)
	for i in range(src_seq.shape[0]):#遍历每个包
		
		
		byte = src_seq[i,0].unsqueeze(0) #bytes
		pos = src_seq[i,1].unsqueeze(0) #pos
		# print('byte.shape', byte.shape, 'pos.shape', pos.shape)
		
		pred, _ = model1(byte, pos) #1*6
		# print(pred.shape)
		# idx = pred.index(max(pred))
		# pred = pred.view(pred.shape[0],pred.shape[1],-1)
		# print('pred.shape', pred.shape)
		
		votes[pred] += 1
		if sum(votes) > 4000:
			break
	total_vote = sum(votes)
	max_vote = max(votes)
	result = votes.index(max_vote)
		# second_vote = 0
	print('total vote:', total_vote, ', max vote: ', max_vote, ', result', result, ', gold:', gold.item())
	if result == gold.item() :
		return True
	return False

"""
def main2(i, flow_dict):
	




	f = open('rresults_%d.txt'%i, 'w')
	f.write('Test\n')
	f.flush()

	model1 = SAM(num_class=len(traffics_nonvpn), max_byte_len=max_byte_len).cuda()
	model1.load_state_dict(torch.load('results_nonvpn_4000_lr0.0001_dropstep20/model_%d.pth'%i))


	test_x, test_label = load_epoch_data_flow(flow_dict, 'test')
	test_x = torch.LongTensor(test_x)
	test_label = torch.LongTensor(test_label)
	# test_data = Dataset(x=test_x, label=test_label)
	# test_data = torch.utils.data.DataLoader(
	# 		Dataset(x=test_x, label=test_label),
	# 		num_workers=0,
	# 		collate_fn=paired_collate_fn,
	# 		batch_size=128,
	# 		shuffle=False
	# 	)

	test_acc, pred = test_epoch(model1, test_x, test_label)
		

	# write F1, PRECISION, RECALL
	with open('results_/metric_%d.txt'%i, 'w') as f3:
		f3.write('F1 PRE REC\n')
		p, r, fscore, _ = precision_recall_fscore_support(test_label, pred)
		for a, b, c in zip(fscore, p, r):
			# for every cls
			f3.write('%.2f %.2f %.2f\n'%(a, b, c))
			f3.flush()
		if len(fscore) != len(traffics_nonvpn):
			a = set(pred)
			b = set(test_label[:,0])
			f3.write('%s\n%s'%(str(a), str(b)))

	# write Confusion Matrix
	with open('results_/cm_%d.pkl'%i, 'wb') as f4:
		pickle.dump(confusion_matrix(test_label, pred, normalize='true'), f4)


	# write ACC
	f.write('%.2f\n'%(test_acc))
	f.flush()
		
"""

if __name__ == '__main__':
	for i in range(1):
		with open('test%d.pkl'%i, 'rb') as f:
			flow_dict = pickle.load(f)
		model = SAM(num_class=len(traffics_nonvpn), max_byte_len=max_byte_len).cuda()
		model.load_state_dict(torch.load('results_nonvpn/model_%d.pth'%i))
		flowAllPkt(flow_dict, model)

	"""
	for i in range(1):
		with open('test%d.pkl'%i, 'rb') as f:
			flow_dict = pickle.load(f)
	
		print('====', i, ' fold validation ====')
		main2(i, flow_dict)
	"""

	"""
	with open('dataset/data_vpn/bytes_1000/vpn_pro_flows_bytes_0_noip_fold.pkl', 'rb') as f:
			flow_dict = pickle.load(f)
	print(len(flow_dict['train']['Chat']+flow_dict['test']['Chat']))
	print(len(flow_dict['train']['Chat']+flow_dict['test']['Chat']))
	"""

	"""
	with open('dataset/data_vpn/bytes_1000/vpn_pro_flows_bytes_0_noip_fold.pkl', 'rb') as f:
		flow_dict = pickle.load(f)
	for p in traffics:
		print("train total flows of",p,":",len(flow_dict["train"][p]))
		print("test total flows of",p,":",len(flow_dict["test"][p]))

	print("==========")
	a = ['Email','Chat','Streaming' ,'File Transfer','Voip' , 'Torrent']
	flow_dict_1 = {'train':{},'test':{}}
	for p in a:
		flow_dict_1['train'][p]=flow_dict['train'][p]
		flow_dict_1['test'][p]=flow_dict['test'][p]
		print("train total flows of",p,":",len(flow_dict_1["train"][p]))
		print("test total flows of",p,":",len(flow_dict_1["test"][p]))
	"""