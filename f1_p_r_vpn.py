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
from Transformer import Transformer_pkt, Transformer_flow
from tool_vpn import traffics_vpn,load_epoch_data_flow,max_byte_len

from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import pickle
import numpy as np
import os
from sklearn.metrics import classification_report


os.environ["CUDA_VISIBLE_DEVICES"] = "1"

parser = argparse.ArgumentParser(description='Encrypted Traffic Classification')
# parser.add_argument("--mode", type=str, default='transformer_flow')
parser.add_argument('--num_classes',type=int, default=4, help='Number of Classes')
parser.add_argument('--num_epochs', type=int, default=10, help='Number of epochs to train.')
parser.add_argument('--dropout', type=int, default=0.1, help='dropout.')
parser.add_argument('--sentence_max_len', type=int, default=50, help='The max length of payload.')
parser.add_argument('--num_pkt', type=int, default=3, help='Numbers of packet.')
parser.add_argument('--input_len', type=int, default=500, help='The length of payload.')
parser.add_argument('--batch_size', type=int, default=256, help='Batch Size.')
parser.add_argument('--learning_rate', type=int, default=0.0005, help='Learning Rate.')
parser.add_argument('--step_size', type=int, default=5, help='Learning Rate change step_size.')
parser.add_argument('--gamma', type=int, default=0.9, help='Learning Rate change gamma.')
parser.add_argument('--dim_model', type=int, default=256, help='Embedding Size.')
parser.add_argument('--d_ff', type=int, default=1024, help='Hidden Size.')
parser.add_argument('--num_head', type=int, default=8, help='Numbers of heads.')
parser.add_argument('--num_encoder', type=int, default=2, help='Numbers of Encoders.')
parser.add_argument('--num_head_flow', type=int, default=2, help='Numbers of heads.')
parser.add_argument('--num_encoder_flow', type=int, default=2, help='Numbers of Encoders.')
parser.add_argument("--load_path", type=str, default='./results/vpn/session/lessdetail/session2pkts_len_50_1000_82_256')
parser.add_argument("--save_path", type=str, default='./results/vpn/session/lessdetail/session2flows_len_3_50_1000_8222_256')
args = parser.parse_args()

class Dataset(torch.utils.data.Dataset):
	"""docstring for Dataset"""
	def __init__(self, x, label):
		super(Dataset, self).__init__()
		self.x = x
		self.label = label

	def __len__(self):
		return len(self.x)

	def __getitem__(self, idx):
		return self.x[idx], self.label[idx]

def paired_collate_fn(insts):
	x,label = list(zip(*insts))
	return torch.LongTensor(x), torch.LongTensor(label)

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

def test_epoch(model1, model2, test_data):
	''' Epoch operation in training phase'''
	model1.eval()
	model2.eval()

	total_acc = []
	total_pred = []
	total_time = []
	# tqdm: 进度条库
	# desc ：进度条的描述
	# leave：把进度条的最终形态保留下来 bool
	# mininterval：最小进度更新间隔，以秒为单位
	for batch in tqdm(
		test_data, mininterval=2,
		desc='  - (Testing)   ', leave=False):

		# prepare data
		features = []
		src_seq, gold = batch
		src_seq, gold = src_seq.cuda(), gold.cuda()
		gold = gold.contiguous().view(-1)

		torch.cuda.synchronize()
		start = time.time()
		# print('src_seq.shape', src_seq.shape[1])
		for i in range(src_seq.shape[1]):
			x = src_seq[:,i,0]
			y = src_seq[:,i,1]
			# print('x.shape', x.shape, 'y.shape', y.shape)
			
			pred = model1.get_liner1(x, y)#128*256
			# pred = pred.view(pred.shape[0],pred.shape[1],-1)
			# print('pred.shape', pred.shape)
			
			features.append(pred)
		features = torch.stack(features, dim=2).transpose(-2, -1) 

		# forward
		
		pred = model2(features)
		torch.cuda.synchronize()
		end = time.time()
		# 相等位置输出1，否则0
		# print('pred:',pred.shape,'gold:',gold.shape)
		n_correct = pred.eq(gold)
		acc = n_correct.sum().item()*100 / n_correct.shape[0]
		total_acc.append(acc)
		total_pred.extend(pred.long().tolist())
		total_time.append(end - start)

	return sum(total_acc)/len(total_acc), total_pred, sum(total_time)/len(total_time)



def main2(i, flow_dict):


	# model1 = SAM(num_class=len(traffics_vpn), max_byte_len=max_byte_len).cuda()
	model1 = Transformer_pkt(args).cuda()
	model1.load_state_dict(torch.load('%s/model_%d.pth'%(args.load_path,i)))
	model2 = Transformer_flow(args).cuda()
	model2.load_state_dict(torch.load('%s/model_%d.pth'%(args.save_path,i)))
	# optimizer = optim.Adam(filter(lambda x: x.requires_grad, model2.parameters()),lr=args.learning_rate)
	# scheduler = optim.lr_scheduler.StepLR(optimizer,step_size=args.step_size,gamma = args.gamma)
	best_test_acc = 0
	
	test_x, test_label = load_epoch_data_flow(flow_dict, 'test')
	test_data = torch.utils.data.DataLoader(
			Dataset(x=test_x, label=test_label),
			num_workers=0,
			collate_fn=paired_collate_fn,
			batch_size=args.batch_size,
			shuffle=False
		)
	test_acc, pred, test_time = test_epoch(model1, model2, test_data)
		
		
	
	
	print(classification_report(test_label, pred, target_names=traffics_vpn ,digits=4))
		
    


if __name__ == '__main__':

	
	for i in range(10):
		with open('dataset/data_vpn/session/lessdetail/session2flows_len_3_50_1000/vpn_flow_3_50_1000_%d.pkl'%i, 'rb') as f:
			flow_dict = pickle.load(f)
	
		print('====', i, ' fold validation ====')
		main2(i, flow_dict)
	

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