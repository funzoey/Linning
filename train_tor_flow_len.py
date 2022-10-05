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
# from tool import protocols, load_epoch_data, max_byte_len
from tool_tor_flowpkt_bytes_gai import traffics_tor,load_epoch_data_flow_len,max_byte_len

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
# parser.add_argument('--input_len', type=int, default=500, help='The length of payload.')
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

class Dataset(torch.utils.data.Dataset):
	"""docstring for Dataset"""
	def __init__(self, x, y, label):
		super(Dataset, self).__init__()
		self.x = x
		self.y = y
		self.label = label

	def __len__(self):
		return len(self.x)

	def __getitem__(self, idx):
		return self.x[idx], self.y[idx], self.label[idx]

def paired_collate_fn(insts):
	x, y, label = list(zip(*insts))
	return torch.LongTensor(x), torch.LongTensor(y), torch.LongTensor(label)

def cal_loss(pred, gold, cls_ratio=None):
	gold = gold.contiguous().view(-1)
	# By default, the losses are averaged over each loss element in the batch. 
	loss = F.cross_entropy(pred, gold)

	# torch.max(a,0) 返回每一列中最大值的那个元素，且返回索引
	pred = F.softmax(pred, dim = -1).max(1)[1]
	
	# 相等位置输出1，否则0
	n_correct = pred.eq(gold)
	# print('n_correct',n_correct.shape)
	# print('n_correct',n_correct)
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
		src_seq, src_len, gold = batch
		src_seq, src_len, gold = src_seq.cuda(), src_len.cuda(), gold.cuda()
		gold = gold.contiguous().view(-1)

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
		torch.cuda.synchronize()
		
		pred = model2(features, src_len)
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

def train_epoch(model1, model2, training_data, optimizer):
	''' Epoch operation in training phase'''
	model1.eval()
	model2.train()

	total_loss = []
	total_acc = []
	# tqdm: 进度条库
	# desc ：进度条的描述
	# leave：把进度条的最终形态保留下来 bool
	# mininterval：最小进度更新间隔，以秒为单位
	for batch in tqdm(
		training_data, mininterval=2,
		desc='  - (Training)   ', leave=False):

		# prepare data
		features = []
		src_seq, src_len, gold = batch
		src_seq, src_len, gold = src_seq.cuda(), src_len.cuda(), gold.cuda()
		# print('src_seq.shape', src_seq.shape[1])
		for i in range(src_seq.shape[1]):
			x = src_seq[:,i,0]
			y = src_seq[:,i,1]
			# print('x.shape', x.shape, 'y.shape', y.shape)
			
			pred = model1.get_liner1(x, y)#128*256
			# pred = pred.view(pred.shape[0],pred.shape[1],-1)
			# print('pred.shape', pred.shape)
			
			features.append(pred)
		features = torch.stack(features, dim=2).transpose(-2, -1) #128, 3, 256
		# features = features.cuda()
		# print('pred.shape', features.shape)

		optimizer.zero_grad()
		# forward
		pred = model2(features, src_len)
		# print('pred:',pred.shape,'gold:',gold.shape)
		loss_per_batch, acc_per_batch = cal_loss(pred, gold)
		# update parameters
		
		loss_per_batch.backward()
		optimizer.step()

		# 只有一个元素，可以用item取而不管维度
		total_loss.append(loss_per_batch.item())
		total_acc.append(acc_per_batch)
		
	return sum(total_loss)/len(total_loss), sum(total_acc)/len(total_acc)
	




def main2(i, flow_dict):
	f = open('results_tor_flow_len/results_%d.txt'%i, 'w')
	f.write('Train Loss Time Test\n')
	f.flush()

	model1 = SAM(num_class=len(traffics_tor), max_byte_len=max_byte_len).cuda()
	model1.load_state_dict(torch.load('results_tor/model_%d.pth'%i))
	model2 = Transformer_flow(args).cuda()
	optimizer = optim.Adam(filter(lambda x: x.requires_grad, model2.parameters()),lr=0.000001)
	scheduler = optim.lr_scheduler.StepLR(optimizer,step_size=20,gamma = 0.9)
	best_test_acc = 0
	for epoch_i in trange(100, mininterval=2, \
		desc='  - (Training Epochs)   ', leave=False):

		train_x, train_y, train_label = load_epoch_data_flow_len(flow_dict, 'train')
		training_data = torch.utils.data.DataLoader(
				Dataset(x=train_x, y=train_y, label=train_label),
				num_workers=0,
				collate_fn=paired_collate_fn,
				batch_size=128,
				shuffle=True
			)
		
		train_loss, train_acc = train_epoch(model1, model2, training_data, optimizer)
		
		scheduler.step()
		# print(optimizer.state_dict()['param_groups'][0]['lr'])
		test_x, test_y, test_label = load_epoch_data_flow_len(flow_dict, 'test')
		test_data = torch.utils.data.DataLoader(
				Dataset(x=test_x, y=test_y ,label=test_label),
				num_workers=0,
				collate_fn=paired_collate_fn,
				batch_size=128,
				shuffle=False
			)
		test_acc, pred, test_time = test_epoch(model1, model2, test_data)
		if test_acc > best_test_acc:
			best_test_acc = test_acc
			torch.save(model2.state_dict(), 'results_tor_flow_len/model_%d.pth'%i)
		

		# write F1, PRECISION, RECALL
		with open('results_tor_flow_len/metric_%d.txt'%i, 'w') as f3:
			f3.write('F1 PRE REC\n')
			p, r, fscore, _ = precision_recall_fscore_support(test_label, pred)
			for a, b, c in zip(fscore, p, r):
				# for every cls
				f3.write('%.2f %.2f %.2f\n'%(a, b, c))
				f3.flush()
			if len(fscore) != len(traffics_tor):
				a = set(pred)
				b = set(test_label[:,0])
				f3.write('%s\n%s'%(str(a), str(b)))

		# write Confusion Matrix
		with open('results_tor_flow_len/cm_%d.pkl'%i, 'wb') as f4:
			pickle.dump(confusion_matrix(test_label, pred, normalize='true'), f4)


		# write ACC
		f.write('%.2f %.4f %.6f %.2f\n'%(train_acc, train_loss, test_time, test_acc))
		f.flush()
		
    


if __name__ == '__main__':

	
	for i in range(1):
		with open('tor_flow_len_%d.pkl'%i, 'rb') as f:
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