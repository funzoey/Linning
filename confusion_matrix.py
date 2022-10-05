import pickle
import numpy as np
import matplotlib.pyplot as plt
import itertools

plt.rcParams['axes.unicode_minus']=False


#non-vpn 
"""
classes = ['Chat', 'File Transfer', 'Streaming', 'Voip', 'Browsing']

confusion_matrix = np.zeros((5,5))
with open('./results/nonvpn/session/lessdetail/session2flows_len_6_60_500_4222_256/5/cm_5.pkl', 'rb') as f:
	a = pickle.load(f)

for i in range(len(classes)):
	for j in range(len(classes)):
		confusion_matrix[i][j]=round(a[i][j] ,2)

# print(flow_dict)
# plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.YlGnBu)  #按照像素显示出矩阵
plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)  #按照像素显示出矩阵
# plt.title('混淆矩阵')
plt.colorbar()
tick_marks = np.arange(len(classes))
plt.xticks(tick_marks, classes, rotation=45)
plt.yticks(tick_marks, classes)
 
thresh = confusion_matrix.max() / 2.
#iters = [[i,j] for i in range(len(classes)) for j in range((classes))]
#ij配对，遍历矩阵迭代器
# iters = np.reshape([[[i,j] for j in range(5)] for i in range(5)],(confusion_matrix.size,2))
# for i, j in iters:
#     plt.text(j, i, format(confusion_matrix[i, j]),fontsize=7)   #显示对应的数字


for i, j in itertools.product(range(confusion_matrix.shape[0]), range(confusion_matrix.shape[1])):
        plt.text(j, i, confusion_matrix[i, j],
                 horizontalalignment="center",
                 color="white" if confusion_matrix[i, j] > thresh else "black")

 
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
plt.show()
plt.savefig("./Pictures/con_non_vpn.png")
""" 


###########################################
#vpn
"""
classes = ['VPN: Chat', 'VPN: File Transfer', 'VPN: Streaming', 'VPN: Voip']

confusion_matrix = np.zeros((4,4))
with open('./results/vpn/session/lessdetail/session2flows_len_3_50_1000_8222_256/cm_7.pkl', 'rb') as f:
	a = pickle.load(f)

for i in range(len(classes)):
	for j in range(len(classes)):
		confusion_matrix[i][j]=round(a[i][j] ,2)

# print(flow_dict)
# plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.YlGnBu)  #按照像素显示出矩阵
plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)  #按照像素显示出矩阵
# plt.title('混淆矩阵')
plt.colorbar()
tick_marks = np.arange(len(classes))
plt.xticks(tick_marks, classes, rotation=45)
plt.yticks(tick_marks, classes)
 
thresh = confusion_matrix.max() / 2.
#iters = [[i,j] for i in range(len(classes)) for j in range((classes))]
#ij配对，遍历矩阵迭代器
# iters = np.reshape([[[i,j] for j in range(4)] for i in range(4)],(confusion_matrix.size,2))
# for i, j in iters:
#     plt.text(j, i, format(confusion_matrix[i, j]),fontsize=7)   #显示对应的数字


for i, j in itertools.product(range(confusion_matrix.shape[0]), range(confusion_matrix.shape[1])):
        plt.text(j, i, confusion_matrix[i, j],
                 horizontalalignment="center",
                 color="white" if confusion_matrix[i, j] > thresh else "black")

 
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
plt.show()
plt.savefig("./Pictures/con_vpn.png")

"""

###########################################
#tor
"""

classes = ['TOR: Chat', 'TOR: File Transfer', 'TOR: Streaming', 'TOR: Voip', 'TOR: Browsing']

confusion_matrix = np.zeros((5,5))
with open('./results/tor/session/lessdetail/session2flows_len_3_50_5000_2122_128/cm_0.pkl', 'rb') as f:
	a = pickle.load(f)

for i in range(len(classes)):
	for j in range(len(classes)):
		confusion_matrix[i][j]=round(a[i][j] ,2)

# print(flow_dict)
# plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.YlGnBu)  #按照像素显示出矩阵
plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)  #按照像素显示出矩阵
# plt.title('混淆矩阵')
plt.colorbar()
tick_marks = np.arange(len(classes))
plt.xticks(tick_marks, classes, rotation=45)
plt.yticks(tick_marks, classes )
 
thresh = confusion_matrix.max() / 2.
#iters = [[i,j] for i in range(len(classes)) for j in range((classes))]
#ij配对，遍历矩阵迭代器
# iters = np.reshape([[[i,j] for j in range(4)] for i in range(4)],(confusion_matrix.size,2))
# for i, j in iters:
#     plt.text(j, i, format(confusion_matrix[i, j]),fontsize=7)   #显示对应的数字


for i, j in itertools.product(range(confusion_matrix.shape[0]), range(confusion_matrix.shape[1])):
        plt.text(j, i, confusion_matrix[i, j],
                 horizontalalignment="center",
                 color="white" if confusion_matrix[i, j] > thresh else "black")

 
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
plt.show()
plt.savefig("./Pictures/con_tor.png")
"""

###########################################
#total
"""
classes =  ['Non_VPN', 'VPN', 'Tor']

confusion_matrix = np.zeros((3,3))
with open('./results/total/session/session2flows_len_3_50_4222_256/cm_0.pkl', 'rb') as f:
	a = pickle.load(f)

for i in range(len(classes)):
	for j in range(len(classes)):
		confusion_matrix[i][j]=round(a[i][j] ,4)

# print(flow_dict)
# plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.YlGnBu)  #按照像素显示出矩阵
plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)  #按照像素显示出矩阵
# plt.title('混淆矩阵')
plt.colorbar()
tick_marks = np.arange(len(classes))
plt.xticks(tick_marks, classes, rotation=45)
plt.yticks(tick_marks, classes)
 
thresh = confusion_matrix.max() / 2.
#iters = [[i,j] for i in range(len(classes)) for j in range((classes))]
#ij配对，遍历矩阵迭代器
# iters = np.reshape([[[i,j] for j in range(4)] for i in range(4)],(confusion_matrix.size,2))
# for i, j in iters:
#     plt.text(j, i, format(confusion_matrix[i, j]),fontsize=7)   #显示对应的数字


for i, j in itertools.product(range(confusion_matrix.shape[0]), range(confusion_matrix.shape[1])):
        plt.text(j, i, confusion_matrix[i, j],
                 horizontalalignment="center",
                 color="white" if confusion_matrix[i, j] > thresh else "black")

 
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
plt.show()
plt.savefig("./Pictures/con_total.png")
"""


#######################################
#app
classes =  ['AIM chat', 'Email', 'Facebook', 'FTPS', 'Gmail', 'Hangouts', 'ICQ', 'Netflix', 'SCP', 'SFTP', 'Skype', 'Spotify', 'Torrent', 'Tor', 'VoipBuster', 'Vimeo', 'YouTube']

confusion_matrix = np.zeros((17,17))
with open('./results/app/session/lessdetail/session2flows_len_3_50_4222_256/0/cm_0.pkl', 'rb') as f:
        a = pickle.load(f)

for i in range(len(classes)):
	for j in range(len(classes)):
		confusion_matrix[i][j]=round(a[i][j] ,4)

# plt.figure(figsize=(500, 500))  # 设置画布
# print(flow_dict)
# plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.YlGnBu)  #按照像素显示出矩阵
plt.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.Blues)  #按照像素显示出矩阵
# plt.title('混淆矩阵')
plt.colorbar()
tick_marks = np.arange(len(classes))
plt.xticks(tick_marks, classes, rotation=45)
plt.yticks(tick_marks, classes)
 
thresh = confusion_matrix.max() / 2.
#iters = [[i,j] for i in range(len(classes)) for j in range((classes))]
#ij配对，遍历矩阵迭代器
# iters = np.reshape([[[i,j] for j in range(4)] for i in range(4)],(confusion_matrix.size,2))
# for i, j in iters:
#     plt.text(j, i, format(confusion_matrix[i, j]),fontsize=7)   #显示对应的数字


for i, j in itertools.product(range(confusion_matrix.shape[0]), range(confusion_matrix.shape[1])):
        plt.text(j, i, confusion_matrix[i, j],
                 horizontalalignment="center",
                 color="white" if confusion_matrix[i, j] > thresh else "black",fontsize=2)

 
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.tight_layout()
plt.show()
plt.savefig("./Pictures/con_app.png")