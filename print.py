import matplotlib.pyplot as plt
import numpy as np 
from matplotlib.font_manager import FontProperties

# 在我的 notebook 里，要设置下面两行才能显示中文
plt.rcParams['font.family'] = ['sans-serif']
# 如果是在 PyCharm 里，只要下面一行，上面的一行可以删除
plt.rcParams['font.sans-serif'] = ['SimHei']







# plt.figure(figsize=(20, 8))  # 设置画布
x_index = np.arange(5)  # 确定label的位置
# 定义一个数字代表独立柱的宽度
bar_width = 0.1  
x_data = (0, 1, 2, 3, 4)
#non_vpn
# acc=(89.94, 89.94, 92.52, 91.85, 90.27)
# f1=(89.75, 89.64, 92.48, 91.61, 90.15)
# p=(89.85, 89.60, 92.64, 91.60, 90.16)
# r=(89.94, 89.93, 92.52, 91.85, 90.27)

# vpn
# acc=(98.96, 98.93, 98.42, 99.12, 98.17)
# f1=(98.95, 98.94, 98.42, 99.12, 98.15)
# p=(98.96, 98.95, 98.42, 99.13, 98.20)
# r=(98.96, 98.93, 98.42, 99.12, 98.17)

#tor
# acc=(88.88, 71.76, 84.82, 68.02, 80.06)
# f1=(88.03, 65.77, 82.40, 62.41, 79.49)
# p=(88.94, 73.39, 81.67, 69.08, 82.59)
# r=(88.88, 71.76, 84.82, 68.02, 80.06)

#total
acc=(99.98, 99.96, 99.97, 99.94, 99.94)
f1=(99.95, 99.93, 99.92, 99.91, 99.92)
p=(99.96,99.93 ,99.91 ,99.88 ,99.97)
r=(99.93 ,99.92 ,99.92 ,99.93 ,99.86)

#直方图
# rects1 = plt.bar(x_index, acc, width=bar_width, color="skyblue", label="Accuracy")
# rects2 = plt.bar(x_index+bar_width, f1, width=bar_width, color="lightsalmon", label="F1-Score")
# rects3 = plt.bar(x_index+(bar_width*2), p, width=bar_width,color="m", alpha=0.6,label="P")
# rects4 = plt.bar(x_index+(bar_width*3), r, width=bar_width, color="gold", label="R")

#折线图
rects1 = plt.plot(x_data, acc, color="skyblue", linewidth=1.0, marker = '*',label="Accuracy")
rects2 = plt.plot(x_data, f1, color="lightsalmon", linewidth=1.0, marker = 'h',label="F1-Score")
rects3 = plt.plot(x_data, p, color="m", linewidth=1.0, marker = 'o',label="Precession")
rects4 = plt.plot(x_data, r, color="gold", linewidth=1.0, marker = '+',label="Recall")

plt.xticks(x_index + 1.5*bar_width, x_data)  # 设定x轴
my_y_ticks = np.arange(0, 110, 20)#原始数据有13个点，故此处为设置从0开始，间隔为1
plt.yticks(my_y_ticks)
# plt.xlabel("K折交叉验证(K=5)")
# plt.ylabel("纵坐标")
plt.legend()#显示图例

plt.grid(ls='-.',alpha=0.3)  # 绘制背景线
plt.savefig("./Pictures/non_vpn_bar.png")
