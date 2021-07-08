import matplotlib
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt

f = open("build/train_log.log")
fl = f.readlines()
x = []
y0 = []
y1 = []
y2 = []
for line in fl:
    a = line.split(' ')
    x.append(int(a[0]))
    y0.append(float(a[1]))
    y1.append(float(a[2]))
    y2.append(float(a[3]))
print(y0)
print(y1)
print(y2)
print(len(x), len(y0), len(y1), len(y2))

plt.plot(x, y0, '-', label = 'Plain text')
plt.plot(x, y2, ':', label = 'Purification')
plt.plot(x, y1, '--', label = 'Dummy tuples')
plt.ylabel('Accuracy')
plt.xlabel('Number of Iterations')
plt.legend() 
plt.show() 
plt.savefig("accuracy_result.jpg")