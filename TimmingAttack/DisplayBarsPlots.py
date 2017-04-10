import glob

import numpy as np
import matplotlib.pyplot as plt


files = glob.glob("wireData/*.txt")
files.sort()

times = []
passwords = []
medias = []
varianzas = []
medianas =[]

for file in files:
    f = open(file, 'r')
    for line in f:
        (password, sec) = line.strip().split(':')
        if float(sec) < 50 and float(sec) > 0:
            times.append(float(sec))
    medias.append(np.mean(times))
    passwords.append(password)
    varianzas.append(np.var(times))
    medianas.append(np.median(times))
    times = []
    f.close()


print(varianzas)
print(medias)
print(passwords)
print(medianas)

ind = np.arange(len(passwords))
width = 0.25
fix, ax = plt.subplots()

plt.xlabel('passwords')
plt.ylabel('Times')
plt.xticks(ind, passwords)
rec = ax.bar(ind, medias, width, align='center',alpha=0.75,color='blue', yerr=varianzas)


plt.show()


