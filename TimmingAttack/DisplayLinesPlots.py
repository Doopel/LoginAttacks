import glob

import matplotlib.pyplot as plt

files = glob.glob("wireData/*.txt")
files.sort()


data = {}
times = []
passwords = []


for file in files:
    f = open(file, 'r')
    for line in f:
        (password, sec) = line.strip().split(':')
        if 32 > float(sec) > 0:
            times.append(float(sec))
    data[password] = times
    passwords.append(password)
    times = []
    f.close()

print(passwords)



for password in passwords:
    plt.plot(data[password], linestyle='-',label=password)   # Dibuja el gráfico
plt.legend(loc="upper right")

plt.grid(True)

plt.show()



