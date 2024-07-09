#Импортируем нужные нам библиотеки:
import threading
import socket
import os
import subprocess
import sys
import psutil
import time
from colorama import Fore, Back, Style

# Чтобы использовать инструмент на постоянной основе нужно сделать его удобным, добавим первые аргументы и получим их значения:
if("--target" in sys.argv):
    indexoftarget=sys.argv.index("--target")
    target=sys.argv[indexoftarget+1]
else:
    print("Target is not specified, see --help")
    exit()

# Так как юзер может быть незнаком с аргументами, нужно сделать команду "--help":
if("--help" in sys.argv):
    print("Usage: python3 rollerscan.py --target [target]")
    print("Additional flags:")
    print("--virtual-hosts (-vh) — try to find virtual hosts")
    print("--vuln (-v) — find possible exploits")
    print("--censys (-c) — use censys to search for additional info.")
    print("--port (-p) — specify port range for scan, by default 1-60 000")
    exit()

# Пока что мы реализуем только ввод промежутка портов, т.е через -
if("--port" in sys.argv):
    indexofport=sys.argv.index("--port")
    port=sys.argv[indexofport+1]
    if("-" in port):
        port=port.split("-")
        end=int(port[1])
        start=int(port[0])
elif("-p" in sys.argv):
    indexofport=sys.argv.index("-p")
    port=sys.argv[indexofport+1]
    if("-" in port):
        port=port.split("-")
        end=int(port[1])
        start=int(port[0])
else:
    start=1
    end=60000

# Перед началом сканирования хорошо бы убедиться что цель вообще доступна.
response=os.system("ping -c 1 " + target)

# Зададим нужные нам в будущем переменные:
processes=[]
nmapdone={}

# Итак, если цель активна, то мы продолжаем исполнение программы, а если же нет, то спрашиваем у пользователя 
# уверен ли он что хочет продолжить.
if (response==0):
    print("[", Fore.LIGHTCYAN_EX+"^"+Style.RESET_ALL, "]", Fore.YELLOW+target+Style.RESET_ALL, Fore.GREEN+"is UP"+Style.RESET_ALL)
if (response!=0):
    print("[", Fore.LIGHTCYAN_EX+"^"+Style.RESET_ALL, "]", Fore.LIGHTYELLOW_EX+target+Style.RESET_ALL, Fore.RED+"is DOWN"+Style.RESET_ALL)
    choise=input("Do you want to continue considiring that target is marked as DOWN? Y/N: ")
    if(choise=="Y" or choise=="y"):
        pass
    else:
        print(Fore.RED+"Shutting down")
        exit()

# Проинформируем о начале сканирования и узнаем точное время запуска:
print("[", Fore.LIGHTCYAN_EX+"&"+Style.RESET_ALL, "]", Fore.BLUE+"Starting Scan!"+Style.RESET_ALL)
start_time=time.time()

# Определим socket.socket(socket.AF_INET, socket.SOCK_STREAM) как s:
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Чтобы сканирование было быстрее, поставим лимит времени на один порт, после которого он определиться как закрытый:
s.settimeout(0.5)

# Теперь сама функция сканирования портов:
def portscan(port):
    try:
        con = s.connect((target,port))
        print('[', Fore.LIGHTCYAN_EX+'*'+Style.RESET_ALL,']',Fore.YELLOW+f'''Port: {port}'''+Style.RESET_ALL, Fore.GREEN+"is opened."+Style.RESET_ALL)
        process=subprocess.Popen(f'''nmap -sV {target} -p {port}''', shell=True)
        processes.append(process.pid)
        con.close()
    except Exception as e:
        pass
# Теперь мультипоточность:
r = start
for r in range(start, end):
    try:
        t = threading.Thread(target=portscan,kwargs={'port':r})
        r += 1
        t.start()
    except KeyboardInterrupt:
        os._exit(0)
    except Exception as e:
        portscan(r)
        r += 1

# Теперь перед завершением нужно удостовериться, что nmap просканировал порты
def checkprocess():
    for proc in processes:
        if psutil.pid_exists(proc):
            nmapdone[proc]='False'
        else:
            nmapdone[proc]='True'

# Запустим функцию:
while 'False' in nmapdone.values():
    checkprocess()

# Нам нужно проверить завершились ли все потоки:
threadslist=int(threading.active_count())
while threadslist>1:
    threadslist=int(threading.active_count())
    time.sleep(0.000001)

# Строка, где мы получим время работы:
print(Fore.BLUE+"Scan of ports Ended in:"+Style.RESET_ALL, Fore.GREEN+str(round(time.time()-start_time))+Style.RESET_ALL, "s")