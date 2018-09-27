import re
import requests
import socket
import socket, time, _thread

socket.setdefaulttimeout(2)

def start_logo():
    theKingOfNight='''
    =========$$$$$$$$$$$$$$$$$$$$====$$$$$=====$$$$$=========$$$$$$$$$$$===========$$$$$$===========$$$=======
    =========$$$$$$$$$$$$$$$$$$$$====$$$$=====$$$$=========$$$=========$$$=========$$$=$$$==========$$$=======
    =================$$$=============$$$$====$$$=========$$$=============$$$=======$$$===$$$========$$$=======
    =================$$$=============$$$$===$$$========$$$================$$$======$$$====$$$=======$$$=======
    =================$$$=============$$$$==$$$========$$$==================$$$=====$$$=====$$$======$$$=======
    =================$$$=============$$$$$$$$========$$$====================$$$====$$$======$$$=====$$$=======
    =================$$$=============$$$$==$$$========$$$==================$$$=====$$$=======$$$====$$$=======
    =================$$$=============$$$$===$$$========$$$================$$$======$$$========$$$===$$$=======
    =================$$$=============$$$$====$$$=========$$$=============$$$=======$$$=========$$$==$$$=======
    =================$$$=============$$$$=====$$$$=========$$$=========$$$=========$$$==========$$$=$$$=======
    =================$$$=he==========$$$$======$$$$$=ing=====$$$$$$$$$$$==f========$$$===========$$$$$$=ight==
    '''
    print(theKingOfNight)

def Headers():
    Headers={
       "Host":"api.webscan.cc",
       "Accept":"application/json,text/javascript,*/*;q=0.01",
       "Origin": "http:// www.webscan.cc",
       "Referer": "http:// www.webscan.cc/",
       "User-Agent":"Mozilla/5.0(Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
       "Referer":"http://www.webscan.cc/",
       "Accept-Language": "zh, zh - CN;q = 0.9, en;q = 0.8, zh - TW;q = 0.7",
       "Accept-Encoding": "gzip,deflate",
       "Connection": "close"
    }

def get_ip(det_url):
    #I haven't concerd CND!!!!!!!!!!!!
    print("*Getting ip:"+det_url)
    get_ip='http://api.webscan.cc/?action=getip&domain=%s'%det_url
    data=requests.get(get_ip,Headers()).text.encode('utf-8').decode('unicode_escape')
    #print(data)
    ip=re.findall(r"(\d+.\d+.\d+.\d+)",data)
    ip=str(ip)[2:-2]
    print("---------ip:"+ip)
    print("==================================================================================")
    return ip

def socket_port(ip, port):
    try:
        if port >= 65535:
            print('Port scanning over...')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        if result == 0:
            lock.acquire()
            print(ip, ':', port, 'open')
            lock.release()
        s.close()
    except:
        print('Port scan error...')

def get_port(ip):
    lock = _thread.allocate_lock()
    print("*Starting analyze "+ip+"'s port:")
    for i in range(0, 65535):
        _thread.start_new_thread(socket_port, (ip, int(i)))
    print('*Completed...')
    print("==================================================================================")
    pass

def get_ip_side(ip):
    get_ip = 'http://api.webscan.cc/?action=query&ip=%s' % ip
    #print("using api:"+get_ip)
    data = requests.get(get_ip, Headers()).text.encode('utf-8').decode('unicode_escape')[3:]
    data=format_data(data)
    return data

def get_side(ip):
    print("*Getting side station :" + ip)
    get_ip = 'http://api.webscan.cc/?action=query&ip=%s' % ip
    #print("using api:"+get_ip)
    data = requests.get(get_ip, Headers()).text.encode('utf-8').decode('unicode_escape')[3:]
    data=get_ip_side(ip)
    for i in data:
        print(i)
    print("========================================================================================================")
    return data

def get_C(ip):
    print("*Starting analyse "+ip+"/24")
    C_ip=str(re.findall(r"(\d+.\d+.\d+.)",ip))[2:-2]
    for i in range(255):
        #add nmap
        temp=[]
        C_temp_ip=C_ip+str(i)
        temp=get_ip_side(C_temp_ip)
        temp_return=str(temp)
        if "null" not in temp_return:
            print("\n*Checking ip:"+C_temp_ip)
            for i in temp:
                print(i)
        continue

    print("\nC segment scan completed")
    print("================================================================================================")

def format_data(data):
    data=data.replace(',','')
    data=data.replace('[{','')
    #data=data.replace('"','')
    data=data.replace('\\','')
    data = data.replace('}]', '')
    data=data.split('}{')
    return data

def webscan():
    start_logo()
    while 1:
        det_url = input("theKingOfNight>Target Url:")
        ip = get_ip(det_url)
        get_port(ip)
        get_side(ip)
        get_C(ip)


if __name__ == '__main__':
    lock = _thread.allocate_lock()
    webscan()



