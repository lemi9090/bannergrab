import socket
import requests
import smtplib
import paramiko
import ftplib
import telnetlib
import ssl
import struct
import logging
from concurrent.futures import ThreadPoolExecutor
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 변경점 
# 1 : 
# 2 : 
# 3 : 
# 4 : 

## TCP SERVICE ##

def http_banner_grabbing(ip, port):
    target_url = f"http://{ip}:{port}"
    try:
        response = requests.get(target_url, timeout=5)
        protocol = 'https:' if response.url.startswith('https://') else 'http:'
        logging.info(f"{port} : {protocol}")
        return protocol
    except requests.exceptions.RequestException:
        return https_banner_grabbing(ip, port)
    
def https_banner_grabbing(ip, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.settimeout(4)
                cert = ssock.getpeercert()
                logging.info(f"Server certificate for {ip}:{port}")
                for key, value in cert.items():
                    logging.info(f"{key}: {value}")
                return 'https:'
    except Exception as e:
        logging.error(f"Error connecting to {ip}:{port}: {str(e)}")
        return False

# def scan_ips(ip_list, port):
#     with ThreadPoolExecutor(max_workers=10) as executor:
#         results = list(executor.map(lambda ip: http_banner_grabbing(ip, port), ip_list))
#     return results


# def http_banner_grabbing(ip, port): # https 요청까지 하기 위해 변수를 수정했습니다.
#     print(f"{port} : checking http...")
#     try:
#         target_url = f"http://{ip}:{port}" 
#         response = requests.get(target_url, timeout=5) 
#         return response.url[0:5] # http: or https 리턴
#     except requests.exceptions.RequestException as e: # http 요청 실패 시 https 요청
#         try: #HTTPS 인증서를 확인하여 임의 추정 가능
#             context = ssl.create_default_context()
#             context.check_hostname = False
#             context.verify_mode = ssl.CERT_NONE
#             with socket.create_connection((ip, port), timeout=3) as sock:
#                 with context.wrap_socket(sock, server_hostname=ip) as ssock:
#                     ssock.settimeout(4)
#                     cert = ssock.getpeercert()
#                     print("Server certificate:")
#                     for key, value in cert.items():
#                         print(f"{key}: {value}")
#         except Exception as e:
#             return False
#     except Exception as e:
#         return False
    
def checkMySQL(ip, port):
    # 소켓 생성 및 연결
    print(f"{port} : checking mysql...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.settimeout(2)
        banner = s.recv(1024)
        packet_Len = int.from_bytes(banner[0:2], 'little') # packet Length[3 Bytes]
        packet_Number = banner[3] # packet Number[1 Bytes]
        proto = int(banner[4]) # MySQL Protocol[1Bytes] 일반적인 경우 0xA Block된 경우 0xFF

        if packet_Len == (int(banner.__len__()) - 4) and packet_Number == 0: # packet 길이와 packet 번호가 mysql 프로토콜에 일반적인 값인지 확인
            if(proto == 255): #Blocked된 경우 MySQL Protocol
                return True
            elif(proto == 10): #일반적인 MySQL Protocol
                packet = str(banner[4:])
                ver = packet[4:packet.find("\\x00")] # 버전 식별
                return True
            else:
                a = open("checkLog.txt",'a') # mysql 패킷헤더는 일치하나 프로토콜 검증 실패 시
                a.write(f"{ip} : {port} : {banner}\n")
                return False
        return False
    except Exception as e:
        return False
    
def checkSSH(ip, port):
    print(f"{port} : checking ssh...")
    # 소켓 생성 및 연결
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP 방식
        s.settimeout(5)
        s.connect((ip, port))
        # 서버 응답
        banner = s.recv(1024).decode(errors='ignore')
        s.close()
        if "SSH" in banner:
            return True
    except Exception as e :
        try:
            transport = paramiko.Transport((ip, port),timeout=5)
            transport.start_client()
            paramiko_banner = transport.remote_version
            transport.close()
            if paramiko_banner:
                return True
        except Exception as e:
            return False
       
def checkFTP(ip,port):
    print(f"{port} : checking ftp...")
    try:
        ftp = ftplib.FTP()
        recv = ftp.connect(ip, port,timeout=5)
        if recv is not None:
            ver = recv.split("\n")[0] # 버전 식별
        else:
            return False
        a = ftp.login('a','a')
        return True
    except (ftplib.error_perm) as e: # 로그인 에러 리턴시 
        if '530' in str(e):
            return True
        return False
    except Exception as e:
        return False
    
def checkTelnet(ip, port):
    print(f"{port} : checking telnet...")
    try:
        tel = telnetlib.Telnet(ip,port,timeout=5)
        recv = tel.read_until(b"login: ",timeout=5)
        tel.write(b'korea\n')
        recv = tel.read_until(b"Password: ",timeout=5)
        if b'Password' in recv:
            return True
        else:
            return False

    except Exception as e:
        return False

def check_SMTP(ip, port):
    print(f"{port} : checking smtp...")
    try:
        with smtplib.SMTP(ip, port, timeout=5) as server:
            banner = server.ehlo()
            if not banner:
                banner = server.helo()
            return True
    except smtplib.SMTPException as e:
        return False
    except Exception as e:
        return False

def check_RDP(ip, port):
    x224_cr_pdu = bytes.fromhex('030001ca02f0807f658201b90400000400000000000000000b00000000000000000000010014000c00010000000000010008000300000007000c0008001000010000')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.sendall(x224_cr_pdu)
            response = sock.recv(1024)
            if response:
                tpkt_ver = response[0]
                reserved, length, x224_type = struct.unpack('!BHb', response[1:5]) #받은 자료의 첫 5바이트를 분석.(RDP 필수 패킷들 - TPKT, X.224 Connection Confirm)
                if tpkt_ver == 3 and x224_type == 0xD0: # RDP가 연결(3HS) 후 보내는 고유 값. TPTK, x224 확인
                    variable_part_length = struct.unpack('!B', response[5:6])[0] # 길이 확인
                    if length == len(response) and variable_part_length + 6 <= length:
                        return True
                return False
            else:
                return False
    except Exception as e:
        return False

def check_imap(ip, port):
    print(f"{port} : checking imap...")
    imap_request = b'A1 CAPABILITY\r\n'  # IMAP capability request command
    expected_response_prefix = b'* CAPABILITY'
    tag_ok_response_prefix = b'A1 OK'
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(imap_request)
            response = sock.recv(4096).decode('utf-8', 'ignore')
            if response is not None and (expected_response_prefix in response or tag_ok_response_prefix in response):
                return True
    except Exception as e:
            try:
                context = ssl.create_default_context()
                with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ip) as ssock:
                     ssock.settimeout(5)
                     ssock.connect((ip, port))
                     ssock.sendall(imap_request)
                     response = ssock.recv(4096).decode('utf-8', 'ignore')
                     if response is not None and (expected_response_prefix in response or tag_ok_response_prefix in response):
                        return True
            except Exception as e:
                return False 


def checkSMB(ip,port):
    print(f"{port} : checking smb...")
    #SMB PROBE 생성
    pack = b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\xc8" \
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00" \
        b"\x00\x00\x00\x00\x00\x22\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e" \
        b"\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00\x02\x53" \
        b"\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00"
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip,port))
        sock.send(pack)
        
        recv = sock.recv(1024)
        if b'SMB' in recv:
            return True
        else:
            return False
    except Exception as e:
        return False

def X (ip, port):
    sock = None 
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            banner = sock.recv(1024).decode().strip()
            print(f"{banner}")
    except Exception as e:
        return False

## UDP SERVICE  1 ##
def check_NTP(ip,port):
    print(f"{port} : checking NTP...")
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # NTP PROBE 생성
    pack = b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"\
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
    b"\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"

    s.settimeout(5)
    try:
        s.sendto(pack,(ip,port))
        recv, server = s.recvfrom(1024)
        if recv.__len__() >= 48 and (0 < int(recv[1] < 15)): # 패킷 최소 길이 및 startum(0~15) 값인지 확인
            return True
        return False
    except:
        return False
    finally:
        s.close()

## UDP SERVICE  2 ##
def check_DNS(ip, port):
    print(f"{port} : checking DNS...")
    message = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(message,(ip, port))
        data, _ = sock.recvfrom(512)
        return True
    except Exception as e:
        return False
    finally:
        sock.close()

## UDP SERVICE  3 ##
def check_SIP(ip, port):
    print(f"{port} : checking SIP...")
    try:
        sip_options_msg = \
        'OPTIONS sip:{} SIP/2.0\r\n' \
        'Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK-524287-1---0000000000000000\r\n' \
        'Max-Forwards: 70\r\n' \
        'Contact: <sip:{}>\r\n' \
        'To: <sip:{}>\r\n' \
        'From: anonymous<sip:anonymous@anonymous.invalid>;tag=0000000000000000\r\n' \
        'Call-ID: 00000000000000000000000000000000@anonymous.invalid\r\n' \
        'CSeq: 1 OPTIONS\r\n' \
        'Accept: application/sdp\r\n' \
        'Content-Length: 0\r\n\r\n'.format(ip, ip, ip, ip)
        # UDP 소켓 생성 및 SIP 서버로 메시지 전송
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        sock.sendto(sip_options_msg.encode(), (ip, port)) 
        data, addr = sock.recvfrom(4096) #최대로 받을 양 4096 바이트(버퍼크기)
        return True
        
    except Exception as e:
        return False
    finally:
        sock.close() #리소스 해제
        return False
def tcpBannerGrab(ip, port):
    try:
        # HTTP 소켓 통신시 오류 발생하므로 우선 체크 추후 변경
        httpCheck = http_banner_grabbing(ip,port)
        if httpCheck == "http:":
            return "http"
        elif httpCheck == "https":
            return "https"
        
        service = 'Unknown'
        
        if(checkMySQL(ip, port)):
            service = "mysql" 
        elif(checkSSH(ip, port)):
            service = "ssh"
        elif(checkFTP(ip, port)):
            service = "ftp"
        elif(checkTelnet(ip, port)):
            service = 'telnet'
        elif(check_SMTP(ip, port)):
            service = 'smtp'
        elif(check_RDP(ip, port)):
            service = 'RDP'
        elif(check_imap(ip, port)):
            service = "IMAP(S)"
        elif(checkSMB(ip,port)):
            service = 'SMB'
        elif(X(ip, port)):
            service = 'etc..'

        if service is not None:
            print(f"{ip} : {port} : {service}")
        return service
    
    except Exception as e:
        return 'Unknown'


def udpBannergrab(ip, port):
    service = None
    try:
        if (check_NTP(ip, port)):
            service = "ntp"
        elif (check_DNS(ip, port)):
            service = "dns"
        elif (check_SIP(ip, port)):
            service = "sip"

        if service is not None:
            print(f"{ip} : {port} : {service}")
            return service
    except Exception as e:
            return "대상 컴퓨터에서 연결을 거부"


def ServiceScan(ip, ports, protocol="tcp"):
    services = []
    if protocol == "tcp":
        for port in ports:
            service = tcpBannerGrab(ip, port)
            services.append([port,service])
    elif protocol == "udp":
        for port in ports:
            service = udpBannergrab(ip, port)
            services.append([port,service])
    
    return services
