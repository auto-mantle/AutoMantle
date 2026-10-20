#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID != 0 || $# != 6 ]]; then
  echo 'Usage: sudo bash tests/network-policy-smoke.sh GATEWAY KERNEL RAW_EXT4 HYPERVISOR APP_JAR JAVA' >&2; exit 2
fi
binary=$(realpath "$1"); kernel=$(realpath "$2"); rootfs=$(realpath "$3")
hypervisor=$(realpath "$4"); jar=$(realpath "$5"); java=$(realpath "$6")
if ss -ltnH 'sport = :8083' | grep -q .; then echo 'Port 8083 already in use' >&2; exit 1; fi
fixture=$(mktemp -d /run/automantle-network-smoke.XXXXXXXX)
chmod 700 "$fixture"
app_pid=; gateway_pid=; run_id=
cleanup() {
  if [[ -n $gateway_pid ]]; then "$binary" stop --socket "$fixture/control.sock" >/dev/null 2>&1 || true; wait "$gateway_pid" || true; fi
  if [[ -n $app_pid ]]; then kill "$app_pid" 2>/dev/null || true; wait "$app_pid" || true; fi
  if [[ -n $run_id ]]; then
    local pid; pid=$(systemctl show "$run_id" --property=MainPID --value)
    if [[ $pid =~ ^[0-9]+$ && $pid != 0 ]]; then echo "Preserving active VM fixture: $fixture" >&2; return; fi
  fi
  if findmnt -rn -o SOURCE,TARGET | grep -Fq "$fixture"; then echo "Preserving mounted fixture: $fixture" >&2; return; fi
  [[ $(realpath "$fixture") == /run/automantle-network-smoke.* ]] && rm -rf -- "$fixture"
}
trap cleanup EXIT
source_hash=$(sha256sum "$rootfs")
cd "$fixture"
AUTOMANTLE_DATA_DIR="$fixture/data" "$java" --enable-native-access=ALL-UNNAMED -jar "$jar" --server.port=8083 --spring.config.import= --app.gateway.socket="$fixture/control.sock" >app.log 2>&1 & app_pid=$!
for _ in {1..100}; do if curl -fsS http://127.0.0.1:8083/csrf >/dev/null 2>&1; then break; fi; sleep .2; done
python3 - "$fixture" <<'PY'
import json,sys,urllib.request,http.cookiejar,pathlib
fixture=pathlib.Path(sys.argv[1]); session=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base='http://127.0.0.1:8083'
def request(path,value=None):
    headers={'Content-Type':'application/json'}
    if value is not None:
        csrf=json.load(session.open(base+'/csrf'));headers[csrf['headerName']]=csrf['token']
    return json.load(session.open(urllib.request.Request(base+path,data=None if value is None else json.dumps(value).encode(),headers=headers)))
profile=request('/agents/profiles',{'name':'network policy smoke'})['id']
request('/agents/profiles/'+profile+'/rules',{'effect':'ALLOW','match':{'resource_type':'http','action':['get'],'hosts':['example.com'],'resource':['/*']}})
(fixture/'profile').write_text(profile)
(fixture/'gateway.json').write_text(json.dumps({'backendUrl':base}))
(fixture/'tls.json').write_text(json.dumps({'caCertificate':str(fixture/'ca.pem'),'caPrivateKey':str(fixture/'ca.key')}))
PY
chmod 600 gateway.json tls.json
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Automantle-Network-Smoke -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout ca.key -out ca.pem >/dev/null 2>&1
chmod 600 ca.key
cp --reflink=auto --sparse=always "$rootfs" guest.ext4
cat >guest-probes.c <<'C'
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
static unsigned short checksum(unsigned char *b, int n) { unsigned int s=0;for(int i=0;i<n;i+=2)s+=(b[i]<<8)|(i+1<n?b[i+1]:0);while(s>>16)s=(s&65535)+(s>>16);return (unsigned short)~s; }
int main(int argc,char **argv) {
  if(argc!=2)return 2;
  int fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);if(fd<0){perror("icmp socket");return 3;}
  struct sockaddr_in target={.sin_family=AF_INET};inet_pton(AF_INET,"1.1.1.1",&target.sin_addr);
  unsigned char echo[8]={8,0,0,0,0,1,0,1};unsigned short c=checksum(echo,8);echo[2]=c>>8;echo[3]=c;
  if(sendto(fd,echo,8,0,(struct sockaddr*)&target,sizeof(target))!=8)return 4;close(fd);
  fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));if(fd<0)return 5;
  struct ifreq request={0};strcpy(request.ifr_name,"eth0");if(ioctl(fd,SIOCGIFHWADDR,&request)<0)return 6;
  struct sockaddr_ll address={.sll_family=AF_PACKET,.sll_ifindex=if_nametoindex("eth0"),.sll_halen=6};
  unsigned int mac[6];if(sscanf(argv[1],"%x:%x:%x:%x:%x:%x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5])!=6)return 7;
  unsigned char packet[64]={0};for(int i=0;i<6;i++){packet[i]=(unsigned char)mac[i];address.sll_addr[i]=packet[i];}
  memcpy(packet+6,request.ifr_hwaddr.sa_data,6);
  packet[12]=0x88;packet[13]=0xb5;if(sendto(fd,packet,60,0,(struct sockaddr*)&address,sizeof(address))!=60)return 8;
  packet[12]=0x81;packet[13]=0;packet[14]=0;packet[15]=1;packet[16]=0x88;packet[17]=0xb5;
  if(sendto(fd,packet,64,0,(struct sockaddr*)&address,sizeof(address))!=64)return 9;
  memset(packet+14,0,50);packet[12]=0x86;packet[13]=0xdd;packet[14]=0x60;packet[20]=59;
  inet_pton(AF_INET6,"fe80::1",packet+22);inet_pton(AF_INET6,"2606:4700:4700::1111",packet+38);
  if(sendto(fd,packet,54,0,(struct sockaddr*)&address,sizeof(address))!=54)return 10;
  close(fd);return 0;
}
C
cc -static -O2 guest-probes.c -o guest-probes
chmod 755 guest-probes
cat >guest-init <<'GUEST'
#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
for argument in $(cat /proc/cmdline); do case "$argument" in ip=*) config=${argument#ip=};; automantle_proxy=*) proxy=${argument#automantle_proxy=};; esac; done
guest_ip=${config%%:*}; remaining=${config#*::}; host_ip=${remaining%%:*}
ip link set eth0 up
ip addr add "$guest_ip/30" dev eth0 2>/dev/null || true
ip route replace default via "$host_ip"
export http_proxy="$proxy" https_proxy="$proxy" HTTP_PROXY="$proxy" HTTPS_PROXY="$proxy"
fail() { echo "NET_POLICY_FAIL $1"; sync; poweroff -f; sleep 20; }
code=$(curl --http1.1 -sS -m 25 -o /dev/null -w '%{http_code}' http://example.com/) || fail http
[ "$code" = 200 ] || fail "http-status-$code"
echo NET_POLICY_HTTP_PASS
code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 25 -o /dev/null -w '%{http_code}' https://example.com/) || fail https
[ "$code" = 200 ] || fail "https-status-$code"
echo NET_POLICY_HTTPS_PASS
code=$(curl --http1.1 -sS -m 10 -o /dev/null -w '%{http_code}' http://www.google.com/) || fail deny
[ "$code" = 403 ] || fail "deny-status-$code"
echo NET_POLICY_DENY_PASS
curl -sS -m 2 -x '' -o /dev/null http://1.1.1.1/ && fail direct-tcp
/bin/bash -c 'printf synthetic-network-test >/dev/udp/1.1.1.1/443' || true
host_mac=$(ip neigh show "$host_ip" dev eth0 | awk '{for(i=1;i<=NF;i++)if($i=="lladdr"){print $(i+1);exit}}')
/network-probes "$host_mac" || fail raw-probes

if [ -f /test-credentials-enabled ]; then
  stty -F /dev/ttyS0 -echo
  code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 25 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' https://example.com/) || fail credential-profile
  [ "$code" = 403 ] || fail "credential-profile-$code"
  echo NET_CREDENTIAL_BIND_READY
  IFS= read -r next </dev/ttyS0
  code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 25 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' -H 'X-API-Key: EXAMPLE_KEY' https://example.com/) || fail credential-add
  [ "$code" = 200 ] || fail "credential-add-$code"
  echo NET_CREDENTIAL_ADDED
  for target in http://example.com/ https://example.com/not-allowed https://www.example.com/;do
    code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 15 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' "$target") || fail credential-scope
    [ "$code" = 403 ] || fail "credential-scope-$code"
  done
  code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 15 -X POST -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' https://example.com/) || fail credential-method
  [ "$code" = 403 ] || fail "credential-method-$code"
  echo NET_CREDENTIAL_SCOPE_PASS
  stty -F /dev/ttyS0 -echo
  echo NET_CREDENTIAL_ROTATE_READY
  IFS= read -r next </dev/ttyS0
  code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 25 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' https://example.com/) || fail credential-rotate
  [ "$code" = 200 ] || fail "credential-rotate-$code"
  echo NET_CREDENTIAL_ROTATED
  echo NET_CREDENTIAL_DELETE_READY
  IFS= read -r next </dev/ttyS0
  code=$(curl --http1.1 --cacert /network-ca.pem -sS -m 15 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer EXAMPLE_TOKEN' https://example.com/) || fail credential-delete
  [ "$code" = 403 ] || fail "credential-delete-$code"
  echo NET_CREDENTIAL_DELETED
fi

sleep 2
echo NET_POLICY_PASS
sync
poweroff -f
sleep 20
GUEST
chmod 755 guest-init
debugfs -w -R "write $fixture/guest-init /network-policy-init" guest.ext4 >/dev/null 2>&1
debugfs -w -R 'set_inode_field /network-policy-init mode 0100755' guest.ext4 >/dev/null 2>&1
debugfs -w -R "write $fixture/guest-probes /network-probes" guest.ext4 >/dev/null 2>&1
debugfs -w -R 'set_inode_field /network-probes mode 0100755' guest.ext4 >/dev/null 2>&1
debugfs -w -R "write $fixture/ca.pem /network-ca.pem" guest.ext4 >/dev/null 2>&1
debugfs -w -R 'mkdir /mnt' guest.ext4 >/dev/null 2>&1 || true
if [[ ${AUTOMANTLE_TEST_CREDENTIALS:-0} == 1 ]];then
 printf 'enabled\n' > credentials-enabled
 debugfs -w -R "write $fixture/credentials-enabled /test-credentials-enabled" guest.ext4 >/dev/null 2>&1
fi

"$binary" start --gateway-config "$fixture/gateway.json" --cloud-hypervisor "$hypervisor" --socket "$fixture/control.sock" --disk-directory "$fixture/disks" >gateway.log 2>&1 & gateway_pid=$!
for _ in {1..50}; do [[ -S control.sock ]] && break; sleep .1; done
if [[ ${AUTOMANTLE_TEST_CREDENTIALS:-0} == 1 ]];then
python3 - "$fixture" <<'CREDENTIALS'
import json,sys,pathlib,urllib.request,http.cookiejar,urllib.error
f=pathlib.Path(sys.argv[1]);base='http://127.0.0.1:8083';opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,value=None,method='GET'):
 headers={}
 if method!='GET':
  csrf=json.load(opener.open(base+'/csrf'));headers[csrf['headerName']]=csrf['token']
 if value is not None:headers['Content-Type']='application/json'
 request=urllib.request.Request(base+path,data=None if value is None else json.dumps(value).encode(),headers=headers,method=method)
 with opener.open(request,timeout=20) as r:return json.load(r) if r.status!=204 else None
profile=(f/'profile').read_text()
for methods,hosts in [(['post'],['example.com']),(['get'],['www.example.com'])]:
 api('/agents/profiles/'+profile+'/rules',{'effect':'ALLOW','match':{'resource_type':'http','action':methods,'hosts':hosts,'resource':['/*']}},'POST')
other_profile=api('/agents/profiles',{'name':'other credential scope'},'POST')['id']
for name,header in [('EXAMPLE_TOKEN','authorization'),('EXAMPLE_KEY','x-api-key')]:
 bound_profile=other_profile if name=='EXAMPLE_TOKEN' else profile
 value={'name':name,'secret':'synthetic-original-credential-123456','scopes':[{'agentProfileId':bound_profile,'host':'example.com','paths':['/'],'location':'header','selector':header}]}
 saved=api('/credentials',value,'POST');assert 'secret' not in saved and saved['name']==name
 api('/agents/profiles/'+bound_profile+'/rules',{'effect':'ALLOW','match':{'resource_type':'http','action':['get'],'hosts':['example.com'],'resource':['/']}},'POST')
assert 'synthetic-original' not in json.dumps(api('/credentials'))
try:
 api('/credentials',{'name':'BAD','secret':'synthetic private rejected 123456'},'POST')
 raise AssertionError('Invalid credential accepted')
except urllib.error.HTTPError as e:assert e.code==400 and 'synthetic-private' not in e.read().decode()
CREDENTIALS
fi

profile=$(cat profile)
run_id=$("$binary" launch --socket "$fixture/control.sock" --kernel "$kernel" --rootfs "$fixture/guest.ext4" --agent-profile-id "$profile" --network proxy --tls-ca-config "$fixture/tls.json" --timeout-seconds 240 --cmdline 'console=ttyS0 root=/dev/vda rootfstype=ext4 ro reboot=k panic=1 init=/network-policy-init' | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
if [[ ${AUTOMANTLE_TEST_CREDENTIALS:-0} == 1 ]];then
python3 - "$fixture" "$run_id" <<'CREDENTIALS'
import socket,json,time,sys,pathlib,urllib.request,http.cookiejar
f=pathlib.Path(sys.argv[1]);run=sys.argv[2];base='http://127.0.0.1:8083';opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def command(v):
 s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(str(f/'control.sock'));s.sendall(json.dumps(v).encode()+b'\n')
 with s,s.makefile() as r:
  response=json.loads(r.readline());assert 'error' not in response,response;return response['result']
def wait(marker):
 deadline=time.monotonic()+80
 while time.monotonic()<deadline:
  text=command({'command':'logs','id':run})['console']
  if 'NET_POLICY_FAIL' in text:raise AssertionError('Guest credential test failed')
  if marker in text:return
  time.sleep(.2)
 raise AssertionError('Guest credential phase timed out: '+marker)
def api(path,value=None,method='GET'):
 headers={}
 if method!='GET':
  csrf=json.load(opener.open(base+'/csrf'));headers[csrf['headerName']]=csrf['token']
 if value is not None:headers['Content-Type']='application/json'
 with opener.open(urllib.request.Request(base+path,data=None if value is None else json.dumps(value).encode(),headers=headers,method=method)) as r:
  return json.load(r) if r.status!=204 else None
wait('NET_CREDENTIAL_BIND_READY')
profile=(f/'profile').read_text()
entry=next(v for v in api('/credentials') if v['name']=='EXAMPLE_TOKEN')
entry['scopes']=[{'agentProfileId':profile,'host':'example.com','paths':['/'],'location':'header','selector':'authorization'}]
api('/credentials/EXAMPLE_TOKEN',entry,'PUT')
api('/agents/profiles/'+profile+'/rules',{'effect':'ALLOW','match':{'resource_type':'http','action':['get'],'hosts':['example.com'],'resource':['/']}},'POST')
command({'command':'terminal-write','id':run,'data':[10]})
wait('NET_CREDENTIAL_ROTATE_READY')
entry=next(v for v in api('/credentials') if v['name']=='EXAMPLE_TOKEN');entry['secret']='synthetic-rotated-credential-654321'
api('/credentials/EXAMPLE_TOKEN',entry,'PUT')
command({'command':'terminal-write','id':run,'data':[10]})
wait('NET_CREDENTIAL_DELETE_READY')
api('/credentials/EXAMPLE_TOKEN',method='DELETE')
command({'command':'terminal-write','id':run,'data':[10]})
wait('NET_CREDENTIAL_DELETED')
assert 'EXAMPLE_TOKEN' not in [v['name'] for v in api('/credentials')]
print('REAL_VM_CREDENTIALS_PASS: named Bearer/API-key, HTTPS/profile/host/path/method scopes, live rotation and deletion',flush=True)
CREDENTIALS
fi

for _ in {1..110}; do
  "$binary" logs "$run_id" --socket "$fixture/control.sock" >console.json
  if python3 -c 'import json,sys;v=json.load(open(sys.argv[1]));sys.exit(0 if v["state"] in ["stopped","failed"] else 1)' console.json; then break; fi
  sleep 1
done
python3 - "$fixture" <<'PY'
import json,sys,pathlib,urllib.request
fixture=pathlib.Path(sys.argv[1]);console=json.loads((fixture/'console.json').read_text())
assert 'NET_POLICY_PASS' in console['console'] and 'NET_POLICY_FAIL' not in console['console'],console
profile=(fixture/'profile').read_text();rows=json.load(urllib.request.urlopen('http://127.0.0.1:8083/request-history?agentProfileId='+profile))['items']
for protocol in ['TCP','UDP','ICMP']:
    assert any(r['protocol']==protocol and r['destinationIp']=='1.1.1.1' and r['result']=='DENIED' for r in rows),(protocol,rows)
for protocol in ['UNKNOWN','VLAN','IPV6']:
    assert any(r['protocol']==protocol and r['result']=='DENIED' for r in rows),(protocol,rows)
assert any(r['result']=='INSPECTED' and r['port']==3128 for r in rows),rows
assert any(r['host']=='example.com' and r['port']==443 and r['result']=='ALLOWED' for r in rows),rows
assert any(r['host']=='www.google.com' and r['result']=='DENIED' for r in rows),rows
assert all(r['packetCount'] is None or r['packetCount']>0 for r in rows),rows
import os,sqlite3
if os.environ.get('AUTOMANTLE_TEST_CREDENTIALS')=='1':
    protected=['synthetic-original-credential-123456','synthetic-rotated-credential-654321','synthetic-private-rejected-123456']
    connection=sqlite3.connect(fixture/'data'/'automantle.sqlite')
    stored='\n'.join(connection.iterdump())
    logs=''.join((fixture/name).read_text(errors='replace') for name in ['app.log','gateway.log'])
    assert all(secret not in stored and secret not in logs for secret in protected)
    print('REAL_VM_SECRET_PRIVACY_PASS: stored values absent from SQLite and process logs')
print('REAL_VM_NETWORK_POLICY_PASS: HTTP, HTTPS, default deny, direct TCP/UDP/ICMP audit')
PY
[[ $(sha256sum "$rootfs") == "$source_hash" ]]
