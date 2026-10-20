#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID != 0 || $# != 6 ]]; then
 echo 'Usage: sudo bash tests/persistent-vm-smoke.sh GATEWAY KERNEL CLEAN_LINUX_EXT4 HYPERVISOR APP_JAR JAVA' >&2; exit 2
fi
binary=$(realpath "$1");kernel=$(realpath "$2");base=$(realpath "$3")
hypervisor=$(realpath "$4");jar=$(realpath "$5");java=$(realpath "$6")
if ss -ltnH 'sport = :8083' | grep -q .; then echo 'Port 8083 is occupied' >&2;exit 1;fi
fixture=$(mktemp -d /var/lib/automantle-persistent-smoke.XXXXXXXX)
chmod 0700 "$fixture"
app_pid=;gateway_pid=
cleanup() {
 if [[ -n $gateway_pid ]]; then "$binary" stop --socket "$fixture/control.sock" >/dev/null 2>&1 || true;wait "$gateway_pid" || true;fi
 if [[ -n $app_pid ]]; then kill "$app_pid" 2>/dev/null || true;wait "$app_pid" || true;fi
 if findmnt -rn -o SOURCE,TARGET | grep -Fq "$fixture";then echo "Preserving mounted fixture $fixture" >&2;return;fi
 if pgrep -af cloud-hypervisor | grep -Fq "$fixture";then echo "Preserving active fixture $fixture" >&2;return;fi
 [[ $(realpath "$fixture") == /var/lib/automantle-persistent-smoke.* ]] && rm -rf -- "$fixture"
}
trap cleanup EXIT
printf '{"backendUrl":"http://127.0.0.1:8083"}\n' > "$fixture/gateway.json"
chmod 0600 "$fixture/gateway.json"
AUTOMANTLE_DATA_DIR="$fixture/data" "$java" -Djava.net.preferIPv4Stack=true --enable-native-access=ALL-UNNAMED -jar "$jar" --server.port=8083 --spring.config.import= --app.gateway.socket="$fixture/control.sock" >"$fixture/app.log" 2>&1 & app_pid=$!
for _ in {1..100}; do if curl -fsS http://127.0.0.1:8083/csrf >/dev/null 2>&1;then break;fi;sleep .2;done
start_gateway() {
 "$binary" start --gateway-config "$fixture/gateway.json" --cloud-hypervisor "$hypervisor" --default-kernel "$kernel" --default-rootfs "$base" --socket "$fixture/control.sock" --disk-directory "$fixture/vms" >"$fixture/gateway.log" 2>&1 & gateway_pid=$!
 for _ in {1..50};do [[ -S "$fixture/control.sock" ]] && return;sleep .1;done
 return 1
}
start_gateway
python3 - "$fixture" <<'PY'
import json,sys,time,urllib.request,urllib.error,http.cookiejar,pathlib
fixture=pathlib.Path(sys.argv[1]);opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));url='http://127.0.0.1:8083'
def api(path,value=None,method=None):
 headers={}
 if value is not None or method in ('POST','PUT','DELETE'):
  csrf=json.load(opener.open(url+'/csrf'));headers[csrf['headerName']]=csrf['token']
 if value is not None: headers['Content-Type']='application/json'
 request=urllib.request.Request(url+path,data=None if value is None else json.dumps(value).encode(),headers=headers,method=method)
 with opener.open(request,timeout=125) as response:return json.load(response)
def vm(id):return next(v for v in api('/vms') if v['id']==id)
def wait(id,state,seconds=60):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  v=vm(id)
  if v['state']==state:return v
  if v['state']=='failed':raise AssertionError(v)
  time.sleep(.2)
 raise AssertionError(('VM state timeout',vm(id),state))
def terminal(id):
 v=wait(id,'running');run=v['runId'];offset=0;text='';until=time.monotonic()+60
 while time.monotonic()<until:
  r=api('/vms/'+run+'/terminal?offset='+str(offset));offset=r['next'];text+=bytes(r['data']).decode(errors='replace')
  if 'agent@' in text and '$' in text:return run,offset
  time.sleep(.2)
 raise AssertionError('Guest shell did not become ready: '+text[-800:])
def command(run,offset,command,marker):
 api('/vms/'+run+'/terminal/input',{'data':list((command+'\r').encode())},'POST');text='';until=time.monotonic()+30
 while time.monotonic()<until:
  r=api('/vms/'+run+'/terminal?offset='+str(offset));offset=r['next'];text+=bytes(r['data']).decode(errors='replace')
  if marker in text.splitlines():return offset
  time.sleep(.2)
 raise AssertionError('Guest command failed: '+text[-1000:])
profile=api('/agents/profiles',{'name':'Persistent VM smoke'},'POST')['id']
settings={'name':'First','agentProfileId':profile,'memoryMib':512,'vcpuCount':1,'setup':False}
first=api('/vms',settings,'POST');id=first['id']
(fixture/'first-id').write_text(id)
api('/vms/'+id+'/start',method='POST');run,offset=terminal(id)
offset=command(run,offset,"printf 'saved-progress\\n' > ~/project/progress.txt; sync; echo SAVED_PROGRESS",'SAVED_PROGRESS')
try:api('/vms/'+id+'/copy',{'name':'Busy copy'},'POST');raise AssertionError('Copy of running VM accepted')
except urllib.error.HTTPError as e:assert e.code==400
api('/vms/'+id+'/stop',method='POST');wait(id,'stopped')
api('/vms/'+id+'/start',method='POST');run,offset=terminal(id)
command(run,offset,'test "$(cat ~/project/progress.txt)" = saved-progress && echo RESTART_PROGRESS','RESTART_PROGRESS')
api('/vms/'+id+'/stop',method='POST');wait(id,'stopped')
copy=api('/vms/'+id+'/copy',{'name':'Independent copy'},'POST');copyid=copy['id']
(fixture/'copy-id').write_text(copyid)
settings['name']='Renamed';settings['memoryMib']=768
api('/vms/'+copyid,settings,'PUT')
assert vm(copyid)['memoryMib']==768
api('/vms/'+id+'/start',method='POST');run,offset=terminal(id)
api('/vms/'+copyid+'/start',method='POST');copyrun,copyoffset=terminal(copyid)
command(copyrun,copyoffset,"printf 'copy-progress\\n' > ~/project/progress.txt; sync; echo COPY_CHANGED",'COPY_CHANGED')
command(run,offset,'test "$(cat ~/project/progress.txt)" = saved-progress && echo ORIGINAL_UNCHANGED','ORIGINAL_UNCHANGED')
for machine in (id,copyid):api('/vms/'+machine+'/stop',method='POST');wait(machine,'stopped')
print('PASS: create, clean stop/start, independent concurrent copy, edit, and busy-copy denial',flush=True)
PY
"$binary" stop --socket "$fixture/control.sock" >/dev/null
wait "$gateway_pid";gateway_pid=
start_gateway
python3 - "$fixture" <<'PY'
import json,sys,pathlib,urllib.request,http.cookiejar,time
f=pathlib.Path(sys.argv[1]);opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));base='http://127.0.0.1:8083'
def api(path,method='GET'):
 headers={}
 if method!='GET':
  csrf=json.load(opener.open(base+'/csrf'));headers[csrf['headerName']]=csrf['token']
 return json.load(opener.open(urllib.request.Request(base+path,headers=headers,method=method)))
first=(f/'first-id').read_text();copy=(f/'copy-id').read_text()
vms=api('/vms');assert len(vms)==2 and all(v['state']=='stopped' for v in vms)
assert next(v for v in vms if v['id']==copy)['name']=='Renamed'
import subprocess
for id,expected in [(first,'saved-progress'),(copy,'copy-progress')]:
 text=subprocess.check_output(['debugfs','-R','cat /home/agent/project/progress.txt',str(f/'vms'/id/'rootfs')],stderr=subprocess.DEVNULL).decode().strip()
 assert text==expected,(id,text)
api('/vms/'+copy,'DELETE')
assert [v['id'] for v in api('/vms')]==[first]
api('/vms/'+first,'DELETE');assert api('/vms')==[]
print('PASS: definitions/files survive gateway restart; explicit delete removes only chosen VM',flush=True)
PY
echo 'PERSISTENT_VM_SMOKE_PASS'
