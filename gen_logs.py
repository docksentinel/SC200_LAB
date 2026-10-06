import random, re
from datetime import datetime, timedelta, timezone
random.seed(42)
base = datetime(2026,10,6,10,0,0,tzinfo=timezone.utc)
ev = []  # (time, action, src, dst, dpt, user, kind)
def add(t,**k): ev.append(dict(t=t,**k))
# 1 trafic normal
for i in range(20):
    add(base+timedelta(seconds=30*i), kind="traffic", act="accept", src=f"10.0.0.{random.randint(20,60)}",
        dst=random.choice(["142.250.74.46","13.107.42.14"]), dpt=random.choice([80,443]), user="-")
# 2 force brute admin
for i in range(15):
    add(base+timedelta(minutes=5,seconds=8*i), kind="login", act="failed", src="203.0.113.45", dst="10.0.0.1", dpt=443, user="admin")
# 3 utilisateur legitime
for i,a in enumerate(["failed","failed","success"]):
    add(base+timedelta(minutes=10,seconds=20*i), kind="login", act=a, src="10.0.0.15", dst="10.0.0.1", dpt=443, user="alice")
# 4 password spraying
for i in range(15):
    add(base+timedelta(minutes=15,seconds=10*i), kind="login", act="failed", src="192.0.2.99", dst="10.0.0.1", dpt=443, user=f"user{i:02d}")
# 5 scan de ports
for i,p in enumerate(range(20,36)):
    add(base+timedelta(minutes=20,seconds=i), kind="traffic", act="deny", src="198.51.100.77", dst="10.0.0.10", dpt=p, user="-")
ev.sort(key=lambda e:e["t"])
syslog=[];cef=[]
for e in ev:
    ts=e["t"].strftime("%Y-%m-%d"); tm=e["t"].strftime("%H:%M:%S")
    if e["kind"]=="traffic":
        syslog.append(f'date={ts} time={tm} devname="fw-lab" type="traffic" subtype="forward" action="{e["act"]}" srcip={e["src"]} dstip={e["dst"]} dstport={e["dpt"]} proto=6')
        cef.append(f'CEF:0|Fortinet|Fortigate|v7.4.0|13056|traffic:forward {e["act"]}|5|rt={int(e["t"].timestamp()*1000)} src={e["src"]} dst={e["dst"]} dpt={e["dpt"]} act={e["act"]} proto=6')
    else:
        lvl="alert" if e["act"]=="failed" else "information"
        syslog.append(f'date={ts} time={tm} devname="fw-lab" type="event" subtype="user" level="{lvl}" logid="0100032002" action="login" status="{e["act"]}" user="{e["user"]}" srcip={e["src"]} dstip={e["dst"]} dstport={e["dpt"]}')
        cef.append(f'CEF:0|Fortinet|Fortigate|v7.4.0|32002|Admin login {e["act"]}|{7 if e["act"]=="failed" else 3}|rt={int(e["t"].timestamp()*1000)} src={e["src"]} dst={e["dst"]} dpt={e["dpt"]} suser={e["user"]} act=login outcome={e["act"]}')
open("fortigate_syslog.log","w").write("\n".join(syslog)+"\n")
open("firewall_cef.log","w").write("\n".join(cef)+"\n")
# controle
def parse_cef(l):
    p=l.split("|",7); d=dict(re.findall(r'(\w+)=(\S+)',p[7])); d["name"]=p[5]; return d
def parse_sys(l): return dict(re.findall(r'(\w+)="?([^"\s]+)"?',l))
c=[parse_cef(l) for l in cef]; s=[parse_sys(l) for l in syslog]
assert len(c)==len(s)==len(ev)==69
bf=sum(1 for x in c if x.get("outcome")=="failed" and x["src"]=="203.0.113.45")
sp={x["suser"] for x in c if x.get("outcome")=="failed" and x["src"]=="192.0.2.99"}
sc=sum(1 for x in c if x["src"]=="198.51.100.77")
print("lignes",len(ev),"| brute force admin:",bf,"| spraying comptes:",len(sp),"| scan ports:",sc)
