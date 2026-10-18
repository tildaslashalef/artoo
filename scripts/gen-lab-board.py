#!/usr/bin/env python3
"""Generate src/watch/dashboards/lab.json, the Proxmox · Homelab board that
`artoo watch setup` provisions as Grafana's home page (SPEC §9.9).

    scripts/gen-lab-board.py > src/watch/dashboards/lab.json

Queries use the data sources' provisioned UIDs (victoriametrics, loki) and
the metric names recorded in SPEC §9.9. Edit here, not the JSON.
"""
import json
VM={"type":"prometheus","uid":"victoriametrics"}
LOKI={"type":"loki","uid":"loki"}
panels=[]; pid=[0]; y=[0]
def nid():
    pid[0]+=1; return pid[0]
def row(title, collapsed=False, inner=None):
    p={"id":nid(),"type":"row","title":title,"collapsed":collapsed,"gridPos":{"x":0,"y":y[0],"w":24,"h":1},"panels":inner or []}
    y[0]+=1; return p
def tgt(expr, legend="", ref="A", instant=False, fmt=None, ds=VM):
    t={"refId":ref,"expr":expr,"legendFormat":legend,"datasource":ds}
    if instant: t["instant"]=True; t["range"]=False
    if fmt: t["format"]=fmt
    return t
def steps(*pairs):
    return {"mode":"absolute","steps":[{"color":c,"value":v} for v,c in pairs]}
GOOD=steps((None,"green"))
def stat(title, expr, x, w, unit="none", th=GOOD, decimals=None, mappings=None, desc="", spark=True, minv=None, maxv=None):
    d={"unit":unit,"thresholds":th,"color":{"mode":"thresholds"}}
    if decimals is not None: d["decimals"]=decimals
    if mappings: d["mappings"]=mappings
    if minv is not None: d["min"]=minv
    if maxv is not None: d["max"]=maxv
    return {"id":nid(),"type":"stat","title":title,"description":desc,"datasource":VM,"gridPos":{"x":x,"y":y[0],"w":w,"h":4},
            "targets":[tgt(expr)],"fieldConfig":{"defaults":d,"overrides":[]},
            "options":{"reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":False},"colorMode":"background","graphMode":"area" if spark else "none","justifyMode":"center","textMode":"value","wideLayout":True,"showPercentChange":False}}
def gauge(title, expr, x, w, h=4, th=None):
    return {"id":nid(),"type":"gauge","title":title,"datasource":VM,"gridPos":{"x":x,"y":y[0],"w":w,"h":h},
            "targets":[tgt(expr)],"fieldConfig":{"defaults":{"unit":"percentunit","min":0,"max":1,"decimals":1,"thresholds":th or steps((None,"green"),(0.75,"yellow"),(0.9,"red")),"color":{"mode":"thresholds"}},"overrides":[]},
            "options":{"reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":False},"showThresholdLabels":False,"showThresholdMarkers":True,"minVizHeight":75,"minVizWidth":75,"sizing":"auto"}}
def ts(title, targets, x, w, h=8, unit="none", stack=False, fill=12, minv=None, maxv=None, overrides=None, desc="", ds=VM, draw="line"):
    custom={"drawStyle":draw,"lineWidth":2,"fillOpacity":fill,"gradientMode":"opacity","showPoints":"never","spanNulls":True,"lineInterpolation":"smooth","axisSoftMin":0,
            "stacking":{"mode":"normal" if stack else "none","group":"A"}}
    if draw=="bars": custom.update({"lineWidth":1,"fillOpacity":80,"gradientMode":"none"})
    d={"unit":unit,"custom":custom,"color":{"mode":"palette-classic"}}
    if minv is not None: d["min"]=minv
    if maxv is not None: d["max"]=maxv
    return {"id":nid(),"type":"timeseries","title":title,"description":desc,"datasource":ds,"gridPos":{"x":x,"y":y[0],"w":w,"h":h},
            "targets":targets,"fieldConfig":{"defaults":d,"overrides":overrides or []},
            "options":{"legend":{"displayMode":"list","placement":"bottom","showLegend":True},"tooltip":{"mode":"multi","sort":"desc"}}}
def adv(h): y[0]+=h

# a probe's service name, from Alloy's job "integrations/blackbox/<service>"
def by_service(expr):
    return 'label_replace(%s, "service", "$1", "job", "integrations/blackbox/(.+)")' % expr
SVC_UP='sort_by_label(max by (service) (%s), "service")' % by_service("probe_success")

# templates have system_template 1; guests 0
GUEST='and on (vmid) (system_template{object="qemu"} == 0)'

# ---------------- Overview
panels.append(row("Overview"))
okth=steps((None,"red"),(1,"green"))
zero_good=steps((None,"green"),(1,"red"))
def multistat(title, targets, x, w, unit, desc=""):
    return {"id":nid(),"type":"stat","title":title,"description":desc,"datasource":VM,"gridPos":{"x":x,"y":y[0],"w":w,"h":4},
            "targets":targets,"fieldConfig":{"defaults":{"unit":unit,"decimals":1,"thresholds":steps((None,"blue")),"color":{"mode":"thresholds"}},
            "overrides":[{"matcher":{"id":"byName","options":"available"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"green"}}]},
                         {"matcher":{"id":"byName","options":"used"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"orange"}}]},
                         {"matcher":{"id":"byName","options":"ZFS ARC"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"purple"}}]},
                         {"matcher":{"id":"byName","options":"total"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"text"}}]}]},
            "options":{"reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":False},"colorMode":"value","graphMode":"none","justifyMode":"center","textMode":"value_and_name","wideLayout":True,"orientation":"vertical","showPercentChange":False}}
panels+= [
 stat("Proxmox CPU",'cpustat_cpu{object="nodes"}',0,4,"percentunit",steps((None,"green"),(0.7,"yellow"),(0.9,"red")),1),
 gauge("Proxmox memory",'memory_memused{object="nodes"} / memory_memtotal{object="nodes"}',4,4),
 multistat("Proxmox memory (GiB)",[tgt('memory_memused{object="nodes"}',"used"),tgt('memory_memavailable{object="nodes"}',"available","B"),
           tgt('memory_arcsize{object="nodes"}',"ZFS ARC","C"),tgt('memory_memtotal{object="nodes"}',"total","D")],8,8,"bytes",
           desc="Used includes the ZFS ARC, a cache ZFS gives back under pressure"),
 stat("Load (1 min)",'cpustat_avg1{object="nodes"}',16,4,"none",steps((None,"green"),(16,"yellow"),(28,"red")),2,desc="Proxmox has 32 threads"),
 stat("Failed units",'sum(node_systemd_unit_state{state="failed"}) or vector(0)',20,4,"none",zero_good,0,spark=False),
]
adv(4)
panels+= [
 stat("Guests running",'count(system_uptime{object="qemu"} > 0)',0,3,"none",steps((None,"blue")),0,spark=False),
 stat("Services down",'count(probe_success < 1) or vector(0)',3,3,"none",zero_good,0,spark=False,desc="Service names whose HTTPS probe through the edge fails; which ones: the strip below"),
 stat("Certificate",'min(probe_ssl_earliest_cert_expiry - time()) / 86400',6,4,"suffix: days",steps((None,"red"),(14,"yellow"),(30,"green")),0,spark=False,desc="*.apps wildcard, days until expiry; Caddy renews it at about 30"),
 stat("Tunnel connections",'sum(cloudflared_tunnel_ha_connections) or vector(0)',10,3,"none",steps((None,"red"),(1,"yellow"),(2,"green")),0,spark=False),
 stat("Router routes",'sum(artoo_tailscale_routes_primary) or vector(0)',13,3,"none",okth,0,spark=False,desc="Primary subnet routes on the Tailscale router"),
 stat("Edge → Proxmox/UniFi (24 h)",'sum(increase(artoo_drop_packets{table="artoo_edge",counter=~"to_pve|to_gateway"}[24h])) or vector(0)',16,4,"none",zero_good,0,spark=False,desc="Any packet here is a sign of compromise (SPEC 9.7)"),
 stat("Telemetry blocked (24 h)",'sum(increase(artoo_drop_packets{table="artoo_watch",counter="telemetry"}[24h])) or vector(0)',20,4,"none",zero_good,0,spark=False,desc="Outbound attempts by Grafana, Loki, VictoriaMetrics, Alloy, ntfy"),
]
adv(4)
# One cell per service name, so a failing one is named (job "integrations/blackbox/<service>").
panels.append({"id":nid(),"type":"stat","title":"HTTPS services","description":"Each service name, probed from the watchdog through the edge (its health path); down = no 2xx, a TLS error or its down text","datasource":VM,
  "gridPos":{"x":0,"y":y[0],"w":24,"h":3},"targets":[tgt(SVC_UP,"{{service}}",instant=True)],
  "fieldConfig":{"defaults":{"unit":"none","thresholds":okth,"color":{"mode":"thresholds"},
    "mappings":[{"type":"value","options":{"0":{"text":"down","color":"red"},"1":{"text":"up","color":"green"}}}]},"overrides":[]},
  "options":{"reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":False},"colorMode":"background","graphMode":"none","justifyMode":"center","textMode":"value_and_name","wideLayout":True,"orientation":"vertical","showPercentChange":False}})
adv(3)

# ---------------- Proxmox
panels.append(row("Proxmox"))
panels+= [
 ts("CPU",[tgt('cpustat_cpu{object="nodes"}',"busy"),tgt('cpustat_wait{object="nodes"}',"I/O wait","B")],0,8,unit="percentunit",minv=0),
 ts("Load",[tgt('cpustat_avg1{object="nodes"}',"1 min"),tgt('cpustat_avg5{object="nodes"}',"5 min","B"),tgt('cpustat_avg15{object="nodes"}',"15 min","C"),tgt('cpustat_cpus{object="nodes"}',"threads","D")],8,8,
    overrides=[{"matcher":{"id":"byName","options":"threads"},"properties":[{"id":"custom.lineStyle","value":{"fill":"dash","dash":[10,10]}},{"id":"custom.fillOpacity","value":0},{"id":"color","value":{"mode":"fixed","fixedColor":"red"}}]}]),
 ts("Memory",[tgt('memory_memused{object="nodes"} - memory_arcsize{object="nodes"}',"used (without ARC)"),tgt('memory_arcsize{object="nodes"}',"ZFS ARC","B"),
               tgt('memory_memavailable{object="nodes"}',"available","C"),tgt('memory_memtotal{object="nodes"}',"total","D")],16,8,unit="bytes",stack=True,
    desc="Used, ARC and available stack up to the total",
    overrides=[{"matcher":{"id":"byName","options":"used (without ARC)"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"orange"}}]},
               {"matcher":{"id":"byName","options":"ZFS ARC"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"purple"}}]},
               {"matcher":{"id":"byName","options":"available"},"properties":[{"id":"color","value":{"mode":"fixed","fixedColor":"green"}},{"id":"custom.fillOpacity","value":5}]},
               {"matcher":{"id":"byName","options":"total"},"properties":[{"id":"custom.stacking","value":{"mode":"none"}},{"id":"custom.fillOpacity","value":0},{"id":"custom.lineStyle","value":{"fill":"dash","dash":[10,10]}},{"id":"color","value":{"mode":"fixed","fixedColor":"red"}}]}]),
]
adv(8)
panels+= [
 ts("Network (vmbr0)",[tgt('rate(nics_receive{object="nodes",instance="vmbr0"}[$__rate_interval])',"in"),tgt('-rate(nics_transmit{object="nodes",instance="vmbr0"}[$__rate_interval])',"out","B")],0,12,unit="Bps",desc="Out drawn below zero"),
 {"id":nid(),"type":"bargauge","title":"Storage","datasource":VM,"gridPos":{"x":12,"y":y[0],"w":12,"h":8},
  "targets":[tgt('system_used{object="storages"} / system_total{object="storages"}',"{{host}}",instant=True)],
  "fieldConfig":{"defaults":{"unit":"percentunit","min":0,"max":1,"decimals":1,"thresholds":steps((None,"green"),(0.75,"yellow"),(0.85,"red")),"color":{"mode":"thresholds"}},"overrides":[]},
  "options":{"orientation":"horizontal","displayMode":"gradient","showUnfilled":True,"valueMode":"color","namePlacement":"left","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":False},"minVizHeight":16,"maxVizHeight":36,"sizing":"auto"}},
]
adv(8)

# ---------------- Guests
panels.append(row("Guests"))
table_targets=[
 tgt('count by (host) (node_cpu_seconds_total{mode="idle"})',"","A",True,"table"),
 tgt('1 - avg by (host) (rate(node_cpu_seconds_total{mode="idle"}[5m]))',"","B",True,"table"),
 tgt('max by (host) (node_memory_MemTotal_bytes)',"","C",True,"table"),
 tgt('max by (host) (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',"","D",True,"table"),
 tgt('max by (host) (1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})',"","E",True,"table"),
 tgt('max by (host) (time() - node_boot_time_seconds)',"","F",True,"table"),
 tgt('max by (host) (artoo_reboot_required)',"","G",True,"table"),
]
def gaugecell(name):
    return {"matcher":{"id":"byName","options":name},"properties":[{"id":"unit","value":"percentunit"},{"id":"min","value":0},{"id":"max","value":1},{"id":"decimals","value":1},
            {"id":"custom.cellOptions","value":{"type":"gauge","mode":"lcd","valueDisplayMode":"text"}},
            {"id":"thresholds","value":steps((None,"green"),(0.75,"yellow"),(0.9,"red"))},{"id":"color","value":{"mode":"thresholds"}},{"id":"custom.width","value":220}]}
panels.append({"id":nid(),"type":"table","title":"Guests","datasource":VM,"gridPos":{"x":0,"y":y[0],"w":24,"h":7},"targets":table_targets,
  "transformations":[{"id":"merge","options":{}},
                     {"id":"organize","options":{"excludeByName":{"Time":True},"indexByName":{"host":0,"Value #A":1,"Value #B":2,"Value #C":3,"Value #D":4,"Value #E":5,"Value #F":6,"Value #G":7},
                      "renameByName":{"host":"Guest","Value #A":"vCPU","Value #B":"CPU","Value #C":"RAM","Value #D":"Memory","Value #E":"Disk /","Value #F":"Uptime","Value #G":"Reboot"}}}],
  "fieldConfig":{"defaults":{"custom":{"align":"left","cellOptions":{"type":"auto"}},"thresholds":GOOD},
    "overrides":[gaugecell("CPU"),gaugecell("Memory"),gaugecell("Disk /"),
      {"matcher":{"id":"byName","options":"RAM"},"properties":[{"id":"unit","value":"bytes"},{"id":"decimals","value":1}]},
      {"matcher":{"id":"byName","options":"Uptime"},"properties":[{"id":"unit","value":"dtdurations"}]},
      {"matcher":{"id":"byName","options":"Reboot"},"properties":[{"id":"mappings","value":[{"type":"value","options":{"0":{"text":"no","color":"green"},"1":{"text":"pending","color":"orange"}}}]},{"id":"custom.cellOptions","value":{"type":"color-text"}}]},
      {"matcher":{"id":"byName","options":"Guest"},"properties":[{"id":"custom.width","value":160}]}]},
  "options":{"showHeader":True,"cellHeight":"sm","sortBy":[{"displayName":"Guest","desc":False}],"footer":{"show":False,"reducer":["sum"],"fields":""}}})
adv(7)
panels+= [
 ts("CPU by guest",[tgt('1 - avg by (host) (rate(node_cpu_seconds_total{mode="idle"}[$__rate_interval]))',"{{host}}")],0,8,unit="percentunit",minv=0),
 ts("Memory by guest",[tgt('max by (host) (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',"{{host}}")],8,8,unit="percentunit",minv=0,maxv=1),
 ts("Network by guest",[tgt('sum by (host) (rate(node_network_receive_bytes_total{device!~"lo|tailscale.*"}[$__rate_interval]))',"{{host}} in"),
                        tgt('-sum by (host) (rate(node_network_transmit_bytes_total{device!~"lo|tailscale.*"}[$__rate_interval]))',"{{host}} out","B")],16,8,unit="Bps",desc="Out drawn below zero"),
]
adv(8)
panels.append(ts("Guest CPU seen by Proxmox",[tgt('system_cpu{object="qemu"} '+GUEST,"{{host}}")],0,12,h=7,unit="percentunit",minv=0,desc="Fraction of each VM's vCPUs, from Proxmox (includes VMs without Alloy)"))
panels.append(ts("Guest memory seen by Proxmox",[tgt('system_mem{object="qemu"} '+GUEST,"{{host}}")],12,12,h=7,unit="bytes",minv=0))
adv(7)

# ---------------- Edge and router
panels.append(row("Edge & router"))
panels+= [
 ts("Edge drops",[tgt('sum by (counter) (increase(artoo_drop_packets{table="artoo_edge"}[$__rate_interval]))',"{{counter}}")],0,8,draw="bars",desc="to_pve / to_gateway: sign of compromise; to_lan, out_other, in_dropped: noise worth a look"),
 ts("Tunnel",[tgt('sum(cloudflared_tunnel_ha_connections)',"connections"),tgt('sum(rate(cloudflared_tunnel_total_requests[$__rate_interval]))',"requests/s","B")],8,8),
 ts("HTTPS probe time",[tgt(by_service('probe_duration_seconds'),"{{service}}")],16,8,unit="s",minv=0),
]
adv(8)
panels+= [
 ts("Certificate expiry",[tgt(by_service('(probe_ssl_earliest_cert_expiry - time()) / 86400'),"{{service}}")],0,8,unit="suffix: days",fill=0),
 ts("Router traffic (tailscale0)",[tgt('sum by (host) (rate(node_network_receive_bytes_total{device="tailscale0"}[$__rate_interval]))',"in"),
                                   tgt('-sum by (host) (rate(node_network_transmit_bytes_total{device="tailscale0"}[$__rate_interval]))',"out","B")],8,8,unit="Bps"),
 ts("Caddy upstreams healthy",[tgt('sum by (upstream) (caddy_reverse_proxy_upstreams_healthy)',"{{upstream}}")],16,8,minv=0,fill=0),
]
adv(8)

# ---------------- Logs (collapsed)
y_logs=y[0]
inner=[]
y[0]+=1
inner.append(ts("Errors per host",[tgt('sum by (host) (count_over_time({level=~"err|crit|alert|emerg"}[$__auto]))',"{{host}}",ds=LOKI)],0,12,h=7,ds=LOKI,draw="bars",stack=True,desc="err, crit, alert, emerg"))
inner.append(ts("Warnings per host",[tgt('sum by (host) (count_over_time({level="warning"}[$__auto]))',"{{host}}",ds=LOKI)],12,12,h=7,ds=LOKI,draw="bars",stack=True,desc="Mostly boot-time chatter from virtual hardware; read them in Explore"))
adv(7)
inner.append({"id":nid(),"type":"logs","title":"Errors (err and worse)","datasource":LOKI,"gridPos":{"x":0,"y":y[0],"w":24,"h":12},
  "targets":[tgt('{level=~"err|crit|alert|emerg"}',"",ds=LOKI)],
  "options":{"showTime":True,"wrapLogMessage":True,"sortOrder":"Descending","enableLogDetails":True,"dedupStrategy":"none","prettifyLogMessage":False}})
r={"id":nid(),"type":"row","title":"Logs","collapsed":True,"gridPos":{"x":0,"y":y_logs,"w":24,"h":1},"panels":inner}
panels.append(r)

dash={"uid":"artoo-lab","title":"Proxmox · Homelab","tags":["artoo"],"timezone":"browser","schemaVersion":41,
      "refresh":"30s","time":{"from":"now-6h","to":"now"},"editable":False,"graphTooltip":1,
      "description":"Managed by artoo (SPEC §9.9); 'artoo watch setup' overwrites edits.","panels":panels,
      "links":[{"title":"Alert rules","type":"link","url":"/alerting/list","icon":"bolt"},{"title":"Explore logs","type":"link","url":"/explore","icon":"compass"}]}
print(json.dumps(dash,indent=2))
