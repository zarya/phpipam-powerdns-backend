import requests
import json
import base64
from mcrypt import MCRYPT 
import iptools
from dns import reversename

class PHPipam:
    def __init__(self,url,app_id,app_key):
        self.url = url
        self.app_id = app_id
        self.app_key = app_key

    def request(self,data):
        data['format'] = "json"
        data['controller'] = "addresses"
        data['action'] = "read"
        c = MCRYPT('rijndael-256','ecb')
        c.init(self.app_key)
        request = json.dumps(data)
        enc_request = bytes(c.encrypt(request))
        req = {
            'enc_request':base64.b64encode(enc_request),
            'app_id':self.app_id
        }
        r = requests.post("%s/api/" % self.url, data=req)
        response = r.json
        if not response['success']:
            return False
        return response['data']

    def lookup(self,fqdn):
        if fqdn.endswith('in-addr.arpa'):
            ip = fqdn.split('.')
            if len(ip) != 6:
                return False
            _ip = "%s.%s.%s.%s" %(ip[3],ip[2],ip[1],ip[0])
            req = {'ip':_ip}
        elif fqdn.endswith('ip6.arpa'):
            ip_rev = fqdn[:-9]
            ip_tmp = ip_rev[::-1].replace(".","")
            ip = ":".join([ip_tmp[j:j+4] for j in range(0,len(ip_tmp),4)])
            req = {'iplong':str(iptools.ipv6.ip2long(ip)) }
        else:
            req = {'dns_name':fqdn}
        
        resp = self.request(req)
        if not resp:
            return False
        hosts = []
        for host in resp:
            try:
                hosts.append({
                    'host':host['dns_name'],
                    'ip':iptools.ipv4.long2ip(int(host['ip_addr']))})
            except:
                hosts.append({
                    'host':host['dns_name'],
                    'ip6':iptools.ipv6.long2ip(int(host['ip_addr']))})
                continue

        return hosts

    def zone(self,zone):
        if zone.endswith('in-addr.arpa'):
            #reverse zone
            ip = zone.split('.')
            if len(ip) == 3:
                ip_from = "%s.0.0.0"%(ip[0])
                ip_to = "%s.255.255.255"%(ip[0])
            elif len(ip) == 4:
                ip_from = "%s.%s.0.0"%(ip[1],ip[0])
                ip_to = "%s.%s.255.255"%(ip[1],ip[0])
            elif len(ip) == 5:
                ip_from = "%s.%s.%s.0"%(ip[2],ip[1],ip[0])
                ip_to = "%s.%s.%s.255"%(ip[2],ip[1],ip[0])
            else:
                return False
            req = {
                'ip_from':ip_from,
                'ip_to':ip_to
            }
        elif zone.endswith('ip6.arpa'):
            ip_rev = zone[:-9]
            ip_tmp = ip_rev[::-1].replace(".","")
            ip = ":".join([ip_tmp[j:j+4] for j in range(0,len(ip_tmp),4)])
            bits = len(ip_rev.split('.')) * 4
            iprange = iptools.ipv6.cidr2block("%s::/%s"%(ip,bits))
            req = {
                'iplong_from': str(iptools.ipv6.ip2long(iprange[0])),
                'iplong_to': str(iptools.ipv6.ip2long(iprange[1]))
            }
        else:
            #forward zone
            query = "%." + zone
            req = {'dns_name': query} 
        resp = self.request(req)
        if not resp:
            return False
        hosts = []
        for host in resp:
            try:
                hosts.append({
                    'host':host['dns_name'],
                    'ip':iptools.ipv4.long2ip(int(host['ip_addr']))})
            except:
                ip6 = iptools.ipv6.long2ip(int(host['ip_addr'])) 
                reverse_octets = str(ip6).split(':')[::-1]
                ip6_rev = '.'.join(reverse_octets) + '.in-addr.arpa'
                ip6_rev = reversename.from_address(ip6) 
                hosts.append({
                    'host':host['dns_name'],
                    'ip6':iptools.ipv6.long2ip(int(host['ip_addr'])),
                    'ip6_rev':ip6_rev
                })
                continue

        return hosts
