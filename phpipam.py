import requests
import json
import base64
from mcrypt import MCRYPT 
import iptools

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
        else:
            req = {'dns_name':fqdn}

        resp = self.request(req)
        if not resp:
            return False
        hosts = []
        for host in resp:
            hosts.append({
                'host':host['dns_name'],
                'ip':iptools.ipv4.long2ip(int(host['ip_addr']))})

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
        else:
            #forward zone
            query = "%." + zone
            req = {'dns_name': query} 
        resp = self.request(req)
        if not resp:
            return False
        hosts = []
        for host in resp:
            hosts.append({
                'host':host['dns_name'],
                'ip':iptools.ipv4.long2ip(int(host['ip_addr']))})

        return hosts
