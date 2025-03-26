import requests,sys,time
from datetime import datetime,timezone,timedelta

def get_text(url):
    with requests.get(url, stream= True) as r:
        if r.status_code == 200:
            with open("./Rules/tmp", "wb") as f:
                for chunk in r.iter_content(chunk_size=4096):
                    if chunk:
                        f.write(chunk)
            time.sleep(0.1)
            with open("./Rules/tmp", "r",encoding='utf-8') as f:
                return f.read().strip()
        else:
            sys.exit(0)

############################################################  
############################################################
REJECT_URL = ("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
             "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
PROXY_URL = ('https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Proxy/Proxy.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Netflix/Netflix.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AppleTV/AppleTV.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GitHub/GitHub.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Google/Google.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/YouTube/YouTube.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Telegram/Telegram.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/TikTok/TikTok.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Twitter/Twitter.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Facebook/Facebook.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Discord/Discord.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Instagram/Instagram.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/GitLab/GitLab.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Pinterest/Pinterest.list',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/OpenAI/OpenAI.list'
            )
DIRECT_URL = ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/AliPay/AliPay.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Apple/Apple.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/JingDong/JingDong.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Alibaba/Alibaba.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/WeChat/WeChat.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/DouYin/DouYin.list',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/ByteDance/ByteDance.list'
             )
reject_set = set([i for i in get_text(REJECT_URL[0]).split("\n") if not ((len(i) == 0) or i.startswith('#') or i.startswith('!'))])
reject_set.update([i[2:-1] for i in get_text(REJECT_URL[1]).split("\n") if (i.startswith('||') and i.endswith('^') and ( not ('*' in i)))])

qx_set = set()
j = ''
for i in reject_set:
    j = 'host-suffix,' + i + ',reject'
    qx_set.add(j)
qx_text = '\n'.join(sorted(qx_set))
with open("./Rules/qx.conf", "w",encoding='utf-8') as f:
    f.write(qx_text)
del j,qx_set,qx_text
