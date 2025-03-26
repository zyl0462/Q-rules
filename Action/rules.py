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
PROXY_URL = (('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Domain.txt',
             'https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt'),
             ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix_Classical.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AppleTV/AppleTV.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Twitter/Twitter.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Facebook/Facebook.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Discord/Discord.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Instagram/Instagram.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitLab/GitLab.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Pinterest/Pinterest.yaml',
             'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml')
            )
DIRECT_URL = ('https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AliPay/AliPay.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Apple/Apple_Classical.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/JingDong/JingDong.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Alibaba/Alibaba_Classical.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/WeChat/WeChat.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/DouYin/DouYin.yaml',
              'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ByteDance/ByteDance.yaml'
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
