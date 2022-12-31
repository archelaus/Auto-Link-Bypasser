import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import base64
import sys
import cloudscraper
import hashlib
from lxml import etree


class DirectDownloadLinkException(Exception):
    """No suitable method found for this site """
    pass


# {"url": "https://new.gdtot.eu/", "cookie": "crypt=; PHPSESSID=nv9735jl65b4t4t7t8642dvqb1"}
CRYPT = "" # Crypt cookie

XSRF_TOKEN = "" # XSRF-TOKEN cookie
laravel_session = "" # laravel_session cookie

# url = input("Enter link: ")
url = sys.argv[1]

# ==============================================

def gdtot_bypass(url: str) -> str:

    if CRYPT is None:
        raise DirectDownloadLinkException("ERROR: CRYPT cookie not provided")

    with requests.Session() as client:
        client.cookies.update({'crypt': CRYPT})
        res = client.get(url)
        res = client.get(f"https://new4.gdtot.cfd/dld?id={url.split('/')[-1]}")
    matches = re.findall('gd=(.*?)&', res.text)
    try:
        decoded_id = base64.b64decode(str(matches[0])).decode('utf-8')
    except:
        raise DirectDownloadLinkException(
            "ERROR: Try in your broswer. File not found!")
    return f'https://drive.google.com/open?id={decoded_id}'

# =================================

def gplinks_bypass(url):
    client = requests.Session()
    res = client.get(url)

    h = {"referer": res.url}
    res = client.get(url, headers=h)

    bs4 = BeautifulSoup(res.content, 'lxml')
    inputs = bs4.find_all('input')
    data = {input.get('name'): input.get('value') for input in inputs}

    h = {
        'content-type': 'application/x-www-form-urlencoded',
        'x-requested-with': 'XMLHttpRequest'
    }

    time.sleep(10)  # !important

    p = urlparse(url)
    final_url = f'{p.scheme}://{p.netloc}/links/go'
    res = client.post(final_url, data=data, headers=h).json()

    return res

# =================================

def rocklinks_bypass(url):
    client = cloudscraper.create_scraper(allow_brotli=False)
    DOMAIN = "https://link.techyone.co"
    url = url[:-1] if url[-1] == '/' else url

    code = url.split("/")[-1]
    final_url = f"{DOMAIN}/{code}?quelle="

    resp = client.get(final_url)
    soup = BeautifulSoup(resp.content, "html.parser")
    
    try: inputs = soup.find(id="go-link").find_all(name="input")
    except: return "Incorrect Link"
    
    data = { input.get('name'): input.get('value') for input in inputs }

    h = { "x-requested-with": "XMLHttpRequest" }
    
    time.sleep(6)
    r = client.post(f"{DOMAIN}/links/go", data=data, headers=h)
    try:
        return r.json()['url']
    except: return "Something went wrong :("
    
# =================================

def gofile_dl(url):
    api_uri = 'https://api.gofile.io'
    client = requests.Session()
    res = client.get(api_uri+'/createAccount').json()
    
    data = {
        'contentId': url.split('/')[-1],
        'token': res['data']['token'],
        'websiteToken': '12345',
        'cache': 'true',
        'password': hashlib.sha256(password.encode('utf-8')).hexdigest()
    }
    res = client.get(api_uri+'/getContent', params=data).json()

    content = []
    for item in res['data']['contents'].values():
        content.append(item)
    
    return {
        'accountToken': data['token'],
        'files': content
    }
    
# =================================

'''
404: Exception Handling Not Found :(
NOTE:
DO NOT use the logout button on website. Instead, clear the site cookies manually to log out.
If you use logout from website, cookies will become invalid.
'''

def parse_info(res):
    f = re.findall(">(.*?)<\/td>", res.text)
    info_parsed = {}
    for i in range(0, len(f), 3):
        info_parsed[f[i].lower().replace(' ', '_')] = f[i+2]
    return info_parsed

def sharer_pw_dl(url, forced_login=False):
    client = requests.Session()
    
    client.cookies.update({
        "XSRF-TOKEN": XSRF_TOKEN,
        "laravel_session": laravel_session
    })
    
    res = client.get(url)
    token = re.findall("_token\s=\s'(.*?)'", res.text, re.DOTALL)[0]
    
    ddl_btn = etree.HTML(res.content).xpath("//button[@id='btndirect']")

    info_parsed = parse_info(res)
    info_parsed['error'] = True
    info_parsed['src_url'] = url
    info_parsed['link_type'] = 'login' # direct/login
    info_parsed['forced_login'] = forced_login
    
    headers = {
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-requested-with': 'XMLHttpRequest'
    }
    
    data = {
        '_token': token
    }
    
    if len(ddl_btn):
        info_parsed['link_type'] = 'direct'
    if not forced_login:
        data['nl'] = 1
    
    try: 
        res = client.post(url+'/dl', headers=headers, data=data).json()
    except:
        return info_parsed
    
    if 'url' in res and res['url']:
        info_parsed['error'] = False
        info_parsed['gdrive_link'] = res['url']
    
    if len(ddl_btn) and not forced_login and not 'url' in info_parsed:
        # retry download via login
        return sharer_pw_dl(url, forced_login=True)
    
    return info_parsed

# =================================

def droplink_bypass(url):
    client = requests.Session()
    res = client.get(url)

    ref = re.findall("action[ ]{0,}=[ ]{0,}['|\"](.*?)['|\"]", res.text)[0]

    h = {'referer': ref}
    res = client.get(url, headers=h)

    bs4 = BeautifulSoup(res.content, 'lxml')
    inputs = bs4.find_all('input')
    data = { input.get('name'): input.get('value') for input in inputs }

    h = {
        'content-type': 'application/x-www-form-urlencoded',
        'x-requested-with': 'XMLHttpRequest'
    }
    p = urlparse(url)
    final_url = f'{p.scheme}://{p.netloc}/links/go'

    time.sleep(3.1)
    res = client.post(final_url, data=data, headers=h).json()

    return res

# ==========================================

'''
404: Complete exception handling not found :(
'''

def decrypt_url(code):
    a, b = '', ''
    for i in range(0, len(code)):
        if i % 2 == 0: a += code[i]
        else: b = code[i] + b

    key = list(a + b)
    i = 0

    while i < len(key):
        if key[i].isdigit():
            for j in range(i+1,len(key)):
                if key[j].isdigit():
                    u = int(key[i]) ^ int(key[j])
                    if u < 10: key[i] = str(u)
                    i = j					
                    break
        i+=1
    
    key = ''.join(key)
    decrypted = b64decode(key)[16:-16]

    return decrypted.decode('utf-8')

def adfly_bypass(url):
    res = requests.get(url).text
    
    out = {'error': False, 'src_url': url}
    
    try:
        ysmm = re.findall("ysmm\s+=\s+['|\"](.*?)['|\"]", res)[0]
    except:
        out['error'] = True
        return out
        
    url = decrypt_url(ysmm)

    if re.search(r'go\.php\?u\=', url):
        url = b64decode(re.sub(r'(.*?)u=', '', url)).decode()
    elif '&dest=' in url:
        url = unquote(re.sub(r'(.*?)dest=', '', url))
    
    out['bypassed_url'] = url
    
    return out

if 'gdtot' in url:
    print(gdtot_bypass(url))
elif 'gplinks' in url:
    print(gplinks_bypass(url))
elif 'rocklinks' in url:
    print(rocklinks_bypass(url))
elif 'gofile' in url:
    print(gofile_dl(url))
elif 'sharer' in url:
    print(sharer_pw_dl(url))
elif 'droplink' in url:
    print(droplink_bypass(url))
elif 'adflyss' in url:
    print(adfly_bypass(url))
else:
    raise DirectDownloadLinkException(
        f'No function found for {url}')
