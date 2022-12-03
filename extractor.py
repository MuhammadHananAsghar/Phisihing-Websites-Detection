import os
import json
import whois
import string
import base64
import favicon
import requests
import tldextract
import datetime
from subprocess import *
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import xml.etree.ElementTree as ET 
from dateutil.relativedelta import relativedelta


class FeatureExtractor:
  def to_find_having_ip_add(self, url):
    "To check if IP Address or Not"
    index = url.find("://")
    split_url = url[index+3:]
    index = split_url.find("/")
    split_url = split_url[:index]
    split_url = split_url.replace(".", "")
    counter_hex = 0
    for i in split_url:
      if i in string.hexdigits:
        counter_hex +=1
    total_len = len(split_url)
    having_IP_Address = 1
    if counter_hex >= total_len:
      having_IP_Address = -1
    return having_IP_Address 
  
  def to_find_url_len(self, url):
    "To check the length of the URL"
    URL_Length = 1
    if len(url)>=75:
      URL_Length = -1
    elif len(url)>=54 and len(url)<=74:
      URL_length = 0
    return URL_Length

  def get_complete_URL(self, shortened_url):
    "To get complete URL"
    command_stdout = Popen(['curl', shortened_url], stdout=PIPE).communicate()[0]
    output = command_stdout.decode('utf-8')
    href_index = output.find("href=")
    if href_index == -1:
      href_index = output.find("HREF=")
    splitted_ = output[href_index:].split('"')
    expanded_url = splitted_[1]
    return expanded_url

  def check_for_shortened_url(self, url):
    "Check for Legit URL Shorten Service"
    famous_short_urls = ["bit.ly", "tinyurl.com", "goo.gl",
                        "rebrand.ly", "t.co", "youtu.be",
                        "ow.ly", "w.wiki", "is.gd"]

    domain_of_url = url.split("://")[1]
    domain_of_url = domain_of_url.split("/")[0]
    status = 1
    if domain_of_url in famous_short_urls:
      status = -1
    complete_url = None
    if status == -1:
      complete_url = self.get_complete_URL(url)
    return (status, complete_url) 
  
  def to_find_at(self, url):
    "To check if @ present in URL or not"
    label = 1
    index = url.find("@")
    if index!=-1:
      label = -1
    return label
  
  def to_find_redirect(self, url):
    "To check if redirects or not"
    index = url.find("://")
    split_url = url[index+3:]
    label = 1
    index = split_url.find("//")
    if index!=-1:
      label = -1
    return label
  
  def to_find_prefix(self, url):
    "To check if - present in URL"
    index = url.find("://")
    split_url = url[index+3:]
    index = split_url.find("/")
    split_url = split_url[:index]
    label = 1
    index = split_url.find("-")
    if index!=-1:
      label = -1
    return label
  
  def to_find_multi_domains(self, url):
    "To check for multi-domains"
    url = url.split("://")[1]
    url = url.split("/")[0]
    index = url.find("www.")
    split_url = url
    if index!=-1:
      split_url = url[index+4:]
    index = split_url.rfind(".")
    if index!=-1:
      split_url = split_url[:index]
    counter = 0
    for i in split_url:
      if i==".":
        counter+=1
    label = 1
    if counter==2:
      label = 0
    elif counter >=3:
      label = -1
    return label
  
  def to_find_authority(self, url):
    "To check if it's registered from verified Authority"
    index_https = url.find("https://")
    valid_auth = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster" , "VeriSign", "LinkedIn", "Sectigo",
                  "Symantec", "DigiCert", "Network Solutions", "RapidSSLonline", "SSL.com", "Entrust Datacard", "Google", "Facebook"]
    cmd = "curl -vvI " + url
    stdout = Popen(cmd, shell=True, stderr=PIPE, env={}).stderr
    output = stdout.read()
    std_out = output.decode('UTF-8')
    index = std_out.find("O=")
    split = std_out[index+2:]
    index_sp = split.find(" ")
    cur = split[:index_sp]
    index_sp = cur.find(",")
    if index_sp!=-1:
      cur = cur[:index_sp]
    print(cur)
    label = -1
    if cur in valid_auth and index_https!=-1:
      label = 1
    return label
  
  def check_submit_to_email(self, url):
    "To check if Submitting to Email"
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    form_opt = str(soup.form)
    idx = form_opt.find("mail()")
    if idx == -1:
      idx = form_opt.find("mailto:")
    if idx == -1:
      return 1
    return -1
  
  def existenceoftoken(self, url):
    "To check https is the part of URL"
    ix = url.find("//https")
    if(ix==-1):
        return 1
    else:
        return -1

  def dregisterlen(self, url):
    "To check the domain registration period length"
    extract_res = tldextract.extract(url)
    ul = extract_res.domain + "." + extract_res.suffix
    try:
        wres = whois.whois(url)
        f = wres["Creation Date"][0]
        s = wres["Registry Expiry Date"][0]
        if(s>f+relativedelta(months=+12)):
            return 1
        else:
            return -1
    except:
        return -1
  
  def sfh(self,   url):
    "TO check SFH of a domain"
    programhtml = requests.get(url).text
    s = BeautifulSoup(programhtml,"lxml")
    try:
        f = str(s.form)
        ac = f.find("action")
        if(ac!=-1):
            i1 = f[ac:].find(">")
            u1 = f[ac+8:i1-1]
            if(u1=="" or u1=="about:blank"):
                return -1
            er1 = tldextract.extract(url)
            upage = er1.domain
            erl2 = tldextract.extract(u1)
            usfh = erl2.domain
            if upage in usfh:
                return 1
            return 0
        else:
            return 1
    except:
        return 1

  def tags(self, url):
    "To check tags in domain"
    programhtml = requests.get(url).text
    s = BeautifulSoup(programhtml,"lxml")
    mtags = s.find_all('Meta')
    ud = tldextract.extract(url)
    upage = ud.domain
    mcount = 0
    for i in mtags:
        u1 = i['href']
        currpage = tldextract.extract(u1)
        u1page = currpage.domain
        if currpage not in ulpage:
            mcount+=1
    scount = 0
    stags = s.find_all('Script')
    for j in stags:
        u1 = j['href']
        currpage = tldextract.extract(u1)
        u1page = currpage.domain
        if currpage not in u1page:
            scount+=1
    lcount = 0
    ltags = s.find_all('Link')
    for k in ltags:
        u1 = k['href']
        currpage = tldextract.extract(u1)
        u1page = currpage.domain
        if currpage not in u1page:
            lcount+=1
    percmtag = 0
    percstag = 0
    percltag = 0

    if len(mtags) != 0:
      percmtag = (mcount*100)//len(mtags)
    if len(stags) != 0:
      percstag = (scount*100)//len(stags)
    if len(ltags) != 0:
      percltag = (lcount*100)//len(ltags)
      
    if(percmtag+percstag+percltag<17):
        return 1
    elif(percmtag+percstag+percltag<=81):
        return 0
    return -1
  
  def url_validator(self, url):
    "URL validator"
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc, result.path])
    except:
        return False

  def redirect(self, url):
    "To check if redirection"
    opt = Popen(["sh", "/red.sh", url], stdout=PIPE).communicate()[0]
    opt = opt.decode('utf-8')
    # print(opt)
    opt = opt.split("\n")
    
    new = []
    for i in opt:
      i = i.replace("\r", " ")
      new.extend(i.split(" "))
    

    count = 0
    for i in new:
    
      if i.isdigit():
        conv = int(i)
        if conv > 300 and conv<310:
          count += 1

    last_url = None
    for i in new[::-1]:
      if self.url_validator(i):
        last_url = i
        break
    if (count<=1):
      return 1, last_url
    elif count>=2 and count <4:
      return 0, last_url
    return -1, last_url
    
  def check_statistical_report(self, url):
    "Statistical report of URL"
    phishTankKey = open('/phishTankKey.txt')
    phishTankKey = phishTankKey.readline()[:-1]

    headers = {
          'format': 'json',
          'app_key': phishTankKey,
          }

    def get_url_with_ip(URI):
        """Returns url with added URI for request"""
        url = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = URI.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        url += base64_new_check
        return url

    def send_the_request_to_phish_tank(url, headers):
        """This function sends a request."""
        response = requests.request("POST", url=url, headers=headers)
        return response

    url = get_url_with_ip(url)
    r = send_the_request_to_phish_tank(url, headers)

    def parseXML(xmlfile): 

      root = ET.fromstring(xmlfile) 
      verified = False
      for item in root.iter('verified'): 
        if item.text == "true":
          verified = True
          break

      phishing = False
      if verified:
        for item in root.iter('valid'): 
          if item.text == "true":
            phishing = True
            break

      return phishing

    inphTank = parseXML(r.text)
    # print(r.text)

    if inphTank:
      return -1
    return 1

    if (count<=1):
      return 1, last_url
    elif count>=2 and count <4:
      return 0, last_url
    return -1, last_url
  
  def get_pagerank(self, url):
    "To check page rank of the URL"
    pageRankApi = "4wsgkkkos8ckgkwc4ks0kccowow0ggkc0ccc0ocw"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    headers = {'API-OPR': pageRankApi}
    domain = url_ref
    req_url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    request = requests.get(req_url, headers=headers)
    result = request.json()
    # print(result)
    value = result['response'][0]['page_rank_decimal']
    if type(value) == str:
      value = 0

    if value < 2:
      return -1
    return 1
  
  def check_web_traffic(self, url):
    "To check web traffic"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    html_content = requests.get("https://www.alexa.com/siteinfo/" + url_ref).text
    soup = BeautifulSoup(html_content, "lxml")
    value = str(soup.find('div', {'class': "rankmini-rank"}))[42:].split("\n")[0].replace(",", "")

    if not value.isdigit():
      return -1

    value = int(value)
    if value < 100000:
      return 1
    return 0
  
  def check_dns_record(self, url):
    "To check DNS record"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
      whois_res = whois.whois(url)
      return 1
    except:
      return -1
  
  def check_age_of_domain(self, url):
    "To check the age of the domain"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    try:
      whois_res = whois.whois(url)
      if datetime.datetime.now() > whois_res["creation_date"][0] + relativedelta(months=+6):
        return 1
      else:
        return -1
    except:
      return -1

  def check_iframe(self, url):
    "To check the iframe on URL"
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup.iframe).lower().find("frameborder") == -1:
      return 1
    return -1
  
  def check_rightclick(self, url):
    "TO check the right click on the URL"
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find("preventdefault()") != -1:
      return -1
    elif str(soup).lower().find("event.button==2") != -1:
      return -1
    elif str(soup).lower().find("event.button == 2") != -1:
      return -1
    return 1

  def check_onmouseover(self, url):
    "To check mouse over on the URL"
    try:
      html_content = requests.get(url).text
    except:
      return -1
    soup = BeautifulSoup(html_content, "lxml")
    if str(soup).lower().find('onmouseover="window.status') != -1:
      return -1
    return 1
  
  def check_favicon(self, url):
    "To check favicon of the URL"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain

    favs = favicon.get(url)
    match = 0
    for favi in favs:
      url2 = favi.url
      extract_res = tldextract.extract(url2)
      url_ref2 = extract_res.domain

      if url_ref in url_ref2:
        match += 1

    if match >= len(favs)/2:
      return 1
    return -1
  
  def check_request_URL(self, url):
    "To check the request URL"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain

    command_stdout = Popen(['curl', 'https://api.hackertarget.com/pagelinks/?q=' + url], stdout=PIPE).communicate()[0]
    links = command_stdout.decode('utf-8').split("\n")

    count = 0

    for link in links:
      extract_res = tldextract.extract(link)
      url_ref2 = extract_res.domain

      if url_ref not in url_ref2:
        count += 1

    count /= len(links)

    if count < 0.22:
      return 1
    elif count < 0.61:
      return 0
    else:
      return -1
  
  def check_URL_of_anchor(self, url):
    "To check URL's of the anchors"
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "lxml")
    a_tags = soup.find_all('a')

    if len(a_tags) == 0:
      return 1

    invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
    bad_count = 0
    for t in a_tags:
      link = t['href']

      if link in invalid:
        bad_count += 1

      if self.url_validator(link):
        extract_res = tldextract.extract(link)
        url_ref2 = extract_res.domain

        if url_ref not in url_ref2:
          bad_count += 1

    bad_count /= len(a_tags)

    if bad_count < 0.31:
      return 1
    elif bad_count <= 0.67:
      return 0
    return -1
  
  def extract(self, url):
    # Number of features 24
    features_extracted = [0]*24
    phStatus, expanded = self.check_for_shortened_url(url)
    features_extracted[2] = phStatus
    phStatus, last_url = self.redirect(url)
    features_extracted[16] = phStatus
    if expanded is not None:
      if len(expanded) >= len(url):
        url = expanded

    if last_url is not None:
      if len(last_url) > len(url):
        url = last_url
    print(url)
    features_extracted[0] = self.to_find_having_ip_add(url)
    features_extracted[1] = self.to_find_url_len(url)
    features_extracted[3] = self.to_find_at(url)
    features_extracted[4] = self.to_find_redirect(url)
    features_extracted[5] = self.to_find_prefix(url)
    features_extracted[6] = self.to_find_multi_domains(url)
    features_extracted[7] = self.to_find_authority(url)
    features_extracted[8] = self.dregisterlen(url)
    features_extracted[9] = self.check_favicon(url)
    features_extracted[10] = self.existenceoftoken(url)
    features_extracted[11] = self.check_request_URL(url)
    features_extracted[12] = self.check_URL_of_anchor(url)
    features_extracted[13] = self.tags(url)
    features_extracted[14] = self.sfh(url)
    features_extracted[15] = self.check_submit_to_email(url)
    features_extracted[17] = self.check_onmouseover(url)
    features_extracted[18] = self.check_rightclick(url)
    features_extracted[19] = self.check_iframe(url)
    features_extracted[20] = self.check_age_of_domain(url)
    features_extracted[21] = self.check_dns_record(url)
    features_extracted[22] = self.check_web_traffic(url)
    features_extracted[23] = self.get_pagerank(url)

    return features_extracted