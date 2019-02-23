import requests
from bs4 import BeautifulSoup
import time
import random
import re
from lxml import etree
import csv

HEADERS = {
'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36',
}
url = 'https://source.android.google.cn/security/bulletin/2017-07-01#media-framework'
if __name__ == '__main__':
    req  = requests.get(url, headers = HEADERS)
    html = etree.HTML(req.text)
    tr = html.xpath('//*[@id="gc-wrapper"]/div/devsite-content/article/article/div[2]/table[4]/tbody/tr')
    for eachCve in tr:
        cveInfo = []
        if len(eachCve.xpath('td[5]/text()')):
            android = eachCve.xpath('td[5]/text()')
            x = re.search(r'6.0、', android[0], re.S)
            y =re.search(r'5.1.1、', android[0], re.S)
            if x or y:
                cveid =  eachCve.xpath('td[1]/text()')[0]
                cveInfo.append(cveid)
                cveDetailUrl = eachCve.xpath('td[2]/a/@href')[0]
                cveDetail = eachCve.xpath('td[2]/a/text()')[0]
                cveInfo.append(cveDetail)
                cveTypes = eachCve.xpath('td[3]/text()')[0]
                cveInfo.append(cveTypes)
                cveLevel = eachCve.xpath('td[4]/text()')[0]
                cveInfo.append(cveLevel)
                androidVersion = eachCve.xpath('td[5]/text()')[0]
                cveInfo.append(androidVersion)
                cveInfo.append(cveDetailUrl)
                path = re.match('(.*)com/(.*\+)', cveDetailUrl, re.S)
                try:
                    detail = requests.get(cveDetailUrl, headers=HEADERS)
                    be = BeautifulSoup(detail.text, 'lxml')
                    diff = be.find('ul', class_='DiffTree').li.a.text
                    diffpath = 'android/'+ path.group(2)[:-1] + diff
                    cveInfo.append(diffpath)
                    diffurl = be.find('ul', class_='DiffTree').li.a['href']
                    diffurl = 'https://android.googlesource.com' + diffurl
                    cveInfo.append(diffurl)
                    bug = be.find('pre', class_='MetadataMessage').text
                    cveInfo.append(bug)
                except BaseException as e:
                    print('error')

                with open('/home/rezirv/桌面/mediasreverCve.csv', 'a+') as f:
                    writer = csv.writer(f, dialect='excel')
                    writer.writerow(cveInfo)
                    f.close()



                
                

        