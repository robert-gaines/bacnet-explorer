
import requests
import folium
import time
import csv

class ICSMap():

    def __init__(self,key):
        self.key = key

    def GenerateFilename(self):
        timestamp = time.ctime()
        timestamp = timestamp.replace(' ','_')
        timestamp = timestamp.replace(':','_')
        filename  = 'shodan_bacnet_log_'+timestamp+'.csv'
        return filename 

    def CreateMap(self):
        self.map = folium.Map(location = [40,-101], zoom_start=4)
        self.map.add_child(folium.LatLngPopup())
        folium.TileLayer('cartodbdark_matter').add_to(self.map)

    def SaveMap(self):
        self.map.save('bacnet-explorer.html')

    def queryShodan(self):
        print("[~] Querying Shodan for BACNET devices")
        queries = [
                    "BACNET"
                  ]
        bacnet_log_file = self.GenerateFilename()
        page_index      = 0
        with open(bacnet_log_file,'w',newline='') as csvfile:
            bacnet_writer = csv.writer(csvfile,delimiter=',')
            for query in queries:
                url = "https://api.shodan.io/shodan/host/search?key={0}&query={1}&page={2}".format(self.key,query,page_index)
                req = requests.get(url=url,timeout=15)
                if(req.status_code == 200):
                    content = req.json()
                    content = content['matches']
                    for entry in content:
                        current_keys = []
                        for key in entry.keys():
                            current_keys.append(key)
                        latitude  = entry['location']['latitude']
                        longitude = entry['location']['longitude'] 
                        try:
                            info = str(entry['info'])
                        except:
                            info = "Unknown Device"
                        try:
                            product = str(entry['product'])
                        except:
                            product = "Unknown Product"
                        timestamp  = str(entry['timestamp'])
                        hostnames  = str(entry['hostnames'])
                        asn        = str(entry['asn'])
                        isp        = str(entry['isp'])
                        org        = str(entry['org'])
                        domains    = str(entry['domains'])
                        try:
                            tags   = str(entry['tags'])
                        except:
                            tags   = "No Tags"
                        ip_addr    = str(entry['ip_str'])
                        transport  = str(entry['transport'])
                        port       = str(entry['port'])
                        city       = str(entry['location']['city'])
                        region     = str(entry['location']['region_code'])
                        proto_data = "<br>"
                        if('bacnet' in current_keys):
                            bacnet_data = entry['bacnet']
                            for element in bacnet_data.keys():
                                line = str(element) + ":" + str(bacnet_data[element]) + "<br>"
                                proto_data += line
                        data    = "<br>"
                        data   += str(entry['data'])
                        if_val  = "INFO:                 %s <br>" % info
                        if_val += "PRODUCT:              %s <br>" % product
                        if_val += "TIMESTAMP:            %s <br>" % timestamp
                        if_val += "ASN:                  %s <br>" % asn
                        if_val += "ISP:                  %s <br>" % isp
                        if_val += "ORGANIZATION:         %s <br>" % org
                        if_val += "HOSTNAMES:            %s <br>" % hostnames
                        if_val += "DOMAINS:              %s <br>" % domains 
                        if_val += "TAGS:                 %s <br>" % tags 
                        if_val += "IP ADDRESS:           %s <br>" % ip_addr 
                        if_val += "TRANSPORT:            %s <br>" % transport
                        if_val += "PORT:                 %s <br>" % port
                        if_val += "CITY:                 %s <br>" % city
                        if_val += "REGION:               %s <br>" % region
                        if_val += "PROTOCOL DATA:        %s <br>" % proto_data
                        if_val += "ADDITIONAL DATA:      %s <br>" % data
                        bacnet_writer.writerow([info,product,timestamp,asn,isp,org,hostnames,domains,tags,ip_addr,transport,port,city,region,proto_data,data])
                        try:
                            taglist = entry['tags']
                        except:
                            taglist = ['Non-Honeypot']
                        if("honeypot" in taglist):
                            iframe = folium.IFrame(if_val)
                            popup  = folium.Popup(iframe,min_width=500,max_width=500)
                            folium.Marker(location=[float(latitude),float(longitude)],popup=popup,icon=folium.Icon(prefix="fa",icon="cog",color='orange')).add_to(self.map)
                        if('bacnet' in current_keys and ("honeypot" not in taglist)):
                            iframe = folium.IFrame(if_val)
                            popup  = folium.Popup(iframe,min_width=500,max_width=500)
                            folium.Marker(location=[float(latitude),float(longitude)],popup=popup,icon=folium.Icon(prefix="fa",icon="cog",color='green')).add_to(self.map)
                    page_index += 1
                    status_code = 200
                    while(status_code == 200):
                        url = "https://api.shodan.io/shodan/host/search?key={0}&query={1}&page={2}".format(self.key,query,page_index)
                        req = requests.get(url=url,timeout=15)
                        status_code = req.status_code
                        if(req.status_code == 200):
                            content = req.json()
                            content = content['matches']
                            for entry in content:
                                current_keys = []
                                for key in entry.keys():
                                    current_keys.append(key)
                                latitude  = entry['location']['latitude']
                                longitude = entry['location']['longitude'] 
                                try:
                                    info = str(entry['info'])
                                except:
                                    info = "Unknown Device"
                                try:
                                    product = str(entry['product'])
                                except:
                                    product = "Unknown Product"
                                try:
                                    timestamp  = str(entry['timestamp'])
                                except:
                                    timestamp  = "No Timestamp"
                                try:
                                    hostnames  = str(entry['hostnames'])
                                except:
                                    hostnames  = ""
                                try:
                                    asn        = str(entry['asn'])
                                except:
                                    asn        = ""
                                try:
                                    isp        = str(entry['isp'])
                                except: 
                                    isp        = ""
                                try:
                                    org        = str(entry['org'])
                                except:
                                    org        = ""
                                try:
                                    domains    = str(entry['domains'])
                                except:
                                    domains    = ""
                                try:
                                    tags   = str(entry['tags'])
                                except:
                                    tags   = "No Tags"
                                try:
                                    ip_addr    = str(entry['ip_str'])
                                except:
                                    ip_addr    = ""
                                try:
                                    transport  = str(entry['transport'])
                                except:
                                    transport  = ""
                                try:
                                    port       = str(entry['port'])
                                except:
                                    port       = ""
                                try:
                                    city       = str(entry['location']['city'])
                                except:
                                    city       = ""
                                try:
                                    region     = str(entry['location']['region_code'])
                                except:
                                    region     = ""
                                try:
                                    proto_data = "<br>"
                                    if('bacnet' in current_keys):
                                        bacnet_data = entry['bacnet']
                                        for element in bacnet_data.keys():
                                            line = str(element) + ":" + str(bacnet_data[element]) + "<br>"
                                            proto_data += line
                                except:
                                    proto_data = ""
                                data    = "<br>"
                                try:
                                    data   += str(entry['data'])
                                except:
                                    data    = ''
                                if_val  = "INFO:                 %s <br>" % info
                                if_val += "PRODUCT:              %s <br>" % product
                                if_val += "TIMESTAMP:            %s <br>" % timestamp
                                if_val += "ASN:                  %s <br>" % asn
                                if_val += "ISP:                  %s <br>" % isp
                                if_val += "ORGANIZATION:         %s <br>" % org
                                if_val += "HOSTNAMES:            %s <br>" % hostnames
                                if_val += "DOMAINS:              %s <br>" % domains 
                                if_val += "TAGS:                 %s <br>" % tags 
                                if_val += "IP ADDRESS:           %s <br>" % ip_addr 
                                if_val += "TRANSPORT:            %s <br>" % transport
                                if_val += "PORT:                 %s <br>" % port
                                if_val += "CITY:                 %s <br>" % city
                                if_val += "REGION:               %s <br>" % region
                                if_val += "PROTOCOL DATA:        %s <br>" % proto_data
                                if_val += "ADDITIONAL DATA:      %s <br>" % data
                                try:
                                    bacnet_writer.writerow([info,product,timestamp,asn,isp,org,hostnames,domains,tags,ip_addr,transport,port,city,region,proto_data,data])
                                except:
                                    pass
                                try:
                                    taglist = entry['tags']
                                except:
                                    taglist = ['Non-Honeypot']
                                if("honeypot" in taglist):
                                    iframe = folium.IFrame(if_val)
                                    popup  = folium.Popup(iframe,min_width=500,max_width=500)
                                    folium.Marker(location=[float(latitude),float(longitude)],popup=popup,icon=folium.Icon(prefix="fa",icon="cog",color='orange')).add_to(self.map)
                                if('bacnet' in current_keys and ("honeypot" not in taglist)):
                                    iframe = folium.IFrame(if_val)
                                    popup  = folium.Popup(iframe,min_width=500,max_width=500)
                                    folium.Marker(location=[float(latitude),float(longitude)],popup=popup,icon=folium.Icon(prefix="fa",icon="cog",color='green')).add_to(self.map)
                            page_index += 1
        print("[*] Query complete ")

if(__name__ == '__main__'):
    print("[*] BACNET Navigator Script ")
    key = input("[+] Enter your Shodan API Key-> ")
    map = ICSMap(key)
    map.CreateMap()
    map.queryShodan()
    map.SaveMap()