import requests, json, ipaddress, pickle, ipinfo
from datetime import datetime, timezone, timedelta
import time


# API KEY(S)
ABUSE_PDB = 'ADD KEY HERE'
VIRUS_TOTAL = 'ADD KEY HERE'
IP_INFO = 'ADD KEY HERE'
HANDLER = ipinfo.getHandler(IP_INFO)

# function for abusepdb
def abusepdb(ip,config):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
    'ipAddress': ip,
    'maxAgeInDays': '30'}
    headers = {
    'Accept': 'application/json',
    'Key': ABUSE_PDB}
    # presetting values
    ip_ver,abuse_score,is_tor = None,None,None
    if config[0][0] == 'A1':
        verify = eval(config[0][4])
        if verify['enabled']:
            resp = requests.request(method='GET', url=url, headers=headers, params=querystring)
            if resp.status_code == 429: # api rate-limited
                return ip_ver,abuse_score,is_tor
            info = json.loads(resp.text)
            info = info['data']
            ip_ver,abuse_score,is_tor = info['ipVersion'],info['abuseConfidenceScore'],info['isTor']
    return ip_ver,abuse_score,is_tor

# function for ipinfo
def geo_ip(ip,config):
    # presetting values
    city,region,country,lat,lon = None,None,None,None,None
    if config[2][0] == 'A3':
        verify = eval(config[2][4])
        if verify['enabled']:
            details = HANDLER.getDetails(ip)
            info = details.all
            city,region,country,lat,lon = info.get('city'),info.get('region'),info.get('country_name'),info.get('latitude'),info.get('longitude')
    return city,region,country,lat,lon

# function for virus total recon
def vt_recon(ip,config):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    # presetting values
    vt_score,reputation,as_owner = None,None,None
    if config[1][0] == 'A2':
        verify = eval(config[1][4])
        if verify['enabled']:
            time.sleep(15) # prevents rate-limits
            resp = requests.get(url, headers={'x-apikey':VIRUS_TOTAL})
            if resp.status_code != 200:
                return vt_score,reputation,as_owner
            info = resp.json()['data']['attributes']
            vt_score = info['last_analysis_stats']['malicious']
            reputation = info['reputation']
            as_owner = info['as_owner']
    return vt_score,reputation,as_owner

# function for checking alerts
def check_alerts(config,threat_score,geo_loc):
    # presetting values
    mal_alert,geoip_alert = False,False
    # checking malicious alert
    if config[9][0] == 'C1':
        verify = eval(config[9][4])
        if verify['enabled']:
            if threat_score >= verify['threshold']:
                mal_alert = True
    # checking geoip blacklist ( list containing city,region,country )
    if config[10][0] == 'C2':
        verify = eval(config[10][4])
        if verify['enabled']:
            blacklist = [item.lower() for item in verify['blacklist']]
            for loc in geo_loc:
                if loc is not None and loc.lower() in blacklist:
                    geoip_alert = True
                    break
    return mal_alert,geoip_alert

# function for removing old cache
def purge_cache():
    purged_cache = dict()
    # loading threat intel cache
    with open('sentinel_data.pkl','rb') as file:
        data = pickle.load(file)
        cache_intel = data['Threat_intel']
    purge_period = datetime.now(timezone.utc) - timedelta(days=30) # 1 month retention period
    for ip,info in cache_intel.items():
        timestamp = datetime.fromisoformat(info['date_enriched'].replace('Z', '+00:00'))
        if timestamp > purge_period:
            purged_cache[ip] = info
    # update cache
    with open('sentinel_data.pkl','wb') as file:
        data['Threat_intel'] = purged_cache
        pickle.dump(data,file)



# Main Threat Intelligence function
def threat_intel(events,config):
    purge_cache()
    enriched_events = list()
    auth_fails = {4625:0,4771:0}
    # loading cached threat intel data
    with open('sentinel_data.pkl','rb') as file:
        data = pickle.load(file)
        cache_intel = data['Threat_intel']
    # add function to delete old cache(s) | convert timestamp to datetime format. 
    for event in events:
        if event['event.module'] == 'Firewall': # firewall events
            # determining ip address for threat intel 
            if event['network.direction'] == 'outbound':
                ip = event['destination.ip']
            elif event['network.direction'] == 'inbound':
                ip = event['source.ip']
            else:
                print('Malformed firewall event..\nskipping.')
                continue
            # check if ip is public
            try:
                if ipaddress.ip_address(ip).is_global:
                    # check if ip in cached data
                    if ip in cache_intel.keys():
                        print('IP found in cached data...')
                        enrich = cache_intel[ip]
                        enriched_events.append(enrich)
                        continue
                    else: # Ip not in cached data
                        # getting AbusePDB score
                        print('IP not in cache...gathering threat intel...')
                        ip_ver,abuse_score,is_tor = abusepdb(ip,config)
                        # getting IPInfo
                        city,region,country,lat,lon = geo_ip(ip,config)
                        # check for null value from abusepdb, loc co-ordinates
                        if abuse_score is None:
                            continue
                        # function for malicious alert and geoalert
                        mal_alert,geoip_alert = check_alerts(config,abuse_score,[city,region,country])
                        # Analysing abuse score for further recon
                        if abuse_score > 40:
                            vt_score,reputation,as_owner = vt_recon(ip,config)
                            if not vt_score:
                                enrichment = 'Not Categorized'
                            # assessing enrichment
                            if vt_score < 3:
                                enrichment = 'Suspicious'
                            elif vt_score < 8:
                                enrichment = 'Probably Dangerous'
                            elif vt_score > 8:
                                enrichment = 'Dangerous'
                            else:
                                enrichment = 'Not Categorized'
                            # adding enrichment data
                            timestamp = datetime.now()
                            #check if the event is a dropped packet
                            if event['event.action'] != 'ALLOW':
                                enrichment = enrichment + ' | Dropped'
                            # enriched data for ingestion
                            enrich_data = {
                                'ip': ip,
                                'ip_version': ip_ver,
                                'abuse_score': abuse_score,
                                'is_tor': is_tor,
                                'city': city,
                                'region': region,
                                'country': country,
                                'vt_score': vt_score,
                                'reputation': reputation,
                                'as_owner': as_owner,
                                'enrichment': enrichment,
                                'malicious_alert': mal_alert,
                                'geoip_alert': geoip_alert,
                                'date_enriched': timestamp.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
                                'event.module': 'Firewall'
                            }
                            # setting map co-ordinates
                            if lat and lon:
                                location = {"lat":float(lat),"lon":float(lon)}
                                enrich_data['location'] = location
                            # caching data
                            cache_intel[ip] = enrich_data
                            # adding to events
                            enriched_events.append(enrich_data)
                            del enrich_data
                        else: # abuse score < 40
                            # assessing enrichment
                            if abuse_score < 20:
                                enrichment = 'Clean'
                            elif abuse_score < 40:
                                enrichment = 'Probably Clean'
                            else:
                                enrichment = 'Not Categorized'
                            # adding enrichment data
                            timestamp = datetime.now()
                            #check if the event is a dropped packet
                            if event['event.action'] != 'ALLOW':
                                enrichment = enrichment + ' | Dropped'
                            # enriched data for ingestion
                            enrich_data = {
                                'ip': ip,
                                'ip_version': ip_ver,
                                'abuse_score': abuse_score,
                                'is_tor': is_tor,
                                'city': city,
                                'region': region,
                                'country': country,
                                'enrichment': enrichment,
                                'malicious_alert': mal_alert,
                                'geoip_alert': geoip_alert,
                                'date_enriched': timestamp.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
                                'event.module': 'Firewall'
                            }
                            # setting map co-ordinates
                            if lat and lon:
                                location = {"lat":float(lat),"lon":float(lon)}
                                enrich_data['location'] = location
                            # caching data
                            cache_intel[ip] = enrich_data
                            # adding to events
                            enriched_events.append(enrich_data)
                            del enrich_data
                else:
                    continue # Private\Internal IP
            except ValueError:
                print('Malformed IP..\nskipping')
                continue
        # Auth-failure alert
        elif event['event.module'] == 'Security':
            print('Enriching security event...')
            # checking auth-alert status
            if config[11][0] == 'C3':
                verify = eval(config[11][4])
                if verify['enabled']:
                    threshold = verify['threshold']
                    if event['event.id'] in auth_fails.keys():
                        auth_fails[event['event.id']] += 1
                    # check for account lockout
                    elif event['event.id'] == 4740:
                        event['auth_fail_alert'] = True
                        enriched_events.append(event)
                        continue
                    # threshold check
                    for count in auth_fails.values():
                        if count >= threshold:
                            event['auth_fail_alert'] = True
                            enriched_events.append(event)
    # writing cached data
    with open('sentinel_data.pkl','wb') as file:
        data['Threat_intel'] = cache_intel
        pickle.dump(data,file)
    return enriched_events
