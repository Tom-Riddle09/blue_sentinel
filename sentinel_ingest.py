from datetime import datetime, timezone
import pickle, json


# function for ingesting data 
def event_ingest(client,index_name,events):
    batches = list()
    batch_size = 10000
    # splitting into batches of 10k events
    for i in range(0,len(events),batch_size):
        batches.append(events[i:i+batch_size])
    # preparing bulk data
    print("preparing data for ingestion..")
    for batch in batches:
        bulk_data = ""
        for event in batch:
            bulk_data += json.dumps({"create":{"_index":index_name}}) + "\n"
            bulk_data += json.dumps(event) + "\n"
        response = client.bulk(body=bulk_data)
        if response['errors']:
            print('Data ingestion caused some errors..')
            # ingestion error written to file
            with open('temp_event_log.txt','w', encoding='utf-8') as temp:
                temp.write(response)
            print('Response written to "temp_event_log.txt" file..')
        else:
            print("Data ingestion completed.")


# function for normalizing events to ECS format
def event_normalizer(events):
    print('Normalizing event logs to ECS format...')
    normalized_events = list()
    # reading events mapping file
    with open("sentinel_data.pkl","rb") as reader:
        mapper = pickle.load(reader)
    # normalizing system events
    for log in events['System']:
        timestamp = log['TimeGenerated'].astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        # mapping event type & event category to event ID
        if log['EventID'] in mapper['System_mapping'].keys():
            event_type = mapper['System_mapping'][log["EventID"]]
        else:
            event_type = mapper['System_mapping']['default']
        # appending data
        normalized_events.append({'event.code':log['RecordNumber'],'@timestamp':timestamp,'event.provider':log['SourceName'],'event.id':log['EventID'],'event.type':event_type,'event.category':"System",'host.hostname':log['ComputerName'],'event.module':'System'})
    # normalizing Security events
    for log in events['Security']:
        timestamp = log['TimeGenerated'].astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        # mapping event type & event category to event ID
        if log['EventID'] in mapper['Security_mapping'].keys():
            event_type = mapper['Security_mapping'][log["EventID"]]["event.type"]
            event_category = mapper['Security_mapping'][log["EventID"]]["event.category"]
        else:
            event_type = mapper['Security_mapping']["default"]["event.type"]
            event_category = mapper['Security_mapping']["default"]["event.category"]
        # appending data
        normalized_events.append({'event.code':log['RecordNumber'],'@timestamp':timestamp,'event.provider':log['SourceName'],'event.id':log['EventID'],'event.type':event_type,'event.category':event_category,'host.hostname':log['ComputerName'],'event.module':'Security'})
    # normalizing Sysmon events
    for log in events['Microsoft-Windows-Sysmon/Operational']:
        timestamp = log['TimeGenerated'].astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        # mapping event type & event category to event ID
        if log['EventID'] in mapper['Sysmon_mapping'].keys():
            event_type = mapper['Sysmon_mapping'][log["EventID"]]["event.type"]
            event_category = mapper['Sysmon_mapping'][log["EventID"]]["event.category"]
        else:
            event_type = mapper['Sysmon_mapping']["default"]["event.type"]
            event_category = mapper['Sysmon_mapping']["default"]["event.category"]
        # appending data
        normalized_events.append({'event.code':log['RecordNumber'],'@timestamp':timestamp,'event.provider':log['SourceName'],'event.id':log['EventID'],'event.type':event_type,'event.category':event_category,'host.hostname':log['ComputerName'],'event.module':'Microsoft-Windows-Sysmon/Operational'})
    # normalizing Windows Firewall events
    for log in events['Firewall']:
        timeobj = datetime.strptime(f'{log['date']} {log['time']}',"%Y-%m-%d %H:%M:%S")
        timestamp = timeobj.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
        protocol = log['protocol'].lower()
        if log['path'] == 'SEND':
            path = 'outbound'
        else: # RECIEVE traffic
            path = 'inbound'
            # print(log)
        # mapping empty data to None object
        for k in log.keys():
            if log[k] == '-':
                    log[k] = "-1"
        # appending data
        try:
            normalized_events.append({'@timestamp':timestamp,'event.action':log['action'],'network.transport':protocol,'source.ip':log['src-ip'],'source.port':int(log['src-port']),'destination.ip':log['dst-ip'],'destination.port':int(log['dst-port']),'network.bytes':int(log['size']),'network.tcp.flags.value':log['tcpflags'],'network.tcp.flags.syn':log['tcpsyn'],'network.tcp.flags.ack':log['tcpack'],'network.tcp.window_size':log['tcpwin'],'icmp.type':log['icmptype'],'icmp.code':log['icmpcode'],'message':log['info'],'network.direction':path,'process.pid':int(log['pid']),'event.module':'Firewall'})
        except KeyError as e:
            print('Parse error while normalizing firewall logs...\tSkipping.')
    print('Logs normalized to ECS format.')

    return normalized_events
