import platform, pyfiglet, ctypes, sys, os, win32evtlog, pickle
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch
from sentinel_config import sentinel_config,get_config
import time
from sentinel_ingest import event_normalizer, event_ingest
from sentinel_intel import threat_intel


# function to create client
def create_client():
    host = 'localhost'
    port = 9200
    auth = ('admin', 'ADD YOUR PASSWORD')

    client = OpenSearch(
        hosts= [{'host': host, 'port': port}],
        http_compress = True,
        http_auth = auth,
        use_ssl = True,
        verify_certs = False,
        ssl_assert_hostname = False,
        ssl_show_warn = False, 
    )
    return client

# admin self-elevation
def check_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print('Blue Sentinel needs escalated privileges.\nRun script in Admin Mode!')
        sys.exit()
    else:
        print('Checking admin-privileges...\tSuccess.')

# function for log life cycle maintenance
def log_cycle(client,config):
    retention = None
    # get config value
    if config[12][0] == 'D1':
        data = eval(config[12][4])
        retention = data['period'] * 30 # converting to date
        # print(retention) 
    if retention is None:
        print('Could not fetch retention value...\tFailed.')
        return None
    # preparing query
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=retention)).isoformat().replace("+00:00", "Z")
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "lt": cutoff_date
                }
            }
        }
    }
    # checking sentinel_windows logs
    response = client.delete_by_query(
        index = "sentinel_windows",
        body = query,
        conflicts = "proceed",
        refresh = True,
        wait_for_completion = True
    )
    print(f'Checking outdated logs...\t{response['deleted']} logs deleted.')
    
# windows events log reader
def events_reader(server,log_type):
    # getting current log state
    with open('sentinel_data.pkl','rb') as file:
        last_event = pickle.load(file)
        # print(f'last event : {last_event}')
    
    hand = win32evtlog.OpenEventLog(server, log_type)
    events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
    logs = list()
    for event in events:
        if event.TimeGenerated > datetime.fromisoformat(last_event[log_type+'_logs_last_read']):
            logs.append({'RecordNumber':event.RecordNumber,'TimeGenerated':event.TimeGenerated,'SourceName':event.SourceName,'EventID':event.EventID,'EventType':event.EventType,'EventCategory':event.EventCategory,'ComputerName':event.ComputerName})

    # updating log state
    with open('sentinel_data.pkl','wb') as file:
        if events:
            last_event[log_type+'_logs_last_read'] = events[0].TimeGenerated.isoformat() #converts to string
        pickle.dump(last_event,file)

    print(f'{log_type}: {len(logs)} logs collected')

    return logs

# function to collect windows logs
def windows_log(config):
    server = 'localhost' 
    windows_logs = dict()
    # row[3]-B1-System logs | row[4]-B2-Firewall logs | row[5]-B3-Sysmon Logs
    # Collecting system & security logs
    if config[3][0] == 'B1':
        verify = eval(config[3][4])
        if verify['enabled'] == True:
            log_type = 'System'
            print('Collecting System logs...')
            windows_logs[log_type] = events_reader(server,log_type)
            # collecting security logs
            log_type = 'Security'
            print('Collecting Security logs...')
            windows_logs[log_type] = events_reader(server,log_type)
    # collecting FIREWALL logs (Windows Defender Firewall)
    if config[4][0] == 'B2':
        verify = eval(config[4][4])
        if verify['enabled'] == True:
            log_path = "PATH-TO-YOUR-LOG"
            parsed_log = list()
            log_type = "Firewall"
            print('Collecting Firewall logs...')
            # getting current log state
            with open('sentinel_data.pkl','rb') as file:
                last_event = pickle.load(file)
            # enable retry for file reading (when file is in exclusive write mode)
            for i in range(5):
                try:
                    with open(log_path,"r") as f:
                        data = f.readlines()
                    break
                except PermissionError:
                    time.sleep(0.5) # wait and retry
            # parsing logs
            fields = data[3].replace("#Fields:","").strip().split()
            for line in data[6:]:
                if line.strip():
                    parsed_log.append(dict(zip(fields, line.strip().split())))
            # Verifying & removing log redundancy
            parsed_log = [log for log in parsed_log if datetime.strptime(f'{log['date']} {log['time']}',"%Y-%m-%d %H:%M:%S") > last_event[log_type+'_logs_last_read']]
            print(f'{log_type}: {len(parsed_log)} logs collected')
            # print(parsed_log[0])
            # updating log state
            with open('sentinel_data.pkl','wb') as file:
                if parsed_log:
                    timestamp = f'{parsed_log[-1]['date']} {parsed_log[-1]['time']}'
                    last_event[log_type+'_logs_last_read'] = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    pickle.dump(last_event,file)
            # appending logs data 
            windows_logs[log_type] = parsed_log
    # collecting sysmon logs
    if config[5][0] == "B3":
        verify = eval(config[5][4])
        if verify['enabled'] == True:
            log_type = 'Microsoft-Windows-Sysmon/Operational'
            print('Collecting Sysmon logs...')
            windows_logs[log_type] = events_reader(server,log_type)
            
    return windows_logs

# Main
if __name__ == '__main__':
    check_admin()
    client = create_client()
    # get current config
    config = get_config(client) # row[0] = ID | row[4] = VALUE(S)
    log_cycle(client,config) # delete old logs
    while True:
        print(pyfiglet.figlet_format("BLUE SENTINEL", font="straight"))
        select = int(input('Log Analysis & Threat Mitigation\n\nSelect one option to proceed\n1.Start Log Ingestion\n2.Edit Configurations\n3.Exit\n>'))
        if select == 1:
            os = platform.system()
            if os == 'Windows':
                print('Windows OS detected...')
                event_updates = windows_log(config)
                # windows log normalization
                normalized_events = event_normalizer(event_updates)
                if normalized_events is None:
                    continue
                # ingesting data
                event_ingest(client,"sentinel_windows",normalized_events)
                # producing threat intel enriched data
                print('Enriching events with Threat Intel')
                enriched_events = threat_intel(normalized_events,config)
                print('Events enriched..')
                # ingesting enriched events
                event_ingest(client,"windows_intel",enriched_events)
                # enriched events written to temp file
                with open('temp_event_log.txt','w', encoding='utf-8') as temp:
                    for item in enriched_events:
                        temp.write(f'{item}\n')
                print('Log collection completed.')
            elif os == 'Linux':
                print('Unsupported OS..\nExiting..')
                exit()
            # code for log simulation (linux)
        elif select == 2:
            sentinel_config(client)
        elif select == 3:
            exit()