from opensearchpy import OpenSearch
from datetime import datetime
import json


THREAT_INTEL_MAPPING =  {
    "mappings": {
      "properties": {
        "abuse_score": {
          "type": "long"
        },
        "city": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "country": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "date_enriched": {
          "type": "date"
        },
        "enrichment": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "event": {
          "properties": {
            "module": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        },
        "geoip_alert": {
          "type": "boolean"
        },
        "ip": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "ip_version": {
          "type": "long"
        },
        "is_tor": {
          "type": "boolean"
        },
        "location": {
          "type": "geo_point"
        },
        "malicious_alert": {
          "type": "boolean"
        },
        "region": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        }
      }
    }
  }

WINDOWS_LOG_MAPPING = {
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "destination": {
          "properties": {
            "ip": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "port": {
              "type": "long"
            }
          }
        },
        "event": {
          "properties": {
            "action": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "category": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "code": {
              "type": "long"
            },
            "id": {
              "type": "long"
            },
            "module": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "provider": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "type": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        },
        "host": {
          "properties": {
            "hostname": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "name": {
              "type": "alias",
              "path": "host.hostname"
            }
          }
        },
        "icmp": {
          "properties": {
            "code": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "type": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        },
        "message": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "network": {
          "properties": {
            "bytes": {
              "type": "long"
            },
            "direction": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "tcp": {
              "properties": {
                "flags": {
                  "properties": {
                    "ack": {
                      "type": "text",
                      "fields": {
                        "keyword": {
                          "type": "keyword",
                          "ignore_above": 256
                        }
                      }
                    },
                    "syn": {
                      "type": "text",
                      "fields": {
                        "keyword": {
                          "type": "keyword",
                          "ignore_above": 256
                        }
                      }
                    },
                    "value": {
                      "type": "text",
                      "fields": {
                        "keyword": {
                          "type": "keyword",
                          "ignore_above": 256
                        }
                      }
                    }
                  }
                },
                "window_size": {
                  "type": "text",
                  "fields": {
                    "keyword": {
                      "type": "keyword",
                      "ignore_above": 256
                    }
                  }
                }
              }
            },
            "transport": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            }
          }
        },
        "process": {
          "properties": {
            "pid": {
              "type": "long"
            }
          }
        },
        "source": {
          "properties": {
            "ip": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "port": {
              "type": "long"
            }
          }
        },
        "timestamp": {
          "type": "alias",
          "path": "@timestamp"
        },
        "windows": {
          "properties": {
            "message": {
              "type": "alias",
              "path": "message"
            }
          }
        },
        "winlog": {
          "properties": {
            "channel": {
              "type": "alias",
              "path": "event.module"
            },
            "event_data": {
              "properties": {
                "Action": {
                  "type": "alias",
                  "path": "event.action"
                },
                "DestAddress": {
                  "type": "alias",
                  "path": "destination.ip"
                },
                "EventType": {
                  "type": "alias",
                  "path": "event.type"
                },
                "IpAddress": {
                  "type": "alias",
                  "path": "source.ip"
                },
                "ProcessId": {
                  "type": "alias",
                  "path": "process.pid"
                },
                "TargetPort": {
                  "type": "alias",
                  "path": "destination.port"
                }
              }
            },
            "event_id": {
              "type": "alias",
              "path": "event.id"
            },
            "provider_name": {
              "type": "alias",
              "path": "event.provider"
            }
          }
        }
      }
    }
  }


def create_client(username,password):
    host = 'localhost'
    port = 9200
    auth = (username, password)

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

# LISTING ALL THE INDICES PRESENT
def list_indices(client):
  indices_info = client.cat.indices(format="json")
  ind = 0
  print('No.\tHealth\tStatus\tIndex Name\t\t\tSize')
  for index in indices_info:
      ind+=1
      print(f'{ind}\t{index["health"]}\t{index["status"]}\t{index["index"]}\t{index["store.size"]}')

# function for creating a new index (table)
def create_index(client,index_name,mapping=None):
    if mapping:
       index_body = mapping
    else:
        index_body = {
        'settings': {
            'index': {
                'number_of_shards': 1,
                'number_of_replicas': 0 
                }
            }
        }
    return client.indices.create(index_name, body=index_body)

# INDEXING A DOCUMENT (adding a document to the index)
def index_doc(client,index,doc,id=None): # doc is a key:value pair ( key is the row name )
   if id:
      res = client.index(
         index = index,
         body = doc,
         id = id,
         refresh = True
   )
   else:
      res = client.index(
         index = index,
         body = doc,
         refresh = True
      )
   return res 

def search_index(client,index,query,field_list):
   bod = {
      'size': 10, # max results to return
      'query': {
         'multi_match': {
            'query': query,
            'fields': field_list # a list containing field names
         }
      }
   }
   return client.search(
      body = bod,
      index = index
   )

def delete_index(client,index):
   return client.indices.delete(index = index)

# First run Config Set-up
def set_config(client):
    # populating index with config values
    docs = [
        {
            "_index": "sentinel_config",
            "_id": "A1",
            "_source": {
                "name": "AbusePDB API",
                "description": "Enable/Disable AbusePDB Threat Intelligence API",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "A2",
            "_source": {
                "name": "VirusTotal API",
                "description": "Enable/Disable VirusTotal Threat Intelligence API",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "A3",
            "_source": {
                "name": "GeoIP API",
                "description": "Enable/Disable GeoIP Threat Intelligence API",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B1",
            "_source": {
                "name": "System Logs (Windows)",
                "description": "Enable/Disable ingestion of system logs (Windows)",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B2",
            "_source": {
                "name": "Firewall Logs (Windows)",
                "description": "Enable/Disable Windows Defender Firewall log ingestion.",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B3",
            "_source": {
                "name": "Sysmon Logs (Windows)",
                "description": "Enable/Disable Sysmon log ingestion.",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B4",
            "_source": {
                "name": "Auth Logs (Linux)",
                "description": "Enable/Disable Auth log ingestion.",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B5",
            "_source": {
                "name": "Sysl Logs (Linux)",
                "description": "Enable/Disable Sys log ingestion.",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "B6",
            "_source": {
                "name": "Audit Logs (Linux)",
                "description": "Enable/Disable Audit log ingestion.",
                "content": {"enabled": True},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "C1",
            "_source": {
                "name": "Malicious Score Alert",
                "description": "Enable/Disable and set threshold value for alerts based on malicious score of network traffic.",
                "content": {"enabled": True, "threshold": 80},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "C2",
            "_source": {
                "name": "GeoIP Alert",
                "description": "Enable/Disable and set blacklist value(s) for GeoIP alerts.",
                "content": {"enabled": True, "blacklist": []},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "C3",
            "_source": {
                "name": "Authentication Failure Alerts",
                "description": "Enable/Disable and set threshold value for authentication failure alerts.",
                "content": {"enabled": True, "threshold": 5},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
        {
            "_index": "sentinel_config",
            "_id": "D1",
            "_source": {
                "name": "Log Retention Period",
                "description": "Set log retention period value, min:1 month | max 12 months.",
                "content": {"period": 2},
                "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        },
    ]

    # format it properly for OpenSearch Bulk API
    bulk_data = ""
    for doc in docs:
        meta = {"index": {"_index": doc["_index"], "_id": doc["_id"]}} # initial "index" can be changed to do other operations like update etc.
        bulk_data += json.dumps(meta) + "\n"
        bulk_data += json.dumps(doc["_source"]) + "\n"
    conf_res = client.bulk(body=bulk_data)
    if not conf_res['errors']:
        print(' Configurations set up completed.')
        return True
    else:
        print(f'Could not create configurations..\nResponse: {conf_res}')
        return False

# Initial set-up manager
if __name__ == '__main__':
   print('Blue Sentinel Tool-Kit\n\nEnter your OpenSearch Credentials.\n(Provided on docker_compose.yml file)\n>')
   username = input("Enter username:")
   password = input("Enter password:")
   client = create_client(username,password)
   while True:
    selct = int(input('Select one option\n1.Start Initial Set-up\n2.Create New Index\n3.Delete a Index\n4.List all Indices\n5.Exit\n>'))
    if selct == 1:
        print('Setting up environment for Blue Sentinel..\nCreating necessary indices..')
        # create config index
        config_resp = create_index(client,"sentinel_config")
        if config_resp['acknowledged']:
            print('Config index created...')
        else:
            print(f'Error while creating config index: \n{config_resp}')
            break
        # populating config values
        value_resp = set_config(client)
        if not value_resp:
           break
        # creating Log indices
        winlog_resp = create_index(client,"sentinel_windows",WINDOWS_LOG_MAPPING)
        if winlog_resp['acknowledged']:
            print('Log index created...')
        else:
            print(f'Error while creating log index: \n{config_resp}')
            break
        intel_resp = create_index(client,"windows_intel",THREAT_INTEL_MAPPING)
        if intel_resp['acknowledged']:
            print('Threat Intel index created...')
        else:
            print(f'Error while creating Threat Intel index: \n{config_resp}')
            break
        print('Blue Sentinel Environment Set-up complete.')
    elif selct == 2:
        resp = create_index(client,input('Enter new index name:(no caps|no space)'))
        if resp['acknowledged']:
           print('Index created.')
        else:
           print(f'Error while creating index: \n{config_resp}')
           break
    elif selct == 3:
       resp = delete_index(client,input('Enter index name to delete:'))
       print(resp)
    elif selct == 4:
       print('Lisitng all indices')
       list_indices(client)
    elif selct == 5:
       exit()
       
        

