from datetime import datetime
import json
from tabulate import tabulate
from textwrap import fill

# function to get doc by id
def get_doc(client, index, doc_id):
    return client.get(index=index, id=doc_id)

# function to gather config's and display
def get_config(client,flag=False):
    data = []
    id_s = ["A1","A2","A3","B1","B2","B3","B4","B5","B6","C1","C2","C3","D1"]
    for id in id_s:
        doc = get_doc(client,"sentinel_config",id)
        # print(doc)
        row = [id,doc['_source']['name'],doc['_source']['description'],doc['_source']['content'].get('enabled','--'),doc['_source']['content'],doc['_source']['last_modified']]
        # text wrapping all columns
        data.append([fill(str(item), width=30) for item in row])
    if flag:
        # Define headers (column names)
        headers = ["ID", "Name", "Description", "Enabled", "Value(s)", "Last Modified"]
        # Print table
        print(tabulate(data, headers=headers, tablefmt="grid"))  
    return data

def update_config(client,data):
    updates = ""
    for key,val in data.items():
        # preparing doc action
        updates += json.dumps({"update":{"_index": "sentinel_config","_id":str(key)}}) + "\n"
        # preparing doc body
        updates += json.dumps({"doc":{"content": val, "last_modified": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}}) + "\n"
    # print(updates)
    # performing update
    res = client.bulk(body=updates)
    if not res['errors']:
        print('Update successfull..')
    else:
        print(f'Update unsuccessfull\nResponse: {res}')

# MAIN function to manage config settings
def sentinel_config(client):
    updates = {}
    print('---- CONFIGURATIONS ----\n')
    config = get_config(client,True) # True flag for printing config info
    while True:
        selection = input('Enter ID to change config value(s) OR "exit" to save & exit config menu\nID >').lower()
        if selection == 'exit':
            if updates:
                print('Saving configurations...')
                update_config(client,updates) 
            else:
                print('No data to update..exiting menu..')
            return None
        for row in config:
            if row[0].lower() == selection:
                print(f'Modify Value:\n{row[4]}') # prints content field
                updates[row[0]] = eval(input('Retype the above value here with necessary modifications -> hit enter\n>'))
                print('Data added to update queue..\n')
