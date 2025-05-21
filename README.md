# Blue Sentinel
A Security Information and Event Management (SIEM) System using Python and OpenSearch
## Features
•	A Security Information and Event Management System with Threat Intelligence detection and alerting.  
•	Event sources include: Windows System logs, Windows Defender Firewall logs and Sysmon logs.  
•	Technologies Used:  
o	Python – Log extraction, parsing and ingestion pipeline + Threat Intelligence backend engine.  
o	OpenSearch – Log database for indexing and querying  
o	OpenSearch Dashboards – To provide visual insights into event’s data.  
•	Logs from multiple sources are normalized to ECS format for easier detection and compatibility with OpenSearch (reference used: https://www.elastic.co/docs/reference/ecs/ecs-field-reference)  
•	Backend Config:  
o	Python backend allows config editing for custom triggers like malicious alert score limit, Geo-IP blacklisting of cities, regions or countries and authentication failure alerts.  
o	Config can also be modified to enable\disable threat intel API’s further giving more control for customizing detection rules.    
•	Threat Intelligence Enrichment  
o	Windows Firewall logs are enriched with threat intel data from AbusePDB, Virus Total and IPInfo APIs for malicious score rating, IP reputation and TOR detection.  
o	Tracing IP to its City, Region and Country based locations and finally enabling custom thresholds for malicious score alerts and custom blacklisting for Geo-IP tracking alerts.  
•	Dashboards (OpenSearch Dashboards)  
o	Summarized into 8 visualizations for deep insights into system and network events of the host.
o	Threat Alerts: A table displaying the details of events which triggered alerts.
o	IP Status: A pie chart showing IP enrichment status categorized into Clean, Probably Clean, Suspicious, Dangerous and Not Categorized based on the malicious score.
o	IP Location Intel: A world map with IP locations marked to track the incoming traffic locations.
o	Firewall Traffic (Known Ports): A bar chart which maps the network events traffic into know services to provide better insights into network activity.
o	Firewall Logs: A table displaying the recent firewall logs summarized to include only necessary fields.
o	Event Category: A bar chart mapping events to specific category based on its Event-ID.
o	Event Types: A pie chart splitting events into slices based on its event type, which is derived based on its Event-ID.
o	Event Logs: A table displaying recent events.
o	This dashboard can be imported to your OpenSearch dashboards by going to : Dashboard Management > Saved Objects > Import > select the “Dashboard_setup.ndjson” file.  

## Running the Blue Sentinel System (Windows System)
•	Requirements
o	Docker Desktop Application
o	WSL Enabled System
o	SysInternals-Suite
•	Install OpenSearch & OpenSearch Dashboards
o	Open “docker-compose.yml” file from the script directory with a text editor.
o	Change “[ YOUR-PASSWORD-HERE ]” with a strong password of your choice.
o	Open PowerShell as administrator, change directory to the folder where “.yml” file is stored and run “docker compose up -d”.
o	This will download OpenSearch & OpenSearch Dashboards Docker images onto your system, create & run the containers.
o	Note: “docker compose down” can be used to stop the container.
•	 Initial set-up for Blue Sentinel backend script
o	While the OpenSearch container is running, change current directory to the location where the backend script is stored. 
o	Create a python virtual environment, activate it. Then install all the dependencies from “requirements.txt” file. [ use command: pip install -r requirements.txt ]
o	Now run the script “sentinel_toolkit.py” and enter your OpenSearch username (“admin” by default) & password, then select option “Start Initial Set-up” to create necessary indices with required mappings. 
o	This script also contains some additional options, for OpenSearch client operations.

•	Enabling Log Sources
o	Windows Firewall:
	Open Windows Defender Firewall with Advanced Security (run as administrator).
	Go to Actions > Properties > Logging 
	Select Customize > select a path for saving logs (preferably somewhere you have permission to access the files.)
	Select “Yes” for both logging successful connections and dropped packets, click ok. (enable for Domain, Private and Public profiles.)
o	SysLog:
	Download syslog configuration file: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
	Make sure that you have SysInternals-Suite extracted and ready.
	Go to folder where SysInternals-Suite is located, open CMD as administrator, run command: Sysmon64.exe -accepteula -i "<Path to file>\sysmonconfig-export.xml"
	Confirm that the log is being stored by running Event Viewer as administrator, and navigate to: Application & Services > Microsoft > Windows > Sysmon > Operational (shows list of logs collected.) 
•	Running Blue Sentinel backend script
o	Modify the files “blue_sentinel.py”, “sentinel_intel.py”, populate it with your OpenSearch username, password and API keys for AbusePDB, Virus Total and IPInfo API’s.
o	Run “blue_sentinel.py” to start the backend script.
o	You can start the log ingestion directly with the default configurations or make tweaks to configurations by selecting option “Edit Configurations”.

