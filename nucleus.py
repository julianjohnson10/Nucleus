from dotenv.main import load_dotenv
import os
import pandas as pd
import json
import requests
import time

"""Create an .env file and pass in your environment variables. EX: API_KEY = ABCDEF"""
load_dotenv()

PROD_ROOT_URL = os.getenv("PROD_ROOT_URL")
PROD_KEY = os.getenv("PROD_KEY")
TRIAL_ROOT_URL = os.getenv("TRIAL_ROOT_URL")
TRIAL_KEY = os.getenv("TRIAL_KEY")

class Nucleus:
    def __init__(self, projectid, trial=bool):
        self.projectid = projectid
        self.trial = trial
    def post_to_nucleus(self, outputPath):
        if self.trial == True:
            with open(outputPath, 'rb') as f:
                print(f"Posting {outputPath} to the Nucleus trial instance:")
                nucleus_url = str(TRIAL_ROOT_URL + '/projects/' + str(self.projectid) + '/scans')
                upload = requests.post(nucleus_url, files={outputPath: f}, headers={'x-apikey' : TRIAL_KEY})
        else:
            with open(outputPath, 'rb') as f:
                print(f"Posting {outputPath} to the Nucleus production instance:")
                nucleus_url = str(PROD_ROOT_URL + '/projects/' + str(self.projectid) + '/scans')
                upload = requests.post(nucleus_url, files={outputPath: f}, headers={'x-apikey' : PROD_KEY})
        if upload.raise_for_status() == None:
            pass
        else:
            print(upload.status_code)
        
        print("Done!")

    def _to_df(self, file):
        return pd.read_csv(file, dtype=object)
    
    def ren(self, df, columns):
        return df.rename(columns=columns, inplace=True)

    def ingest_vulns(self, inputPath, outputPath):
        
        # Turn file into dataframe.
        print("Ingesting vuln data...")
        
        #df = pd.read_csv(self.df, encoding="ISO-8859-1")
        df = self._to_df(inputPath)
        
        # Fill NaN values with empty strings and drop empty rows
        df.fillna("", inplace=True)
        df = df[df["IP Address"] != ""]
        
        # Get list of targets
        targets = df["IP Address"].unique().tolist()
        
        # Get scan date
        scan_date = pd.to_datetime(df["Detection_Date"]).min()
        
        # Parse dataframe and convert to findings JSON
        assets = []
        for target in targets:
            targets_df = df[df["IP Address"]==target]
            
            # Populate asset record
            asset_info = {
                "pentest.category": targets_df.iloc[0]["Category"],
            }
            findings = []
            for i in range(len(targets_df)):
                if i == len(targets_df):
                    continue
                find_refs = {
                    "Target": targets_df.iloc[i]["IP Address"],
                    "Exploitability": targets_df.iloc[i]["Exploitability"],
                    "CVSS Base Score": targets_df.iloc[i]["Score"]
                }
                finding = {
                    "finding_number": targets_df.iloc[i]["Finding"],
                    "finding_name": targets_df.iloc[i]["Finding"],
                    "finding_description": "{}\n{}".format(targets_df.iloc[i]["Description"], targets_df.iloc[i]["Notes"]),
                    "finding_recommendation": targets_df.iloc[i]["Resolution"],
                    "finding_references": find_refs,
                    "finding_output": "Target: {}\nExploitability: {}\nValidation Date: {}\nNotes: {}".format(
                        targets_df.iloc[i]["IP Address"], targets_df.iloc[i]["Exploitability"],
                        targets_df.iloc[i]["Validation_Date"], targets_df.iloc[i]["Comment"]),
                    "finding_severity": targets_df.iloc[i]["Severity"]
                }
                findings.append(finding)
            # create asset object and append to assets list
            asset = {
                "ip_address": target,
                "findings": findings,
                "asset_info": asset_info
            }
            assets.append(asset)
        # Generate scan object
        scan_obj = {
            "nucleus_import_version": "1",
            "scan_tool": "Scan",
            "scan_type": "Host",
            "scan_date": str(scan_date),
            "assets": assets
        }
        # write JSON to output file
        with open(outputPath, "w") as outfile:
            json.dump(scan_obj, outfile)
            return outfile
    def ingest_assets(self, inputPath, outputPath):
        print("Ingesting asset data...")
        
        # Create dataframe from cmdb file
        df = self._to_df(inputPath)
        
        # Get rid of NaN values
        df.fillna("", inplace=True)

        #Fill with columns you want in the dataframe
        df.rename(columns={
        "Aggregated: Asset Unique ID": "Asset ID", 
        "Aggregated: Last Used Users": "Last User",
        "Aggregated: First Seen": "First Seen",
        "Aggregated: Last Seen": "Last Seen",
        "Aggregated: Boot Time": "Last Boot Time",
        "Aggregated: Network Interfaces: MAC": "MAC Address",
        "Aggregated: OS: Type":"OS Name",
        "Aggregated: OS: Type and Distribution": "OS Version",
        "Aggregated: Host Name" : "Host Name",
        "Aggregated: Network Interfaces: IPv4s" : "IP Address",
        "Aggregated: Uptime (Days)": "Uptime (Days)",
        "Assets[Managed by]" : "Managed by"} , inplace=True)
        
        # Drops the rest of the columns. Keeps only the columns listed below.
        df = df[[
        "Asset ID",
        "Last User",
        "Owned by",
        "Managed by",
        "Supported by",
        "Management Group",
        "Support group",
        "First Seen",
        "Last Seen",
        "Last Boot Time",
        "Uptime (Days)",
        "Host Name",
        "IP Address",
        "MAC Address",
        "OS Name",
        "OS Version"
        "Compliance Whatever"
        ]]
        
        df.to_csv('assets.csv')
        
        # JSON parsing
        assets = []
        
        for i in range(len(df)):
            asset_info = {
                "cmdb.asset_id": df.loc[i, "Asset ID"],
                "cmdb.last_user": df.loc[i, "Last User"],
                "cmdb.owned_by": df.loc[i, "Owned by"],
                "cmdb.managed_by": df.loc[i, "Managed by"],
                "cmdb.supported_by": df.loc[i, "Supported by"],
                "cmdb.management_group": df.loc[i, "Management Group"],
                "cmdb.support_group": df.loc[i, "Support group"],
                "cmdb.asset_name": df.loc[i, "First Seen"],
                "cmdb.asset_name": df.loc[i, "Last Seen"],
                "cmdb.last_boot_time": df.loc[i, "Last Boot Time"],
                "cmdb.asset_name": df.loc[i, "Uptime (Days)"],
            }
            asset = {
                "host_name": df.loc[i, "Host Name"],
                "ip_address": df.loc[i, "IP Address"],
                "mac_address": df.loc[i, "MAC Address"],
                "operating_system_name": df.loc[i, "OS Name"],
                "operating_system_version": df.loc[i, "OS Version"],
                "asset_info": asset_info
            }
            assets.append(asset)
        scan_obj = {
            "nucleus_import_version": "1",
            "scan_tool": "Asset",
            "scan_type": "Host",
            "assets": assets
        }
        
        with open(outputPath, "w") as outfile:
            json.dump(scan_obj, outfile)
            print("Done!")
        
    def get_findings(self):
        params = None
        count = 0
        limit = 100
        findings_summary = str(NUCLEUS_ROOT_URL + '/projects/' + str(self.projectid) + '/findings/summary')
        while count < 6000:
            params.append({'start': count, 'limit': limit})
            count += limit
        print('Starting!')
        for param in params:
            start = time.time()
            print(f"Working on {param['start']} of {count}")
            response = requests.post(findings_summary, data={}, headers={'x-apikey': API_KEY, 'accept': 'application/json'}, params=param)
            df = pd.read_json(response.text)
            df.to_csv("findings.csv", mode='a', index=False)
            end = time.time()
            total_time = end - start
            print(f"It took {total_time} to run the last call.")
        
        df = pd.read_csv('findings.csv')
        df = df.iloc[: , 1:]
        df = df[~df.asset_count.str.contains('asset_count')]
        df.to_csv('findings_test.csv', index=False)
   
    def get_issues(self):
        issues = str(NUCLEUS_ROOT_URL + '/projects/' + str(self.projectid) + '/issues')
        p = {'start': '0', 'limit': '100'}
        rq = requests.get(issues, params=p, headers={'x-apikey': API_KEY})
        
        print(rq.json())
    
    def get_assetgroups(self):
        asset_groups = str(PROD_ROOT_URL + '/projects/' + str(self.projectid) + '/assets/groups')
        rq = requests.get(asset_groups, params=None, headers={'x-apikey': PROD_KEY})
        df = pd.read_json(rq.content)
        search = ['Management Group', 'Support Group']
        groups_final = []
        groups = df[df['asset_group'].str.contains('|'.join(search))]
        for line in groups['asset_group']:
            split = str(line).split('/',2)
            try:
                split_ind = (split)[2]
                groups_final.append(split_ind)
            except: IndexError
    
        groups_final = pd.DataFrame(groups_final, columns=['asset_group'])
        print(groups_final)
        return groups_final

    def create_team(self, team):
        url = str(PROD_ROOT_URL + '/projects/' + str(self.projectid) + '/teams')
        payload = {"team_name": team}
        rq = requests.post(url, headers={'x-apikey': PROD_KEY}, data=json.dumps(payload))
        
        print(rq.content)

def main():
    prod = Nucleus(projectid='xxxxxx')
    prod.ingest_assets(inputPath="C:\\asset.csv", outputPath="assets.json")
    prod.post_to_nucleus(outputPath="assets.json")
    
    
    for group in groups['asset_group']:
        prod.create_team(group)
if __name__  == '__main__':
    main()
    
