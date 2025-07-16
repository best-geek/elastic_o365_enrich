import argparse
from elasticsearch import Elasticsearch
import requests
import logging 
import json
import time
import sys
import random
import pprint as pp
from datetime import datetime, timedelta, timezone

logging.basicConfig(format="[%(filename)s:%(lineno)d] [fun:%(funcName)s] %(asctime)s [%(levelname)s] %(message)s", datefmt="%m/%d/%Y_%I:%M:%S")
logging.root.setLevel(logging.INFO)

def infer_es_mapping(obj):
    def map_value(value):
        if isinstance(value, dict):
            return {"type": "object", "properties": infer_properties(value)}
        elif isinstance(value, list):
            if not value:
                return {"type": "object"}  # unknown type, empty list
            first = value[0]
            if isinstance(first, dict):
                return {
                    "type": "nested",
                    "properties": infer_properties(first),
                }
            elif isinstance(first, str):
                return {"type": "text", "is_array": True}
            elif isinstance(first, int):
                return {"type": "long", "is_array": True}
            elif isinstance(first, float):
                return {"type": "float", "is_array": True}
            elif isinstance(first, bool):
                return {"type": "boolean", "is_array": True}
            else:
                return {"type": "text", "is_array": True}
        elif isinstance(value, str):
            return {"type": "text"}
        elif isinstance(value, bool):
            return {"type": "boolean"}
        elif isinstance(value, int):
            return {"type": "long"}
        elif isinstance(value, float):
            return {"type": "float"}
        else:
            return {"type": "text"}

    def infer_properties(obj):
        properties = {}
        for key, value in obj.items():
            properties[key] = map_value(value)
        return properties

    return {"properties": infer_properties(obj)}

def prime_record_infer_mappings(cache):
    best_key = max(cache, key=cache.get("infer_quality"))
    return best_key
    

    
class GraphApi:
    def request_access_flow_token(self) -> str:
        """Get a Microsoft 'authorization bearer' header from the Ouath2 API

        Returns:
            str: returns the string response of HTTP data. Should be then inputted into a JSON parser
        """

        # look to see if we can just return a current token stored in class. Note on initialisation
        # the attibute is not yet registered, so we just skip by
        expiredToken = False
        try:
            if int(time.time()) > int(self.active_token.get("expires_on",0)):
                expiredToken = True

            if not expiredToken:
                return self.active_token
        except AttributeError:
            pass


        base_domain = "https://login.microsoftonline.com"
        full_url = f"{base_domain}/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "client_id":self.client_id,
            "client_secret":self.client_secret,
            "grant_type":"client_credentials",
            "scope":"https://graph.microsoft.com/.default"    
        }

        # run fetch attempts for flow token until we exceed tries of do not get 200 HTTP code
        successful_token = False
        attempts = 0
        max_try = 4
        while not successful_token:
            r = requests.post(full_url, data=payload)
            if r.status_code == 200:
                logging.info("Acquired Microsoft Flow Token")
                token = json.loads(r.text)
                token['expires_on'] = int(time.time()) + (token.get('expires_in', 0) - 10) # make a note of when the token is going to expire. This way we can re-use
                return token

            else:
                logging.warning("[Try:{}/{}] Getting Microsoft Access Flow Token has failed.".format(attempts, max_try))
                attempts+=1
                time.sleep(1)
            
            if attempts == max_try:
                logging.error(f"Could not get Microsoft API flow token. Check the Azure AD application secret has not expired and is correct. {r.text} {r.status_code}")
                print(r.text)
                sys.exit(2)
        
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        
        # test we can get a token and cache it
        self.active_token = self.request_access_flow_token()


    def authenticated_graph_get(self, uri='', append_values=True, ver='1.0', **params):
            
            time.sleep((random.randint(0,50))/100)
            
            token = self.request_access_flow_token()
            
            base_url = f"https://graph.microsoft.com/v{ver}/{uri}"
            if not append_values:
                base_url = uri
            headers = {"Authorization":f"Bearer {token['access_token']}"}
            
            max_try = 2
            attempts = 0
            while True:
                r = requests.get(base_url, headers=headers, params=params)
                if r.status_code == 200:
                    logging.info(f"Acquired response for {base_url}")
                    return json.loads(r.text)
                else:
                    attempts+=1
                    time.sleep(1)
                    
                if attempts == max_try:
                    logging.error(f"Could not get {base_url} due to: {r.text}")
                    return None
                    
        
    def get_users(self):
        user_list = []
        users = self.authenticated_graph_get(uri="users?$select=id,userPrincipalName")
        if users: user_list.extend(users.get("value", []))
        if users and users.get("@odata.nextLink", None):
            while users.get("@odata.nextLink", None):
                users = self.authenticated_graph_get(uri=users['@odata.nextLink'], append_values=False)
                if users: users.extend(users.get("value", []))
                
        return user_list
    
    def get_auth_methods(self, upn=None):
        if not upn:
            raise ValueError("upn must be populated")
        methods_list = []
        methods = self.authenticated_graph_get(uri=f"users/{upn}/authentication/methods")
        if methods: methods_list.extend(methods.get("value", []))
        if methods and methods.get("@odata.nextLink", None):
            while methods.get("@odata.nextLink", None):
                methods = self.authenticated_graph_get(uri=methods['@odata.nextLink'], append_values=False)
                if methods: methods_list.extend(methods.get("value", []))
                
        return methods_list

    def get_eligible_roles(self, upn=None):
        if not upn:
            raise ValueError("upn must be populated")
        roles_list = []
        roles = self.authenticated_graph_get(uri=f"roleManagement/directory/roleEligibilityScheduleRequests?$filter=principalId eq '{upn}'")
        if roles: roles_list.extend(roles.get("value", []))
        if roles and roles.get("@odata.nextLink", None):
            while roles.get("@odata.nextLink", None):
                roles = self.authenticated_graph_get(uri=roles['@odata.nextLink'], append_values=False)
                if roles: roles_list.extend(roles.get("value", []))
                
        return roles_list

    def get_scheduled_roles(self, upn=None):
        if not upn:
            raise ValueError("upn must be populated")
        roles_list = []
        roles = self.authenticated_graph_get(uri=f"/roleManagement/directory/roleAssignmentScheduleRequests?$filter=principalId eq '{upn}'")
        if roles: roles_list.extend(roles.get("value", []))
        if roles and roles.get("@odata.nextLink", None):
            while roles.get("@odata.nextLink", None):
                roles = self.authenticated_graph_get(uri=roles['@odata.nextLink'], append_values=False)
                if roles: roles_list.extend(roles.get("value", []))
                
        return roles_list
  
    def get_last_password_change(self, upn=None):
            if not upn:
                raise ValueError("upn must be populated")

            
            last_set = self.authenticated_graph_get(uri=f"users/{upn}?$select=lastPasswordChangeDateTime")
            if last_set:
                return last_set.get("lastPasswordChangeDateTime", "")
            else:
                return ""

    def get_user_groups(self, upn=None, require_name=True):
        # require name menas a display name is required
        if not upn:
            raise ValueError("upn must be populated")
        groups_list = []
        groups = self.authenticated_graph_get(uri=f"users/{upn}/memberOf?$select=id,displayName,groupTypes")
        if groups: groups_list.extend(groups.get("value", []))
        if groups and groups.get("@odata.nextLink", None):
            while groups.get("@odata.nextLink", None):
                groups = self.authenticated_graph_get(uri=groups['@odata.nextLink'], append_values=False)
                if groups: groups_list.extend(groups.get("value", []))

        if require_name:
            groups_list = [g for g in groups_list if g.get("displayName", "null") != "null" and g.get("displayName", None)]                
        return groups_list
    
    def get_assigned_roles(self, upn=None):
        if not upn:
            raise ValueError("upn must be populated")
        
        user_groups = self.get_user_groups(upn)
        assigned_roles = [g for g in user_groups if g.get("@odata.type", "") == "#microsoft.graph.directoryRole"]
        return assigned_roles
                
        

def main():
    parser = argparse.ArgumentParser(description="Arg parser to get Entra information")
    parser.add_argument(
        "-t", "--tenant_id", type=str, required=True, default=None, help="The tenant ID used for the registered application"
    )
    parser.add_argument(
        "-ci", "--client_id", type=str, required=True, default=None, help="The client ID used for registered application"
    )
    parser.add_argument(
        "-cs", "--client_secret", type=str, required=True, default=None, help="SSL key file (default: key.pem)"
    )
    parser.add_argument(
        "-eo", "--elastic_output", type=str, required=True, default=None, help="The elastic output destination"
    )
    parser.add_argument(
        "-eapi", "--elastic_api_key", type=str, required=True, default=None, help="The elastic api to authenticate with"
    )
    parser.add_argument(
        "-r", "--refresh_every", type=int, default=60, help="The amount of time to sleep between cycles"
    )
    args = parser.parse_args()

    
    # init our class
    Graph = GraphApi(tenant_id=args.tenant_id, client_id=args.client_id, client_secret=args.client_secret)
    
    # initialise and add everybody as a key
    cache = {}
    users = Graph.get_users()
    for u in users:
        try:
            upn = u['userPrincipalName']
        except KeyError: # for some reason we have no results
            continue
    
        if upn not in cache:
            cache[upn] = {}
            
    for upn in list(cache.keys()):
        auth_methods = Graph.get_auth_methods(upn)
        group_membership =  Graph.get_user_groups(upn)
        scheduled_roles = Graph.get_scheduled_roles(upn)
        eligible_roles = Graph.get_eligible_roles(upn)
        assigned_roles = Graph.get_assigned_roles(upn)
        password_last_set = Graph.get_last_password_change(upn)
        now = datetime.now(timezone.utc)
        
        cache[upn]["auth_methods"] = auth_methods
        cache[upn]["group_membership"] = group_membership
        cache[upn]["scheduled_roles"] = scheduled_roles
        cache[upn]["eligible_roles"] = eligible_roles
        cache[upn]["assigned_roles"] = assigned_roles
        cache[upn]["last_password_change"] = password_last_set
        cache[upn]["last_enriched"] = now.isoformat()
        cache[upn]["upn_enrich"]=upn
        
        # we will create a mapping based on a record that has the highest 
        # quality index
        infer_quality  = 0
        if auth_methods: infer_quality +=1
        if group_membership: infer_quality +=1
        if scheduled_roles: infer_quality +=1
        if eligible_roles: infer_quality +=1
        if assigned_roles: infer_quality +=1
        if password_last_set: infer_quality +=1
        cache[upn]["infer_quality"] = infer_quality
        

    logging.info(f"Processed {len(cache)} users in cache")

    if cache:    
        # output to elastic
        index_name = f"o365_userdata_enrich"
        
        
        mapping = infer_es_mapping(cache[prime_record_infer_mappings(cache)])
        print(f"Mappings:\n{mapping}")
        
        
        es = Elasticsearch(args.elastic_output, verify_certs=False, api_key=args.elastic_api_key)
        if not es.indices.exists(index=index_name):
            es.indices.create(index=index_name, body={"mappings":mapping})
            logging.info(f"Index '{index_name}' created with mapping.")
        
        for upn in list(cache.keys()):
            # Index in Elasticsearch for enrichment
            es.index(index=index_name, id=upn, body=cache[upn])
    
    
    now = datetime.now()
    future_time = now + timedelta(minutes=60)
    logging.info(f"Sleeping for {args.refresh_every} minutes. Next run at: {future_time}")
    time.sleep(args.refresh_every * 60)
    main()


if __name__ == "__main__":
    main()