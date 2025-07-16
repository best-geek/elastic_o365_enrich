# Elastic o365 Enrichment
This repository contains a docker container and steps that can be used to support the enrichment of Office365 logging within Elastic. This assumes you have already configured the 'Microsoft Office 365' integration. 

The script will currently provide fields that contain the following information:
- Authentication methods (such as iPhone, Yubikey and phone number)
- Last Password Change
- Group Membership
- Static Role Membership
- Scheduled Role Membership
- Eligible Role Membership (PIM)
- Last enrichment date

A high level process can be seen below:

**Client Side**
```
                                                                                                                       
 Python Script in Docker Container    ─────────────► Graph API calls  ─────────────────► Post to Elastic Search via API
                                                                                                                       
```             
*The Python script refreshes data every hour*

**Elastic Side**
```                                                                                                                       
  Ingest Office365 Logs  ─────────────► Query Enrichment Index and add fields                                          
```
Elastic Ingest Pipelines are used to add additional fields to the existing Office365 logging. 


# Configuration
It is implied that you have cloned the repository containing the files needed to build the docker image. 

## Entra ID
The script requires an App Registration to be deployed within Entra ID to authenticate and query user data against the Graph API. 
When creating an App Registration, add and grant the following API permissions:
- RoleManagement.Read.Directory
- RoleManagement.ReadWrite.Directory
- RoleEligibilitySchedule.Read.Directory
- User.Read.All
- UserAuthenticationMethod.Read.All

Under 'Clients and Secrets' for the App Registration, create an Client Secret. Make a note of the value displayed on the screen as it will only be displayed once. 

On the overview page, obtain the Application (Client) ID and Directory (Tenant ID) values. 

Update the corresponding values in the .env file `ENRICH_TENANT_ID`,
`ENRICH_CLIENT_ID` and `ENRICH_CLIENT_SECRET`

## Elastic API Key
The associated user for the API will need the ability to create indexes and ingest documents

From the Kibana interface search 'Api Keys' and select 'Security / API Keys'.
Create the API key and make a note of the value as this will only be displayed once. 

Update the fields `ENRICH_ELASTIC_API_KEY` and `ENRICH_ELASTIC_API_KEY` within the .env file. `ENRICH_ELASTIC_API_KEY` should contain the full URI used for an ingest node, ie 'https://10.1.1.9:9200'

# Docker
With the .env file configured, it should be possible to build and run the container. 
Within the cloned directory run `docker compose build` followed by `docker compose up -d`. 

Output and Python script errors will be outputted in the container logs and can be reviewed by running `docker logs -f elastic-o365enrich`.
Successful and failed Graph API calls are indicated in output. 

# Elastic Enrichment Setup
For user ease, these steps are provided from the Kibana interface, however their equivalent requests are included later on in this document.

From 'Stack Management > Index Management' if the script has run successfully you should see the 'o365_userdata_enrich; under indicies.

- Create a new Enrich Policy from 'Stack Management > Index Management'
    - Policy Name: o365_userdata_enrich
    - Policy Type: match
    - Source: o365_userdata_enrich
    - Field Selection, Match Field: upn_enrich
    - Field Selection, Enrich Fields: 'assigned_roles', 'auth_methods', 'group_membership', 'last_password_change', 'last_enriched', 'scheduled_roles', 'eligible_roles' [*Note the last two items may not be available without a P2 license*]

Go to 'Ingest / Ingest Pipelines'
- Create a new pipeline
    - Create the name 'o365-enrich-additionaldata'
    - Create a New Processor
        - Processor: Enrich
        - Field: o365.audit.UserId
        - Policy Name: o365_userdata_enrich
        - Target Field: upn_enrich
        - Override: Enabled
        - Ignore missing: Enabled
        - Tag: Enriched



# Known Issues
- Certain API keys for Scheduled and Eligible Role Membership require Entra ID P2 licensing. Script errors may output messages `The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license` which can be safely ignored.
- The index creation occurs at the first script run and will detect if the index already exists. Index mappings are then generated dynamically based of a 'best candidate' user records the script pulls. I am unable to provide a complete index mapping due to lack of P2 licensing in my testing. 

# Elastic Search Calls

## Check index:
`GET /o365_userdata_enrich`

## Add enrichment policy
```
POST /index_management/enrich_policies
{
  "name": "o365_userdata_enrich",
  "type": "match",
  "sourceIndices": [
    "o365_userdata_enrich"
  ],
  "matchField": "upn_enrich",
  "enrichFields": [
    "assigned_roles",
    "auth_methods",
    "group_membership",
    "last_password_change",
    "last_enriched",
    "scheduled_roles",
    "eligible_roles"
  ]
}
```

## Add Ingestion Pipeline
```
PUT _ingest/pipeline/o365-enrich-additionaldata
{
  "description": "Enriches authentication methods for office365 logs",
  "processors": [
    {
      "enrich": {
        "field": "o365.audit.UserId",
        "policy_name": "o365_userdata_enrich",
        "target_field": "upn_enrich",
        "ignore_missing": true,
        "tag": "enriched"
      }
    }
  ]
}
```