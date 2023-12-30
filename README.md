# Understand how to create an XDR Incident and attached sightings

This article share a python script that create and XDR Incident and one attached sightings.

The goal is to share with the audience an example of working static Incident creation done by a python script. And detail into the python script every steps of the Incident creation.

This script applies into on python scripts everything that is described into the **XDR Incident creation** details. Refer to this documentation if you want to understand every details of what the python script does.

## Install the python environment

We don't describe the python process. We assume that you know how to do for this part. 

This is a standard python installation. 

You need the **crayons** and **requests** python modules.

## Step 1 - edit the config.txt initialization file

Edit the config.txt initialization file and assign the correct values to the variables the file contains.

Then you are ready to go

## Run the script

You have to read the **1-create_XDR_incident.py**

    python 1-create_XDR_incident.py

Then you just have to follow every steps one by one into the console. The result will be a new **Incident** created within the XDR **Incident Manager** and a new **sighting**. The source for both objects is : **XDR Demo**.

## What happens ?

Every steps can be seen into the **main** function. Here are these steps 

- 1 : create the Incident JSON payload and generate the Incident External ID
- 2 : create Sighting JSON payload and sighting External ID
-  2-a : read the **observables** variable into the **demo_data.py** file and add it into the sighting JSON payload
-  2-b : read the **targets** variable into the **demo_data.py** file and add it into the sighting JSON payload
-  2-c : read the **observables relationships** variable into the **demo_data.py** file and add it into the sighting JSON payload
- 3 : create Incident Relationships payload for sighting and Incident
- 4 : create Bundle JSON payload => Put everything together into the bundle JSON payload
- 5 : read XDR Tenant details and credentials into **config.txt**
- 6 : aks for a CTR ( Cisco Threat Response ) authentication token
- 7 : Invoke the XDR **bundle** API and create the new **Incident** within XDR

**Observables, targets and observable_relationships** are declared as string variables into the **demo_data.py** script. We understand that in real Security Event situation, we will have to dynamically generate these variables from the Security Product events. We will discribe an example into another article.

The **Bundle** API creates objects one after the other. First the **Incident**, second the **Sightings** and finally the *relatioships**. 

Each object has an API execution result. This result will be equal to : **created** if everything goes well. And if not you will see a long **msg** that contains the key value you sent and at the end of the message the location and cause of the error. 

Errors will be most of the time due to an invalid JSON payload. 

Within the **sightinh** JSON payload you have to notice that every object mentionned into observable relationships must be declared has an observable as well. If one observable is missing the sighting will not be created.
 
## Delete the XDR Demo Incident and sithing

In order to clean up everything just run the

    python 2-delete_XDR_demo_data.py
    
    
## Required fields for every objects

Have a look to the **1-create_XDR_incident.py** script. You will easily identitify dedicated python functions that create JSON payload for every **Incident** objects. 

These functions just builds python dictionnaries and return the JSON dumps of these dictionnaries. Python is very efficient for generating JSON payloads.

It is easy to understand from these function a list of mandatory and required fields need to build the JSON payloads

Here is a list of these fields :

**Incident :**

    ```python
    def create_incident_json():
        incident_object = {}
        incident_object["description"] = description
        incident_object["schema_version"] = "1.3.9"
        incident_object["type"] = "incident"
        incident_object["source"] = "XDR Demo"
        incident_object["short_description"] = incident_title
        incident_object["title"] = incident_title
        incident_object["incident_time"] = { "discovered": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "opened": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
        incident_object["status"] = "New" status: Must be one of ["New", "Open", "Stalled", "Containment Achieved", "Restoration Achieved", "Incident Reported", "Closed", "Rejected"]
        incident_object["tlp"] = "amber"
        incident_object["confidence"] = "High"  Must be one of ["Info", "Low", "Medium", "High", "None", "Unknown"]
        incident_object["severity"] = "Critical" Must be one of ["Info", "Low", "Medium", "High", "Critical", "None", "Unknown"]
        incident_object["id"] = xid
        incident_object["techniques"] = ["T1036"]
        incident_object["tactics"] = ["TA0002","TA0005"]
        incident_object["categories"]:[categories[3]]
        incident_object["discovery_method"]:discover_method[2]
        incident_object["promotion_method"]:"Automated" # Manual or Automated         
        incident_object["scores"]={}
        incident_object["scores"]["asset"]=10
        incident_object["scores"]["ttp"]=100
        incident_object["scores"]["global"]=1000  
    ```
 
discover_method=["Agent Disclosure","Antivirus","Audit","Customer","External - Fraud Detection","Financial Audit","HIPS","IT Audit","Incident Response","Internal - Fraud Detection","Law Enforcement"]

categories=["Denial of Service","Exercise/Network Defense Testing","Improper Usage","Investigation","Malicious Code","Scans/Probes/Attempted Access","Unauthorized Access"]
 
**Sightings :**

```python
def create_sighting_object(xid,title,observables,targets,confidence,description,source,tlp,severity):
    sighting_obj_json["confidence"] = "High"
    sighting_obj_json["observables"] = json.loads(observables)
    sighting_obj_json["targets"] = json.loads(targets)
    sighting_obj_json["external_ids"] = [xid]
    sighting_obj_json["id"] ="transient:"+xid
    sighting_obj_json["description"] = description
    sighting_obj_json["title"] = title
    sighting_obj_json["source"] = source
    sighting_obj_json["type"] = "sighting"
    sighting_obj_json["observed_time"] = {"start_time": start_date }
    sighting_obj_json["tlp"] = "amber"
    sighting_obj_json["severity"] = "Critical" Must be one of ["Info", "Low", "Medium", "High", "Critical", "None", "Unknown"]
    sighting_obj_json["relations"] = json.loads(sighting_relations)
```

**Sightings - Observables :**

Observables are just a list of values and types

```python
observables =[
  {
    "value": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
    "type": "sha256"
  },
  {
    ...
    ...
  }
  ]
```

**Sightings - Targets :**

This a list of object definitions

For each object, the object type with one or several object characteristics, and an observed time. This information might change frequently overtime. A good practice would be to update these information every time an alert occur.

Actually we would start from the observable we see into the raw alert. The IP address for example, and from this information query every sources that can help us to discover other variable values


```python
targets=[
  {
    "type": "endpoint",
    "observables": [
      {
        "value": "Victim Laptop",
        "type": "hostname"
      },
      {
        "value": "2.3.4.42",
        "type": "ip"
      },
      {
        "value": "00:E1:6D:26:24:E9",
        "type": "mac_address"
      }
    ],
    "observed_time": {
      "start_time": "2023-09-09T13:31:02.000Z",
      "end_time": "2023-09-09T13:31:02.000Z"
    }
  },
  {
  ... Second Target
  }
]
```

## Recommandation for description formating

**Incidents** Includes a detailed **description** field which is a very important component. It is supposed to be a documentation summary which help Security Operator

[Incident Summary Guidelines](https://github.com/threatgrid/ctim/blob/master/doc/tutorials/incident-summary-guidelines.md)