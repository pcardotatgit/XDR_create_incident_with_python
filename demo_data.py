incident_title="Patrick Incident"

description ='**Description:** Something bad happened into the system today '

observables ='''[
    {
        "value":"b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
        "type":"sha256"
    },
    {
        "value":"/c C/Users/ReallyReallyLong/Desktop/detection_v3.bat", 
        "type":"process_args"
    },
    {
        "value":"cmd.exe",
        "type":"process_name"
    },
    {
        "value":"My_Domain/Alice",
        "type":"user"
    },
    {
        "value":"cmd.exe",
        "type":"process_name"
    },
    {
        "value":"b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
        "type":"sha256"
    },
    {
        "value":"C/Windows/System32/cmd.exe",
        "type":"file_path"
    },
    {
        "value":"'asktgt' /userdatalake/test /passwordQuietFerret90 /dcdc.datalake.int",
        "type":"process_args"
    },
    {
        "value":"rubeus.exe", 
        "type":"process_name"
    },
    {
        "value":"10.0.36.82",
        "type":"ip"
    },
    {
        "value":"Victim_Laptop", 
        "type":"hostname"
    },
    {
        "value":"1bfbefa4ff4d0df3ee0090b5079cf84ed2e8d5377ba5b7a30afd88367d57b9ff",
        "type":"sha256"
    },
    {
        "value":"C/Users/ReallyReallyLong/Desktop/Rubeus.exe",
        "type":"file_path"
    }
]'''

targets='''[
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
  }
]'''

sighting_relations ='''
[
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Args_Of",
      "source": {
        "value": "/c C:/Users/ReallyReallyLong/Desktop/detection_v3.bat",
        "type": "process_args"
      },
      "related": {
        "value": "cmd.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Executed",
      "source": {
        "value": "My_Domain/Alice",
        "type": "user"
      },
      "related": {
        "value": "cmd.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Name_Of",
      "source": {
        "value": "cmd.exe",
        "type": "process_name"
      },
      "related": {
        "value": "b99d61d874728edc0918ca0eb10eab93d381e7367e377406e65963366c874450",
        "type": "sha256"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Path_Of",
      "source": {
        "value": "C:/Windows/System32/cmd.exe",
        "type": "file_path"
      },
      "related": {
        "value": "cmd.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Args_Of",
      "source": {
        "value": "'asktgt' /user:datalake/test /password:QuietFerret90 /dc:dc.datalake.int",
        "type": "process_args"
      },
      "related": {
        "value": "rubeus.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Attached_To",
      "source": {
        "value": "10.0.36.82",
        "type": "ip"
      },
      "related": {
        "value": "Victim_Laptop",
        "type": "hostname"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Name_Of",
      "source": {
        "value": "rubeus.exe",
        "type": "process_name"
      },
      "related": {
        "value": "1bfbefa4ff4d0df3ee0090b5079cf84ed2e8d5377ba5b7a30afd88367d57b9ff",
        "type": "sha256"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Path_Of",
      "source": {
        "value": "C:/Users/ReallyReallyLong/Desktop/Rubeus.exe",
        "type": "file_path"
      },
      "related": {
        "value": "rubeus.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Parent_Of",
      "source": {
        "value": "cmd.exe",
        "type": "process_name"
      },
      "related": {
        "value": "rubeus.exe",
        "type": "process_name"
      }
    },
    {
      "origin": "XDR DEmo Detection",
      "origin_uri": "https://e2e-rsa-securex.dev.obsrvbl.com/#/observations/type/nvm_suspicious_activity_v1",
      "relation": "Executed",
      "source": {
        "value": "My_Domain/Alice",
        "type": "user"
      },
      "related": {
        "value": "rubeus.exe",
        "type": "process_name"
      }
    }
]
'''