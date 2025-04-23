import requests
import json

def fetch_otx_pulses(api_key):
    """Fetch IOCs from AlienVault OTX pulses."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    iocs = []
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        pulses = response.json().get("results", [])
        print(f"Fetched {len(pulses)} OTX pulses")
        
        for pulse in pulses[:10]:  # Limit to 10 pulses
            for ioc in pulse.get("indicators", []):
                print(f"OTX IOC: type={ioc['type'].lower()}, value={ioc['indicator']}")
                iocs.append({
                    "type": ioc["type"].lower(),
                    "value": ioc["indicator"],
                    "source": "AlienVault OTX",
                    "description": ioc.get("description", pulse.get("name", ""))
                })
    except requests.RequestException as e:
        print(f"Error fetching OTX pulses: {e}")
    
    # Add test IOCs
    iocs.extend([
        {
            "type": "ipv4-addr",
            "value": "192.168.1.50",
            "source": "Test",
            "description": "Test IP in organization range"
        },
        {
            "type": "domain-name",
            "value": "phish.example.com",
            "source": "Test",
            "description": "Test phishing domain"
        },
        {
            "type": "ipv4-addr",
            "value": "8.8.8.8",
            "source": "Test",
            "description": "Test non-relevant IP"
        }
    ])
    
    print(f"Fetched {len(iocs)} OTX/test IOCs")
    return iocs

def fetch_misp_iocs(feed_url):
    """Fetch IOCs from CIRCL MISP OSINT feed."""
    iocs = []
    
    try:
        # Fetch manifest
        manifest_url = feed_url.rstrip("/") + "/manifest.json"
        response = requests.get(manifest_url, timeout=10)
        response.raise_for_status()
        
        try:
            manifest = json.loads(response.text)
        except json.JSONDecodeError as e:
            print(f"Error decoding manifest JSON: {e}")
            return iocs
        
        print(f"Fetched CIRCL OSINT manifest with {len(manifest)} events")
        
        # Fetch up to 10 event JSON files
        for event_id, event_info in list(manifest.items())[:10]:
            event_url = feed_url.rstrip("/") + f"/{event_id}.json"
            try:
                event_response = requests.get(event_url, timeout=10)
                event_response.raise_for_status()
                event_data = json.loads(event_response.text)
                event = event_data.get("Event", {})
                
                for attr in event.get("Attribute", []):
                    attr_type = attr["type"].lower()
                    print(f"MISP IOC: type={attr_type}, value={attr['value']}")
                    if attr_type in ["ip-dst", "ip-src"]:
                        iocs.append({
                            "type": "ipv4-addr",
                            "value": attr["value"],
                            "source": "CIRCL OSINT",
                            "description": event.get("info", "")
                        })
                    elif attr_type in ["domain", "hostname"]:
                        iocs.append({
                            "type": "domain-name",
                            "value": attr["value"],
                            "source": "CIRCL OSINT",
                            "description": event.get("info", "")
                        })
            except (requests.RequestException, json.JSONDecodeError) as e:
                print(f"Error fetching event {event_id}: {e}")
                continue
        
    except requests.RequestException as e:
        print(f"Error fetching CIRCL OSINT manifest: {e}")
    
    print(f"Fetched {len(iocs)} CIRCL OSINT IOCs")
    return iocs