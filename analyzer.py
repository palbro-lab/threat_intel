import pandas as pd
import ipaddress

def normalize_iocs(iocs):
    """Normalize IOCs into a DataFrame."""
    normalized = []
    
    for ioc in iocs:
        try:
            ioc_type = ioc["type"].lower()
            # Map OTX and MISP types
            if ioc_type in ["ipv4", "ipv4-addr", "ip-dst", "ip-src"]:
                ioc_type = "ipv4-addr"
            elif ioc_type in ["domain", "hostname", "domain-name"]:
                ioc_type = "domain-name"
            else:
                print(f"Skipping unsupported IOC type: {ioc_type}")
                continue
            normalized.append({
                "type": ioc_type,
                "value": ioc["value"],
                "source": ioc["source"],
                "description": ioc["description"]
            })
        except KeyError as e:
            print(f"Skipping IOC with missing key: {e}")
    
    df = pd.DataFrame(normalized)
    print(f"Normalized IOCs: {len(df)}")
    return df

def flag_relevant_iocs(df, org_assets):
    """Flag IOCs that match organization assets."""
    def is_ip_in_range(ip, ip_ranges):
        try:
            ip_addr = ipaddress.ip_address(ip)
            for ip_range in ip_ranges:
                if ip_addr in ipaddress.ip_network(ip_range):
                    return True
        except ValueError:
            return False
        return False
    
    def is_domain_match(domain, org_domains):
        for org_domain in org_domains:
            if domain == org_domain or domain.endswith(f".{org_domain}"):
                return True
        return False
    
    df["relevant"] = False
    for idx, row in df.iterrows():
        if row["type"] == "ipv4-addr":
            if is_ip_in_range(row["value"], org_assets["ip_ranges"]):
                df.at[idx, "relevant"] = True
        elif row["type"] == "domain-name":
            if is_domain_match(row["value"], org_assets["domains"]):
                df.at[idx, "relevant"] = True
    
    return df