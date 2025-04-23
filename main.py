import os
import pandas as pd
from feeds import fetch_otx_pulses, fetch_misp_iocs
from analyzer import normalize_iocs, flag_relevant_iocs
from config import OTX_API_KEY, MISP_FEED_URL, ORGANIZATION_ASSETS

def main():
    os.makedirs("output", exist_ok=True)
    output_file = "output/ioc_report.csv"

    print("Fetching AlienVault OTX pulses...")
    otx_iocs = fetch_otx_pulses(OTX_API_KEY)
    
    print("Fetching CIRCL MISP OSINT feed...")
    misp_iocs = fetch_misp_iocs(MISP_FEED_URL)

    all_iocs = otx_iocs + misp_iocs
    print(f"Collected {len(all_iocs)} IOCs.")

    df = normalize_iocs(all_iocs)
    print(f"Normalized {len(df)} IOCs.")

    df = flag_relevant_iocs(df, ORGANIZATION_ASSETS)
    
    df.to_csv(output_file, index=False)
    print(f"Report saved to {output_file}")

    relevant_iocs = df[df["relevant"] == True]
    print("\nSummary of Relevant IOCs:")
    print(f"Total Relevant IOCs: {len(relevant_iocs)}")
    print(relevant_iocs[["type", "value", "source", "description"]])

if __name__ == "__main__":
    main()