import pandas as pd
import whois
from urllib.parse import urlparse
import datetime

def calculate_domain_age(creation_date):
    if creation_date:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime.datetime):
            now = datetime.datetime.now()
            domain_age_years = (now - creation_date).days // 365
            if domain_age_years < 1:
                return "Less than a year"
            else:
                return f"{domain_age_years} years"
    return "Unknown"

def calculate_domain_age_from_csv(csv_file, output_csv):
    try:
        df = pd.read_csv(csv_file)
        df['Domain_Age'] = df['URL'].apply(lambda url: calculate_domain_age(get_creation_date(url)))
        df.to_csv(output_csv, index=False)
        print(f"Domain age analysis saved to {output_csv}")
    except Exception as e:
        print(f"Error occurred: {e}")

def get_creation_date(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        if w.creation_date is not None:
            return w.creation_date
        else:
            return None
    except Exception as e:
        print(f"Error retrieving WHOIS data for {url}: {e}")
        return None

input_csv = 'dataseturl.csv'
output_csv = 'domain_age_analysis.csv'
calculate_domain_age_from_csv(input_csv, output_csv)

