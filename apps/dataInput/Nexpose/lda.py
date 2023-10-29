import re
import gensim
import spacy
import pyLDAvis
import pyLDAvis.gensim_models as gensimvis
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from nltk.corpus import stopwords
import requests
import json
import os

# Function to fetch CVE descriptions from NVD
def fetch_cve_descriptions(cve_list):
    cve_descriptions = {}
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    
    for cve_id in cve_list:
        url = base_url + cve_id
        response = requests.get(url)
        
        # Check for a valid response
        if response.status_code == 200:
            cve_data = response.json()
            description = cve_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
            cve_descriptions[cve_id] = description
        else:
            print(f"Failed to retrieve {cve_id}. Status code: {response.status_code}")
    print(cve_descriptions)
    return cve_descriptions

# Load CVE entries from the specified JSON file
file_path = os.path.join('apps', 'static', 'assets', 'data', 'all_cves_site_8.json')
with open(file_path, 'r') as file:
    cve_entries = json.load(file)
    print(cve_entries)

# Ensure the data is in the expected format (a list of CVE IDs)
if not isinstance(cve_entries, list):
    raise ValueError(f"Unexpected data format in {file_path}")

# Get CVE descriptions
cve_descriptions = fetch_cve_descriptions(cve_entries)
for cve_id, description in cve_descriptions.items():
    print(f"{cve_id}: {description}")

# Gather descriptions
documents = [fetch_cve_descriptions(cve_id) for cve_id in cve_entries]

# Phase 1: Data Preprocessing
stop_words = stopwords.words('english')
nlp = spacy.load('en_core_web_sm')

def preprocess_text(text):
    # Lemmatization and stopword removal
    doc = nlp(text)
    text = ' '.join([token.lemma_ for token in doc if token.text.lower() not in stop_words])
    # Removing emails and newline characters
    text = re.sub(r'\S*@\S*\s?', '', text)
    text = re.sub(r'\s+', ' ', text)
    return text

processed_documents = [preprocess_text(doc) for doc in documents]

# Creating Bigram and Trigram Models
bigram = gensim.models.Phrases(processed_documents, min_count=5, threshold=100)
trigram = gensim.models.Phrases(bigram[processed_documents], threshold=100)
bigram_mod = gensim.models.phrases.Phraser(bigram)
trigram_mod = gensim.models.phrases.Phraser(trigram)

def make_bigrams(texts):
    return [bigram_mod[doc] for doc in texts]

def make_trigrams(texts):
    return [trigram_mod[bigram_mod[doc]] for doc in texts]

data_words_bigrams = make_bigrams(processed_documents)
data_words_trigrams = make_trigrams(processed_documents)

# Phase 2: Building the Topic Model
id2word = gensim.corpora.Dictionary(data_words_trigrams)
corpus = [id2word.doc2bow(text) for text in data_words_trigrams]
lda_model = gensim.models.LdaMulticore(corpus=corpus, id2word=id2word, num_topics=10, random_state=100)

# Phase 3: Rule-based Topic Classification
# Assuming we have predefined keyword sets for OWASP vulnerabilities
owasp_keywords = {
    'A01:2021-Broken Access Control': set(['auth', 'access', 'session', 'token', 'credentials', 'privilege']),
    'A02:2021-Cryptographic Failures': set(['crypto', 'encryption', 'certificate', 'SSL', 'TLS', 'hash', 'cipher']),
    'A03:2021-Injection': set(['SQL', 'LDAP', 'ORM', 'XML', 'SSTI', 'command', 'injection']),
    'A04:2021-Insecure Design': set(['design', 'architecture', 'implementation']),
    'A05:2021-Security Misconfiguration': set(['config', 'setup', 'misconfig', 'default', 'hardening']),
    'A06:2021-Vulnerable and Outdated Components': set(['library', 'dependency', 'version', 'update', 'patch']),
    'A07:2021-Identification and Authentication Failures': set(['password', '2FA', 'MFA', 'OTP', 'replay', 'bruteforce', 'credential', 'auth']),
    'A08:2021-Software and Data Integrity Failures': set(['tampering', 'integrity', 'checksum', 'signature', 'validation']),
    'A09:2021-Security Logging and Monitoring Failures': set(['log', 'monitor', 'audit', 'incident', 'alert']),
    'A10:2021-Server-Side Request Forgery (SSRF)': set(['SSRF', 'server', 'request', 'forgery', 'external']),
}

# Mapping topics to sets of relevant terms
topic_term_dict = {}
for topic_num, topic_terms in lda_model.show_topics(formatted=False):
    topic_term_dict[topic_num] = set([term for term, _ in topic_terms])

# Mapping topics to OWASP vulnerabilities
topic_vulnerability_mapping = {}
for topic_num, terms in topic_term_dict.items():
    best_match = None
    best_match_count = 0
    for vulnerability, keywords in owasp_keywords.items():
        intersection_count = len(terms.intersection(keywords))
        if intersection_count > best_match_count:
            best_match = vulnerability
            best_match_count = intersection_count
    topic_vulnerability_mapping[topic_num] = best_match

# Display the mapping
for topic_num, vulnerability in topic_vulnerability_mapping.items():
    print(f'Topic {topic_num}: {vulnerability}')

# Visualizing the topics using pyLDAvis
vis_data = gensimvis.prepare(lda_model, corpus, id2word)
pyLDAvis.display(vis_data)

# Additional steps based on the text provided for manual and automatic mapping comparison
# The following steps are more abstract as they require specific data structures from the text.

# Assuming we have predefined mappings for manual mapping
manual_mapping = {
    # ... (manual mapping data)
}

# Tabulating the % of tokens for each vulnerability type (assuming a function to calculate % of tokens)
def calculate_token_percentage(topic_num):
    # Replace with actual function to calculate % of tokens for a given topic
    pass

# Calculating % of tokens for each topic
token_percentages = {topic_num: calculate_token_percentage(topic_num) for topic_num in range(10)}

# Comparing manual and automatic mapping
comparison_data = {
    'Manual': manual_mapping,
    'Auto': topic_vulnerability_mapping,
    '% of Tokens': token_percentages,
}

comparison_df = pd.DataFrame(comparison_data)
print(comparison_df)

# Calculating Coefficient of Variance (CV) for each set
cv_data = {
    'Manual': np.std(comparison_df['Manual']) / np.mean(comparison_df['Manual']),
    'Auto': np.std(comparison_df['Auto']) / np.mean(comparison_df['Auto']),
}

cv_df = pd.DataFrame(cv_data, index=['CV'])
print(cv_df)

# Conclusion: The above steps provide a structured approach to implement the analysis of CVEs as described in the text.
# The actual implementation might require more detailed data and adjustments to match the specifics of the provided text.
