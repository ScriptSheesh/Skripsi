import pandas as pd
from joblib import load
from sklearn.feature_extraction import FeatureHasher

# Load the saved pipeline
pipeline = load('RandomForest.joblib')

# Define each attribute as a separate variable
tld_list = ['fish']
domain_age_list = [2]
special_char_list = [0]
has_submit_button_list = [0]
has_password_field_list = [0]
no_of_iframe_list = [0]
no_of_js_list = [0]
is_https_list = [1]
url_length_list = [16]
has_title_list = [1]
has_obfuscation_list = [0]
no_of_url_redirect_list = [0]
url_title_match_score_list = [0]

# Combine these variables into a dictionary
new_data_dict = {
    'TLD': tld_list,
    'Domain_Age': domain_age_list,
    'special_char': special_char_list,
    'HasSubmitButton': has_submit_button_list,
    'HasPasswordField': has_password_field_list,
    'NoOfiFrame': no_of_iframe_list,
    'NoOfJS': no_of_js_list,
    'IsHTTPS': is_https_list,
    'URLLength': url_length_list,
    'HasTitle': has_title_list,
    'HasObfuscation': has_obfuscation_list,
    'NoOfURLRedirect': no_of_url_redirect_list,
    'URLTitleMatchScore': url_title_match_score_list
}

# Create a DataFrame from the dictionary
new_X = pd.DataFrame(new_data_dict)

# Process 'TLD' with FeatureHasher, if included
if 'TLD' in new_X.columns:
    hasher = FeatureHasher(n_features=10, input_type='string')
    hashed_features = hasher.transform(new_X['TLD'].apply(lambda x: [x])).toarray()
    hashed_feature_names = [f'TLD_hashed_{i}' for i in range(10)]
    new_X = pd.concat([new_X.drop('TLD', axis=1), pd.DataFrame(hashed_features, columns=hashed_feature_names, index=new_X.index)], axis=1)

# Use the loaded pipeline to make predictions
predictions = pipeline.predict(new_X)
print("Predictions:", predictions)
if predictions == 1 :
    print("URL bukan sebuah phishing")
else:
    print("URL adalah phishing")

# Optionally, try to get predicted probabilities if the model supports it
try:
    predicted_probabilities = pipeline.predict_proba(new_X)
    print("Predicted probabilities:", predicted_probabilities)
except AttributeError:
    print("This model does not support probability estimates.")