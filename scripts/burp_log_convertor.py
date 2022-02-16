import pandas as pd
import base64
import re
import io
import json

# Save your Burp logs as burp_logs.xml
df = pd.read_xml("burp_logs.xml")

# Create new columns for the decoded request and response
decoded_reqs= []
for request in df["request"]:
    decoded_bytes = base64.b64decode(request)
    decodedStr = str(decoded_bytes, "utf-8")
    decodedStr.replace("\r\n", "\n")
    # According to https://stackoverflow.com/questions/31203259/python-write-valid-json-with-newlines-to-file \n is not valid in json
    # In that case, or if the mapper requires new lines in the actual data in json format, use the following line instead of the previous one
    #decodedStr.replace("\r\n", "\\n")
    decoded_reqs.append(decodedStr)

df["decoded_request"] = decoded_reqs

decoded_ress = []
for response in df["response"]:
    decoded_bytes = base64.b64decode(response)
    decodedStr = str(decoded_bytes, "utf-8")
    decodedStr.replace("\r\n", "\n")
    # According to https://stackoverflow.com/questions/31203259/python-write-valid-json-with-newlines-to-file \n is not valid in json,
    # In that case, or if the mapper requires new lines in the actual data in json format, use the following line instead of the previous one
    #decodedStr.replace("\r\n", "\\n")
    decoded_ress.append(decodedStr)

df["decoded_response"] = decoded_ress

# Create new dataframe with only the decoded data, and rename the columns
decoded_df = df.filter(["decoded_request", "decoded_response"])
decoded_df.columns = ["request", "response"]

# Convert to dict
decoded_dict = decoded_df.to_dict(orient="records")

# More formatting...
formatted_data = []
myDict = {"session": None}
myDict.update({"session": decoded_dict})

formatted_data.append(myDict)



# Format again to remove \ character but not \n
# In case of \\n, the regex pattern will be: \\(?!\\n)(?!n)
# After running the script look for the parsed_logs.json file
with open("parsed_logs.json", "a+", encoding="utf8") as f:
    json.dump(formatted_data,f)
