import requests
from requests import Request, Session

# Create a Request object
url = 'http://httpbin.org/post'
headers = {'Content-Type': 'application/json'}
data = {'key': 'value'}
req = Request('POST', url, data=data, headers=headers)

# Prepare the request
prepared_req = req.prepare()

# Print the prepared request details
print("Prepared Request:")
print(f"URL: {prepared_req.url}")
print(f"Method: {prepared_req.method}")
print(f"Headers: {prepared_req.headers}")
print(f"Body: {prepared_req.body}")

# Send the request using a Session
with Session() as s:
    response = s.send(prepared_req)

# Print the response
print(f"\nResponse Status Code: {response.status_code}")
print(response.text)