from flask import Flask, request, render_template
import requests
import base64

app = Flask(__name__)

API_KEY = '1df9a47a4a2f6919fbeb4d2895ef6985daa64d668eab83b02782fc55b60047a5'

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url_scanned = None

    if request.method == 'POST':
        url_scanned = request.form['url']
        headers = {"x-apikey": API_KEY}

        # Encode URL to base64 (VirusTotal requires it)
        url_id = base64.urlsafe_b64encode(url_scanned.encode()).decode().strip("=")
        
        # Submit for scanning
        data = {"url": url_scanned}
        requests.post("https://www.virustotal.com/api/v3/urls", data=data, headers=headers)
        
        # Fetch scan result
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        result = response.json()
        
    return render_template('index.html', result=result, url=url_scanned)

if __name__ == '__main__':
    app.run(debug=True)
