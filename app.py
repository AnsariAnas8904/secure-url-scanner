from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

VT_API_KEY = 'YOUR_API_KEY'  # Replace with your actual key

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>PhishGuard</title>
    <style>
        body { font-family: Arial; background-color: #f0f0f0; text-align: center; padding-top: 50px; }
        form { background: #fff; padding: 20px; border-radius: 10px; display: inline-block; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input[type="text"] { padding: 10px; width: 300px; border-radius: 5px; border: 1px solid #ccc; }
        input[type="submit"] { padding: 10px 20px; border: none; border-radius: 5px; background-color: #007BFF; color: white; margin-top: 10px; cursor: pointer; }
        .result { margin-top: 20px; font-size: 20px; padding: 15px; border-radius: 5px; }
        .safe { background-color: #d4edda; color: #155724; }
        .unsafe { background-color: #f8d7da; color: #721c24; }
        .details { text-align: left; margin-top: 20px; background: #fff3cd; padding: 15px; border-radius: 5px; display: inline-block; }
    </style>
</head>
<body>
    <h1>PhishGuard - URL Safety Checker</h1>
    <form method="POST">
        <input type="text" name="url" placeholder="Enter a URL" required />
        <br><input type="submit" value="Check" />
    </form>

    {% if verdict %}
        <div class="result {{ 'safe' if verdict == 'SAFE' else 'unsafe' }}">
            Result: <strong>{{ verdict }}</strong>
        </div>
        <div class="details">
            <strong>Details:</strong><br>
            - Detections: {{ malicious_count }} flagged out of {{ total_engines }} vendors<br>
            - Vendors: {{ vendor_names }}<br>
            - HTTPS Used: {{ https_used }}<br>
            - Reputation: {{ reputation }}
        </div>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    verdict = None
    malicious_count = 0
    total_engines = 0
    vendor_names = "None"
    https_used = "Unknown"
    reputation = "Not Available"

    if request.method == 'POST':
        url = request.form['url']
        headers = {
            "x-apikey": VT_API_KEY
        }

        # Step 1: Get analysis report
        scan_url = f"https://www.virustotal.com/api/v3/urls"
        resp = requests.post(scan_url, headers=headers, data={'url': url})
        scan_data = resp.json()
        url_id = scan_data['data']['id']

        # Step 2: Get analysis result
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_resp = requests.get(report_url, headers=headers)
        report_data = report_resp.json()

        try:
            analysis = report_data['data']['attributes']['last_analysis_results']
            malicious_vendors = [vendor for vendor, result in analysis.items() if result['category'] == 'malicious']
            malicious_count = len(malicious_vendors)
            total_engines = len(analysis)
            vendor_names = ', '.join(malicious_vendors) if malicious_vendors else "None"

            https_used = "Yes" if url.startswith("https") else "No"

            rep_score = report_data['data']['attributes'].get('reputation', 0)
            if rep_score > 5:
                reputation = "Trusted"
            elif rep_score < 0:
                reputation = "Suspicious"
            else:
                reputation = "Neutral"

            # Final verdict
            verdict = "NOT SAFE" if malicious_count > 0 else "SAFE"

        except Exception as e:
            verdict = "Could not analyze"
            print("Error parsing VT response:", e)

    return render_template_string(
        HTML_TEMPLATE,
        verdict=verdict,
        malicious_count=malicious_count,
        total_engines=total_engines,
        vendor_names=vendor_names,
        https_used=https_used,
        reputation=reputation
    )

if __name__ == '__main__':
    app.run(debug=True)

