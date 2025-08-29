import requests
import base64

VT_API_KEY = "4741de869659951a1667ff4e8ce1772846be3841c9e21b24c862ea097831e5b9"
url = input("enter url")

# Encode URL for VirusTotal
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
headers = {"x-apikey": VT_API_KEY}

response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

if response.status_code == 200:
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    if stats["malicious"] > 0:
        print(f"⚠️ UNSAFE LINK! {stats['malicious']} engines flagged this URL.")
    else:
        print(f"✅ SAFE LINK: No detections.")
else:
    print("❌ Error checking URL.")
//output
/*enter urlhttps://www.5movierulz.irish/
⚠️ UNSAFE LINK! 1 engines flagged this URL
enter urlhttps://openai.com/index/chatgpt/
✅ SAFE LINK: No detections.*/
