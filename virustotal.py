import requests
import base64
import os

from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

def url_to_id(url):
    url_bytes = url.encode("utf-8")
    encoded = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
    return encoded

def check_virustotal(links):

    score = 0
    reasons = []
    results = []

    headers = {
        "x-apikey": API_KEY
    }

    for link in links:

        try:

            url_id = url_to_id(link)

            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:

                score += 40

                reasons.append(
                    f"VirusTotal detected malicious URL ({malicious} engines)"
                )

            elif suspicious > 0:

                score += 20

                reasons.append(
                    f"VirusTotal detected suspicious URL ({suspicious} engines)"
                )

            results.append({
                "url": link,
                "malicious": malicious,
                "suspicious": suspicious
            })

        except Exception as e:

            reasons.append(
                f"VirusTotal API error: {str(e)}"
            )

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "results": results
    }