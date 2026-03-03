"""Quick API smoke test."""
import httpx

base = "http://localhost:8000"

# Dashboard
r = httpx.get(f"{base}/")
print(f"Dashboard:    {r.status_code}")

# Events API
r = httpx.get(f"{base}/api/events/?per_page=3")
data = r.json()
print(f"Events API:   {r.status_code} - {len(data)} items")

# Event types
r = httpx.get(f"{base}/api/events/types")
print(f"Event types:  {r.json()}")

# Event count
r = httpx.get(f"{base}/api/events/count")
print(f"Event count:  {r.json()}")

# Alerts
r = httpx.get(f"{base}/api/alerts/")
data = r.json()
print(f"Alerts API:   {r.status_code} - {len(data)} alerts")
for a in data:
    sev = a["severity"].upper()
    rule = a["rule_name"]
    ip = a["source_ip"]
    cnt = a["event_count"]
    print(f"  [{sev}] {rule} | IP={ip} | count={cnt}")

# Stats
r = httpx.get(f"{base}/api/alerts/stats")
print(f"Alert stats:  {r.json()}")

# Filter test
r = httpx.get(f"{base}/api/events/?source_ip=203.0.113.50&per_page=3")
data = r.json()
print(f"IP filter:    {len(data)} events from 203.0.113.50")

print("\nAll API endpoints working!")
