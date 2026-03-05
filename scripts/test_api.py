"""Quick API smoke test."""
import httpx

def main() -> None:
    base = "http://localhost:8000"

    r = httpx.get(f"{base}/")
    print(f"Dashboard:    {r.status_code}")

    r = httpx.get(f"{base}/api/events/?per_page=3")
    data = r.json()
    print(f"Events API:   {r.status_code} - {len(data)} items")

    r = httpx.get(f"{base}/api/events/types")
    print(f"Event types:  {r.json()}")

    r = httpx.get(f"{base}/api/events/count")
    print(f"Event count:  {r.json()}")

    r = httpx.get(f"{base}/api/alerts/")
    data = r.json()
    print(f"Alerts API:   {r.status_code} - {len(data)} alerts")
    for alert in data:
        sev = alert["severity"].upper()
        rule = alert["rule_name"]
        ip = alert["source_ip"]
        cnt = alert["event_count"]
        print(f"  [{sev}] {rule} | IP={ip} | count={cnt}")

    r = httpx.get(f"{base}/api/alerts/stats")
    print(f"Alert stats:  {r.json()}")

    r = httpx.get(f"{base}/api/events/?source_ip=203.0.113.50&per_page=3")
    data = r.json()
    print(f"IP filter:    {len(data)} events from 203.0.113.50")

    print("\nAll API endpoints working!")


if __name__ == "__main__":
    main()
