# import httpx
# import asyncio
# import random

# endpoints = [
#     ('GET',  'http://target-api.com/api/products'),
#     ('POST', 'http://target-api.com/api/users/login'),
#     ('GET',  'http://target-api.com/api/users/profile'),
#     ('PUT',  'http://target-api.com/api/users/profile'),
#     ('GET',  'http://target-api.com/api/orders'),
#     ('POST', 'http://target-api.com/api/orders'),
#     ('DELETE','http://target-api.com/api/admin/users/5'),
# ]

# async def seed():
#     async with httpx.AsyncClient() as client:
#         for i in range(30):
#             method, url = random.choice(endpoints)
#             payload = {
#                 'method': method,
#                 'url': url,
#                 'request_headers': {
#                     'user-agent': 'test-agent',
#                     'authorization': 'Bearer token123'
#                 },
#                 'status_code': random.choice([200, 200, 200, 401, 403, 404, 500]),
#                 'latency_ms': round(random.uniform(20, 800), 2),
#                 'source_ip': random.choice(['192.168.1.10', '192.168.1.11', '10.0.0.5']),
#                 'session_id': random.choice(['sess_abc', 'sess_xyz', 'sess_anon'])
#             }

#             r = await client.post(
#                 'http://localhost:8000/api/traffic/ingest',
#                 json=payload
#             )

#             print(f'[{i+1}] {method} {url} → {r.status_code}')

# asyncio.run(seed())


import httpx
import asyncio
import random

BASE_URL = "http://localhost:8000"

endpoints = [
    ("GET",    "http://target-api.com/api/products"),
    ("POST",   "http://target-api.com/api/users/login"),
    ("GET",    "http://target-api.com/api/users/profile"),
    ("PUT",    "http://target-api.com/api/users/profile"),
    ("GET",    "http://target-api.com/api/orders"),
    ("POST",   "http://target-api.com/api/orders"),
    ("DELETE", "http://target-api.com/api/admin/users/5"),
]

request_bodies = {
    "POST:http://target-api.com/api/users/login": '{"email":"test@example.com","password":"secret123"}',
    "POST:http://target-api.com/api/orders":      '{"product_id":42,"quantity":2,"address":"123 Main St"}',
    "PUT:http://target-api.com/api/users/profile": '{"name":"John Doe","email":"john@example.com"}',
}

source_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "10.0.0.5",
    "10.0.0.8",
]

sessions = ["sess_abc123", "sess_xyz789", "sess_anon001", "sess_user042"]

async def seed(count: int = 50):
    async with httpx.AsyncClient(timeout=30) as client:
        print(f"Seeding {count} traffic records...\n")

        for i in range(count):
            method, url = random.choice(endpoints)
            key = f"{method}:{url}"
            body = request_bodies.get(key)

            payload = {
                "method": method,
                "url": url,
                "request_headers": {
                    "user-agent": "Mozilla/5.0 (seed script)",
                    "content-type": "application/json",
                    "authorization": random.choice([
                        "Bearer valid_token_abc",
                        "Bearer valid_token_xyz",
                        "",   # missing auth — will trigger rule later
                    ]),
                },
                "request_body": body,
                "query_params": {},
                "status_code": random.choice([200, 200, 200, 200, 401, 403, 404, 500]),
                "response_headers": {"content-type": "application/json"},
                "response_body": '{"success": true}',
                "latency_ms": round(random.uniform(15, 400), 2),
                "source_ip": random.choice(source_ips),
                "session_id": random.choice(sessions),
            }

            try:
                r = await client.post(f"{BASE_URL}/api/traffic/ingest", json=payload)
                status = r.status_code
                print(f"[{i+1:02d}] {method:<7} {url:<45} → ingest:{status}  latency:{payload['latency_ms']}ms")
            except Exception as e:
                print(f"[{i+1:02d}] ERROR: {e}")

        print("\nDone! Checking stats...")

        r = await client.get(f"{BASE_URL}/api/traffic/stats")
        print("\nTraffic stats:", r.json())

        r = await client.get(f"{BASE_URL}/api/schema/all")
        schemas = r.json()
        print(f"\nSchemas learned: {len(schemas)}")
        for s in schemas:
            stable = "✅ stable" if s["is_stable"] else "⏳ learning"
            print(f"  {s['method']:<7} {s['endpoint']:<35} samples:{s['sample_count']:>3}  {stable}")

if __name__ == "__main__":
    asyncio.run(seed(count=50))