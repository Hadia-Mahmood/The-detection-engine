from sqli_detector import detect_sqli

payloads = [
    ("' OR 1=1 --", True),
    ("' UNION SELECT username, password FROM users --", True),
    ("1'; SELECT SLEEP(5) --", True),
    ("admin' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --", True),
    ("%27%20OR%201%3D1--", True),
    ("hello world", False),
    ("O'Reilly", False),
]

for payload, expected in payloads:
    result = detect_sqli(payload)
    status = "✅" if result.detected == expected else "❌"
    print(f"{status} {payload[:45]:47s} "
          f"score={result.score:.2f} "
          f"categories={result.categories}")
