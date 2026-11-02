from app.anomaly_detector import NetworkAnomalyDetector


# Generate sample normal network traffic
normal_flows = []

for i in range(100):
    normal_flows.append({
        "id": i + 1,
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "protocol": "TCP",
        "packet_count": 10 + (i % 5),
        "byte_count": 5000 + (i * 10),
        "duration_seconds": 1.0 + (i % 3) * 0.1,
        "source_port": 50000 + (i % 100),
        "destination_port": 443,
    })


# Add unusual traffic patterns
normal_flows.extend([
    {
        "id": 101,
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "packet_count": 50000,
        "byte_count": 100000000,
        "duration_seconds": 0.01,
        "source_port": 12345,
        "destination_port": 22,
    },
    {
        "id": 102,
        "source_ip": "192.168.1.60",
        "destination_ip": "10.0.0.2",
        "protocol": "UDP",
        "packet_count": 1,
        "byte_count": 64,
        "duration_seconds": 0.001,
        "source_port": 54321,
        "destination_port": 53,
    },
])


detector = NetworkAnomalyDetector()

# Train using the first 100 flows
training_result = detector.train(normal_flows[:100])

print("\nTRAINING RESULT")
print(training_result)

# Predict only on unseen traffic
unseen_flows = normal_flows[100:]

results = detector.predict(unseen_flows)

print("\nUNSEEN DATA EVALUATION")

for result in results:
    print(result)

print("\nSUMMARY")
print("Unseen flows:", len(results))
print(
    "Anomalies detected:",
    sum(1 for result in results if result["is_anomaly"])
)
print(
    "Normal flows:",
    sum(1 for result in results if not result["is_anomaly"])
)