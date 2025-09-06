from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import SpanKind

# Initialize OpenTelemetry Tracer
provider = TracerProvider()
processor = BatchSpanProcessor(ConsoleSpanExporter())
provider.add_span_processor(processor)

# Function to transform logs into OpenTelemetry format
def transform_log_to_otel(log_data):
    tracer = provider.get_tracer("network-security")
    with tracer.start_as_current_span("log-processing", kind=SpanKind.CONSUMER) as span:
        span.set_attribute("log.source", log_data["source"])
        span.set_attribute("log.message", log_data["message"])
        span.set_attribute("log.timestamp", log_data["timestamp"])
        # Add more attributes as needed
        print(f"Transformed log: {log_data}")

# Example log data
logs = [
    {"source": "192.168.1.1", "message": "Potential threat detected", "timestamp": "2023-10-01T12:00:00Z"},
    {"source": "192.168.1.2", "message": "Normal activity", "timestamp": "2023-10-01T12:01:00Z"}
]

# Transform each log
for log in logs:
    transform_log_to_otel(log)
