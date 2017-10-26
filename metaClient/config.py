# Update with unique ID
CONSUMER_KEY = "DEMO-b9531eca-9db6-421e-9145-933ff4ff0364"
# Update with proper URI for websocket server
WS_SERVER = "ws://127.0.0.1:8000/"
# Update the source & destination IP to ignore websocket server traffic
WS_SERVER_IP = "127.0.0.1"
# Update to match the monitor interface
MON_IFACE = "enp0s3"

verifySSL = True

debug = False

# If you require a proxy, configure it here.
proxies = {
    # "http": "http://192.168.5.13:3128",
    # "https": "http://192.168.5.13:1080",
}

# Regular Expression for dotted-quad IP addresses with or without CIDR suffixes
re_ipcidr = (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
             '{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
             '((/([0-9]|[1-2][0-9]|3[0-2]){0,2})?)')
