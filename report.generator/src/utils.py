import base64

def decode_base64(content):
    try:
        return base64.b64decode(content).decode("utf-8")
    except Exception:
        return ""
