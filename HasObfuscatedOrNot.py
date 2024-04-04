def detect_obfuscated(url):
    decoded_url = urllib.parse.unquote(url)
    if url != decoded_url:
        return 1  # Obfuscated characters detected
    else:
        return 0  # No obfuscated characters detected