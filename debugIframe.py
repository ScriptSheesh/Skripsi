# import requests
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

# def count_iframes(url):
#     headers = {
#         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
#     }
#     try:
#         response = requests.get(url, headers=headers, timeout=10)
#         response.raise_for_status()  # Raise an exception for HTTP errors
#         html_content = response.content
#         soup = BeautifulSoup(html_content, 'html.parser')
#         iframes = soup.find_all('iframe')
#         return len(iframes)
#     except requests.exceptions.RequestException as e:
#         print(f"Request exception occurred: {e}")
#         return 0
#     except Exception as e:
#         print(f"General error occurred: {e}")
#         return 0

# # Test the function with the provided URL
# url = "https://www.capeblancoheritagesociety.com"
# print(f"Number of iframes: {count_iframes(url)}")


def count_iframes(url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(url, headers=headers, timeout=10)
            html_content = response.content
            soup = BeautifulSoup(html_content, 'html.parser')
            iframes = soup.find_all('iframe')
            return len(iframes)
        except Exception:
            print(f"Error counting iframes")
            return 0

# Test the function with the provided URL
url = "https://www.capeblancoheritagesociety.com"
print(f"Number of iframes: {count_iframes(url)}")