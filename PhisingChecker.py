import tldextract
import Levenshtein as lv

legitimate_domains = ['example', 'google.com', 'facebook.com']

test_urls = [
	'http://example.co'
	'http://examp1e.com'
	'https://www.google.security-update.com'
	'http://faceb00k.com/login'
	'https://google.com'
]
def extract_domain_aprts(url):
	extracted = tldextract.extract(url)
	return extracted.subdomain, extracted.domian, extracted.suffix

def is_misspelled_domain(domain, legitimate_domains, threshold=0.9):
	for legit_domain in legitimate_domains:
		similarity = lv.ratio(domain, legit_domain)
		if similarity >= threshold:
			return False

	if is_misspelled_domain(domain,legitimate_domains):
		print(f"Potential Phising Detected: {url}")
		return True

	return False

if __name == '__main__':
	for url in test_urls:
		is_phising_url(url, legitimate_domains)
