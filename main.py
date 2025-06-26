import json
import os
import requests
import base64
import subprocess
import whois
from typing import Dict, List, Optional, Tuple
from openai import OpenAI
from config import openai_api_key, jina_api_key, google_cloud_API_key, search_engine_ID, http_request_header


class SMSPhishingDetector:
    """
    A comprehensive SMS phishing detection system that analyzes SMS messages
    for potential phishing attempts using multiple detection methods.
    """
    
    def __init__(self, openai_api_key: str, jina_api_key: str, google_cloud_API_key: str, search_engine_id: str):
        """
        Initialize the SMS Phishing Detector.
        
        Args:
            openai_api_key (str): OpenAI API key for GPT analysis
            jina_api_key (str): Jina API key for web content extraction
        """
        self.openai_api_key = openai_api_key
        self.jina_api_key = jina_api_key
        self.openai_client = OpenAI(api_key=openai_api_key)
        self.google_cloud_API_key = google_cloud_API_key
        self.search_engine_id = search_engine_id
        
    def detect_sms_phishing(
        self, 
        sms_message: str, 
        output_dir: str = "output",
        enable_redirect_chain: bool = True,
        enable_brand_search: bool = True,
        enable_screenshot: bool = True,
        enable_html_content: bool = True,
        enable_domain_info: bool = True
    ) -> bool:
        """
        Main function to detect if an SMS message is phishing.
        
        Args:
            sms_message (str): The SMS message to analyze
            output_dir (str): Directory to save analysis results
            enable_redirect_chain (bool): Whether to analyze URL redirect chains
            enable_brand_search (bool): Whether to search for brand domains
            enable_screenshot (bool): Whether to take website screenshots
            enable_html_content (bool): Whether to analyze HTML content
            enable_domain_info (bool): Whether to get domain information
            
        Returns:
            bool: True if the SMS is detected as phishing/spam, False if legitimate
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Step 1: Extract URLs and brands from SMS
        initial_analysis = self._extract_urls_and_brands(sms_message)
        
        # Step 2: Analyze URLs if present
        if initial_analysis['is_URL'] and initial_analysis['URLs'] != "non":
            url_analysis = self._analyze_urls(
                initial_analysis['URLs'],
                output_dir,
                enable_redirect_chain,
                enable_brand_search,
                enable_screenshot,
                enable_html_content,
                enable_domain_info
            )
            initial_analysis['URLs'] = url_analysis
            
            # Brand search if enabled and brands detected
            if enable_brand_search and initial_analysis['is_brand']:
                brand_analysis = self._search_brand_domains(initial_analysis['brands'])
                for url_idx in url_analysis:
                    initial_analysis['URLs'][url_idx]['brand_search'] = brand_analysis
        
        # Step 3: Generate detection prompt and analyze
        detection_prompt = self._build_detection_prompt(sms_message, initial_analysis)
        detection_result = self._perform_final_detection(detection_prompt)
        
        # Step 4: Generate user-friendly output
        user_friendly_output = self._generate_user_friendly_output(sms_message, detection_result)
        
        # Step 5: Save complete analysis
        complete_analysis = {
            **initial_analysis,
            'SMS': sms_message,
            'detect_result': detection_result,
            'user_friendly_output': user_friendly_output,
            'detection_prompt': detection_prompt
        }
        
        self._save_analysis_results(complete_analysis, output_dir)
        
        return detection_result.get('category', True)
    
    def _extract_urls_and_brands(self, sms_message: str) -> Dict:
        """Extract URLs and brand names from SMS message."""
        prompt = self._get_url_extraction_prompt() + "\n" + sms_message
        
        response = self.openai_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="gpt-4o",
            response_format={
                "type": "json_object",
            }
        )
        
        content = self._clean_json_response(response.choices[0].message.content)
        return json.loads(content)
    
    def _analyze_urls(
        self, 
        urls: List[str], 
        output_dir: str,
        enable_redirect_chain: bool,
        enable_brand_search: bool,
        enable_screenshot: bool,
        enable_html_content: bool,
        enable_domain_info: bool
    ) -> Dict:
        """Analyze each URL in the SMS message."""
        url_analysis = {}
        
        for idx, url in enumerate(urls):
            url_analysis[idx] = {'URL': url}
            
            # Normalize URL
            normalized_url = self._normalize_url(url)
            final_url = self._expand_url(normalized_url)
            
            url_analysis[idx]['final_URL'] = final_url or normalized_url
            
            # Redirect chain analysis
            if enable_redirect_chain:
                redirect_chain = self._get_redirect_chain(normalized_url)
                url_analysis[idx]['redirect_chain'] = redirect_chain
            
            # HTML content analysis
            if enable_html_content:
                html_content, html_summary = self._analyze_html_content(final_url or normalized_url)
                url_analysis[idx]['URL_content'] = html_content
                url_analysis[idx]['html_summary'] = html_summary
            
            # Domain information
            if enable_domain_info:
                domain_info = self._get_domain_info(normalized_url)
                url_analysis[idx]['domain_info'] = domain_info
            
            # Screenshot analysis
            if enable_screenshot:
                screenshot_path, image_content = self._analyze_screenshot(
                    final_url or normalized_url, 
                    output_dir, 
                    idx
                )
                url_analysis[idx]['screenshot_path'] = screenshot_path
                url_analysis[idx]['Image_content'] = image_content
        
        return url_analysis
    
    def _normalize_url(self, url: str) -> str:
        """Add http:// prefix if missing."""
        if not (url.startswith("http://") or url.startswith("https://")):
            return "http://" + url
        return url
    
    def _check_url_validity(self, url: str) -> Tuple[bool, Optional[int]]:
        """Check if URL is valid and accessible."""
        try:
            response = requests.head(url, allow_redirects=True, headers=http_request_header)

            # If the status code is in the range of 200 to 399, the URL is valid
            if response.status_code in range(200, 400):
                return True, response.status_code
            else:
                return False, response.status_code
        except requests.exceptions.RequestException as e:
            print(f"Error occurred: {e}")
            return False, None
    
    def _expand_url(self, url: str) -> Optional[str]:
        """Expand shortened URLs to their final destination."""
        try:
            response = requests.head(url, allow_redirects=True, headers=http_request_header, timeout=10)
            return response.url
        except requests.RequestException:
            return None
    
    def _get_redirect_chain(self, url: str) -> List[Tuple[str, int]]:
        """Get the complete redirect chain for a URL."""
        try:
            response = requests.head(url, allow_redirects=True, headers=http_request_header)

            response_chain = []
            response_status = []

            if response.history:
                for resp in response.history:
                    response_chain.append(resp.url)
                    response_status.append(resp.status_code)

            # Add the final response URL and status
            response_chain.append(response.url)
            response_status.append(response.status_code)

            return list(zip(response_chain, response_status))
        except requests.RequestException:
            return "non"
    
    def _analyze_html_content(self, url: str) -> Tuple[str, str]:
        """Analyze HTML content of the URL."""
        
        try:
            jina_url = f'https://r.jina.ai/{url}'
            headers = {"Authorization": f"Bearer {self.jina_api_key}"}
            response = requests.get(jina_url, headers=headers)
            
            # Limit content length
            content = response.text[:10000] if len(response.text) > 10000 else response.text
            
            # Summarize content using GPT
            summary = self._summarize_html_content(content)
            return content, summary
            
        except requests.RequestException:
            content = "There is no information known about the URL. The URL might be invalid or expired."
            return content, content
    
    def _summarize_html_content(self, content: str) -> str:
        """Summarize HTML content using GPT."""
        prompt = """Please summarize the content in English and determine whether the website has a block wall or not.
        Your output should be in json format and should not have any other output:
        - summary: the summary of the content in English. Within 500 words. Some website might have a robot-human verification page. If the website has no information available, mention that the content might be hidden behind a verification wall. Both phishing and legitimate websites can have a robot-human verification page. It doesn't necessarily indicate malicious intent.
        """ + f"\n\nThe website content: {content}"
        
        try:
            response = self.openai_client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4o",
                response_format={
                    "type": "json_object",
                }
            )
            
            content_summary = self._clean_json_response(response.choices[0].message.content)
            return json.loads(content_summary)['summary']
        except Exception:
            return "Could not analyze content"
    
    def _get_domain_info(self, url: str) -> str:
        """Get domain registration information."""
        try:
            domain = url.split("//")[-1].split("/")[0]
            domain_info = whois.whois(domain)
            return str(domain_info)
        except Exception:
            return "non"
    
    def _analyze_screenshot(self, url: str, output_dir: str, idx: int) -> Tuple[str, str]:
        """Take and analyze screenshot of the webpage."""
        try:
            screenshot_path = os.path.join(output_dir, f"screenshot_{idx}.png")
            
            # Take screenshot if it doesn't exist
            if not os.path.exists(screenshot_path):
                self._take_screenshot(url, screenshot_path)
            
            # Analyze screenshot with GPT Vision
            image_content = self._analyze_screenshot_with_gpt(screenshot_path)
            return screenshot_path, image_content
            
        except Exception as e:
            print(f"Screenshot error: {e}")
            return "non", "non"
    
    def _take_screenshot(self, url: str, screenshot_path: str):
        """Take screenshot using Node.js crawler."""
        try:
            subprocess.run(
                ['node', 'crawler_proj/crawler.js', url, screenshot_path],
                check=True,
                capture_output=True,
                text=True,
            )
            print(f"Screenshot saved to {screenshot_path}")
        except subprocess.SubprocessError as e:
            print(f"Screenshot capture failed: {e}")
            raise
    
    def _analyze_screenshot_with_gpt(self, image_path: str) -> str:
        """Analyze screenshot using GPT Vision API."""
        try:
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}"
            }
            
            payload = {
                "model": "gpt-4o",
                "messages": [{
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": """You are a website screenshot analysis assistant. Your primary function is to analyze website screenshots, provide a detailed description of the content, and determine the purpose of the page. For instance:
                            If the screenshot shows a news site, summarize the main news topics or articles.
                            Identify any logos, brands, or key visual elements.
                            The URL might be redirected to a robot-human verification page. If the screenshot is a blank page, mention that the content might be hidden behind a verification wall.
                            Your response should be in English and plain text, without any markdown or HTML formatting. Your response should be in 15 sentences or less."""
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                        }
                    ]
                }],
                "max_tokens": 300
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions", 
                headers=headers, 
                json=payload
            )
            
            return response.json()["choices"][0]["message"]["content"]
            
        except Exception as e:
            print(f"Screenshot analysis failed: {e}")
            return "non"
    
    def _search_brand_domains(self, brands: List[str]) -> Dict:
        """Search for official domains of mentioned brands."""
        brand_search = {}
        
        for idx, brand in enumerate(brands):
            brand_search[idx] = {
                'brand_name': brand,
                'brand_domain': self._google_search_brand(brand_name=brand, google_cloud_API=self.google_cloud_API_key, search_engine_id=self.search_engine_id)
            }
        
        return brand_search
        


    def _google_search_brand(self, google_cloud_API:str, search_engine_id: str, brand_name: str) -> List[str]:
        """Search Google for brand's official domains."""
        try:
            url = f"https://www.googleapis.com/customsearch/v1"
            params = {
                'key': google_cloud_API,
                'cx': search_engine_id,
                'q': brand_name,
                'num': 5,  # Get top 5 results
            }
            response = requests.get(url, params=params)
            response = response.json()
            return [item['link'] for item in response.get('items', [])]
        except Exception as e:
            print(f"Google search failed: {e}")
            return []

    def _build_detection_prompt(self, sms_message: str, analysis: Dict) -> str:
        """Build the comprehensive prompt for final detection."""
        prompt = self._get_detection_prompt_template()
        prompt += f"\n- SMS to be analyzed: {sms_message}\n"
        
        if analysis.get('is_URL') and analysis.get('URLs') != "non":
            urls = analysis.get('URLs', {})
            if len(urls) > 1:
                prompt += f"- There are {len(urls)} URLs in the SMS.\n"
            
            for url_idx, url_data in urls.items():
                url = url_data.get('URL', '')
                if len(urls) > 1:
                    prompt += f"- URL {url_idx}: {url}\n"
                else:
                    prompt += f"- URL: {url}\n"
                
                # Add analysis data if available
                if url_data.get('redirect_chain') not in [None, "non"]:
                    prompt += f"- Redirect Chain of {url}: {url_data['redirect_chain']}\n"
                
                if url_data.get('html_summary') not in [None, "non"]:
                    prompt += f"- Html Content Summary of {url}: {url_data['html_summary']}\n"
                
                if url_data.get('domain_info') not in [None, "non"]:
                    prompt += f"- Domain Information of {url}: {url_data['domain_info']}\n"
                
                if url_data.get('Image_content') not in [None, "non"]:
                    prompt += f"- Screenshot Description {url}: {url_data['Image_content']}\n"
                
                if url_data.get('brand_search') not in [None, "non"] and analysis.get('is_brand'):
                    brands = analysis.get('brands', [])
                    if len(brands) > 1:
                        prompt += f"- There are {len(brands)} brands referred in the SMS.\n"
                    
                    for brand_idx, brand in enumerate(brands):
                        prompt += f"- Brand {brand_idx}: {brand}\n"
                        brand_domains = url_data.get('brand_search', {}).get(brand_idx, {}).get('brand_domain', [])
                        prompt += f"- The top five results from a Google search of the brand name: {brand_domains}\n"
        else:
            prompt += "- No URL in the SMS.\n"
        
        return prompt
    
    def _perform_final_detection(self, prompt: str) -> Dict:
        """Perform final phishing detection using GPT."""
        try:
            response = self.openai_client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4o",
                response_format={
                    "type": "json_object",
                }
            )
            
            content = self._clean_json_response(response.choices[0].message.content)
            return json.loads(content)
            
        except Exception as e:
            print(f"Detection analysis failed: {e}")
            return {"category": True, "brief_reason": "Analysis failed", "advice": "Exercise caution"}
    
    def _generate_user_friendly_output(self, sms_message: str, detection_result: Dict) -> str:
        """Generate user-friendly analysis output."""
        prompt = self._get_user_friendly_prompt() + f"\nThe SMS message: {sms_message}\nThe analysis result: {detection_result}"
        
        try:
            response = self.openai_client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4o"
            )
            
            return self._clean_json_response(response.choices[0].message.content)
            
        except Exception:
            return "Unable to generate user-friendly analysis."
    
    def _save_analysis_results(self, analysis: Dict, output_dir: str):
        """Save complete analysis results to JSON file."""
        # Clean up data for JSON serialization
        cleaned_analysis = self._prepare_for_json_serialization(analysis)
        
        output_file = os.path.join(output_dir, "analysis_output.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_analysis, f, indent=2, ensure_ascii=False)
    
    def _prepare_for_json_serialization(self, data):
        """Prepare data for JSON serialization by handling special types."""
        from datetime import datetime
        from requests.structures import CaseInsensitiveDict
        
        if isinstance(data, CaseInsensitiveDict):
            return dict(data)
        elif isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, set):
            return list(data)
        elif isinstance(data, dict):
            return {k: self._prepare_for_json_serialization(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._prepare_for_json_serialization(item) for item in data]
        else:
            return data
    
    def _clean_json_response(self, content: str) -> str:
        """Clean GPT response to extract valid JSON."""
        content = content.replace("\n", "")
        content = content.replace("```json", "")
        content = content.replace("```", "")
        return content.strip()
    
    def _get_url_extraction_prompt(self) -> str:
        """Get prompt for URL and brand extraction."""
        return """Extract any URLs, and brand names from the following SMS message.
        Your output should be in json format and should not have any other output: 
        - is_URL: true or false
        - URLs: if no URL in SMS, answer non. If there are URLs, the response should be a list, each element is a URL extracted from the SMS. 
        - is_brand: true or false
        - brands: if no brand name in SMS, answer non. If there are brand names, the response should be a list, each element is a brand name extracted from the SMS. You can extract the brand name from the SMS content and the URL."""
    
    def _get_detection_prompt_template(self) -> str:
        """Get the main detection prompt template."""
        return """I want you to act as a spam detector to determine whether a given SMS is phishing, spam, or legitimate. Your analysis should be thorough and evidence-based. Analyze the SMS by following these steps:
        1. If the SMS is promoting any of the following categories: Online gambling, bets, spins, adult content, digital currency, lottery, it is either spam or phishing.
        2. The SMS is legitimate if it is from known organizations, such as appointment reminders,  OTP (One-Time Password) verification, delivery notifications, account updates, tracking information, or other expected messages.
        3. The SMS is considered legitimate if it involves a conversation between friends, family members, or colleagues.
        4. Promotions and advertisements are considered spam. The SMS is spam if it is promotion from legitimate companies and is not impersonating any brand, but it is advertisements, app download promotions, sales promotions, donation requests, event promotions, online loan services, or other irrelevant information.
        5. The SMS is phishing if it is fraudulent and attempts to deceive recipients into providing sensitive information or clicking malicious links. Phishing SMS may exhibit the following characteristics:
        Promotions or Rewards: Some phishing SMS offer fake prizes, rewards, or other incentives to lure recipients into clicking links or providing personal information.
        Urgent or Alarming Language: Phishing messages often create a sense of urgency or fear, such as threats of account suspension, missed payments, or urgent security alerts.
        Suspicious Links: Phishing messages may contain links to fake websites designed to steal personal information.
        Requests for Personal Information: Phishing SMS may ask for sensitive information like passwords, credit card numbers, social security numbers, or other personal details.
        Grammatical and Spelling Errors: Many phishing messages contain grammatical mistakes or unusual wording, which can be a red flag for recipients.
        Expired Domain: Phishing websites often use domains that expire quickly or are already listed for sale.
        Inconsistency: The URL may be irrelevant to the message content.
        6. Please be aware that: It is common to see shortened URLs in SMS. You can get the expanded URL from the provided redirection chain. Both phishing and legitimate URLs can be shortened. And both phishing and legitimate websites may use a robot-human verification page (CAPTCHA-like mechanism) before granting access the content.
        7. I will provide you with some external information if there is a URL in the SMS. The information includes:
        - Redirect Chain: The URL may redirect through multiple intermediate links before reaching the final destination; if any of them is flagged as phishing, the original URL becomes suspicious.
        - Brand Search Information:  The top five results from a Google search of the brand name. You can compare if the URL's domain matches the results from Google.
        - Screenshot Description: A description of the website's screenshot, highlighting any notable visual elements.
        - HTML Content Summary: The title of HTML, and the summary of its content.
        - Domain Information: The domain registration details, including registrar, creation date, and DNS records, which are analyzed to verify the domain's legitimacy.
        8. Please give your rationales before making a decision. And your output should be in json format and should not have any other output:
        - brand\_impersonated: brand name associated with the SMS, if applicable.
        - URL: any URL appears in SMS, if no URL, answer "non".
        - rationales: detailed rationales for the determination, up to 500 words. Directly give sentences, do not categorize the rationales. Only tell the reasons why the SMS is legitimate or not, do not include the reasons why the SMS is spam or phishing.
        - brief\_reason: brief reason for the determination.
        - category: True or False. If the SMS is legitimate, output False. Else, output True.
        - advice: If the SMS is phishing, output potential risk and your advice for the recipients, such as ''Do not respond to this message or access the link.''

        Below is the information of the SMS:"""
    
    def _get_user_friendly_prompt(self) -> str:
        """Get prompt for generating user-friendly output."""
        return """Based on the detailed analysis, I want you to create a simple and easy-to-understand response to tell the user whether the text message is a phishing attempt or a legitimate message. Use plain language and avoid technical terms like URL or HTTP headers. Explain your conclusion in 3 sentences, focusing on whether the message seems suspicious or safe. Provide a simple reason to support your conclusion, including clear evidence such as a suspicious website link or an urgent tone in the message. The response should be reassuring and concise, easy for anyone to understand."""


def detect_sms_phishing(
    sms_message: str,
    openai_api_key: str,
    jina_api_key: str,
    output_dir: str = "output"
) -> bool:
    """
    Convenience function to detect SMS phishing.
    
    Args:
        sms_message (str): The SMS message to analyze
        openai_api_key (str): OpenAI API key
        jina_api_key (str): Jina API key  
        output_dir (str): Output directory for results
        
    Returns:
        bool: True if phishing/spam detected, False if legitimate
    """
    detector = SMSPhishingDetector(openai_api_key, jina_api_key)
    return detector.detect_sms_phishing(sms_message, output_dir)


# Example usage
if __name__ == "__main__":
    # Example SMS message
    test_sms = "[US POSTAL] Your package is ready for delivery. Confirm your address to avoid returns: https://dik.si/postal"
    # test_sms = "Need to set up data and picture messaging? Mint mobile will be sending you a message with instructions shortly. Or check it out bit.ly/mintapn"
    # Initialize detector (replace with your actual API keys)
    detector = SMSPhishingDetector(openai_api_key, jina_api_key, google_cloud_API_key, search_engine_ID)
    result = detector.detect_sms_phishing(test_sms, "analysis_output")
    print(f"Phishing detected: {result}")