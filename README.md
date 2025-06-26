# This repository contains the supplementary materials for the paper:
**Title**: Can You Walk Me Through It? Explainable SMS-Phishing Detection Using LLM-Based Agents

**Authors**: Yizhu Wang, Haoyu Zhai, Chenkai Wang, Qingying Hao, Nick A. Cohen, Roopa Foulger, Jonathan A. Handler, Gang Wang

**Published in**: SOUPS 2025


## Repository Contents

```
├── UserStudy/                              # Materials and codebooks of the user study
│   ├── UserstudyCodebook.md                # Three detailed codebooks for analyzing open-text answers
│   ├── UserStudyMaterials.md               # All questions, messages, and SmishX explanations used
│   └── UserStudyWorkflow.pdf               # Detailed workflow of user study design
├── data/                                   # Coming soon
├── main.py                                 # Main detection system
├── config.py                               # API configuration
├── requirements.txt                        # Python dependencies
├── crawler.js                              # Puppeteer screenshot script
└── README.md                               # This file
```

## Key Files

- **UserStudy/UserstudyCodebook.md**: This file includes three detailed codebooks for analyzing the open-text answers from the user study (Simplified versions are included in the paper's Appendix.):
  - Codebook of User Feedback
  - Codebook for Disagreement with AI Agent (why participants believed the SMS was phishing despite the AI determining it as legitimate)
  - Codebook for Disagreement with AI Agent (why participants believed the SMS was legitimate despite the AI determining it as phishing)

- **UserStudy/UserStudyMaterials.md**: This file contains all the questions asked during the user study, along with the messages and SmishX's explanations used in the study.

- **UserStudy/UserStudyWorkflow.pdf**: This PDF file illustrates the detailed workflow of our user study design. A simplified version of this workflow is included in the paper.


## Quick Start to Run the Code

### System Requirements

- **Python 3.8+**
- **Node.js 16+** (for screenshot capture)
- **npm** (Node Package Manager)

### Prerequisites

You'll need to obtain the following API keys:

1. **OpenAI API Key** - Get from [OpenAI Platform](https://platform.openai.com/api-keys)
2. **Jina Reader API Key** - Get from [Jina.ai](https://jina.ai/reader/)
3. **Google Cloud API Key** - Get from [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
4. **Google Search Engine ID** - Get from [Programmable Search Engine](https://programmablesearchengine.google.com/controlpanel/all)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yizhu-joy/SmishX.git
cd SmishX
```

### 2. Set Up Python Environment with Conda

```bash
# Create conda environment
conda create -n SmishX python=3.9

# Activate conda environment
conda activate SmishX

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Set Up Node.js Dependencies
You need to meet the following pre-requisites first:
- Node.js version 16.0
- Have NPM installed
  
If not certain, confirm the prerequisites by running:
```bash
node -v
npm -v
```
Set up
```bash
# Install Node.js dependencies
npx crawlee create crawler_proj

# Select **Empty project [JavaScript]** option using arrow keys.

# Move crawler.js to crawler_proj
move crawler.js crawler_proj\
```

### 4. Configure API Keys

Edit `config.py` and replace the placeholder values with your actual API keys:
 ```python
 # OpenAI API Key
 openai_api_key = "your_actual_openai_api_key_here"
 
 # Jina Reader API Key
 jina_api_key = "your_actual_jina_api_key_here"
 
 # Google Cloud API Key
 google_cloud_API_key = "your_actual_google_cloud_API_key_here"
 
 # Search Engine ID
 search_engine_ID = "your_actual_search_engine_ID_here"
```


## Usage

### Basic Usage

```python
from main import SMSPhishingDetector
from config import openai_api_key, jina_api_key, google_cloud_API_key, search_engine_ID

# Initialize the detector
detector = SMSPhishingDetector(
    openai_api_key=openai_api_key,
    jina_api_key=jina_api_key,
    google_cloud_API_key=google_cloud_API_key,
    search_engine_id=search_engine_ID
)

# Analyze an SMS message
sms_message = "Your package is ready for delivery. Confirm: https://suspicious-link.com"
result = detector.detect_sms_phishing(sms_message, output_dir="analysis_results")

print(f"Phishing detected: {result}")

# True: Phishing
# False: Legitimate
```

### Running the Example

```bash
python main.py
```

## Dataset
Coming soon.


## Citation

If you use these materials in your research, please cite:

```bibtex
@inproceedings{smishx2025wang,
  author = {Yizhu Wang and Haoyu Zhai and Chenkai Wang and Qingying Hao and Nick A. Cohen and Roopa Foulger and Jonathan A. Handler and Gang Wang},
  title = {Can You Walk Me Through It? Explainable SMS-Phishing Detection Using LLM-Based Agents},
  booktitle = {Proceedings of the 2025 Symposium on Usable Privacy and Security (SOUPS)},
  year = {2025},
  publisher = {USENIX Association}
}
```


