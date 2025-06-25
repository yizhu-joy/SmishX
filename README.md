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
├── crawlee-project/                        # Webpage Screenshot Taker
│   ├── crawler.js                          # Webpage Screenshot
│   └── package.json                        # Node.js package file
├── main.py                                 # Main function to run sms phishing detector
├── config.py                               # Config file to set the keys
└── README.md                               # This file
```

## Key Files

- **UserStudy/UserstudyCodebook.md**: This file includes three detailed codebooks for analyzing the open-text answers from the user study (Simplified versions are included in the paper's Appendix.):
  - Codebook of User Feedback
  - Codebook for Disagreement with AI Agent (why participants believed the SMS was phishing despite the AI determining it as legitimate)
  - Codebook for Disagreement with AI Agent (why participants believed the SMS was legitimate despite the AI determining it as phishing)

- **UserStudy/UserStudyMaterials.md**: This file contains all the questions asked during the user study, along with the messages and SmishX's explanations used in the study.

- **UserStudy/UserStudyWorkflow.pdf**: This PDF file illustrates the detailed workflow of our user study design. A simplified version of this workflow is included in the paper.


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


