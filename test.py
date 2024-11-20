import gradio as gr
import openai
import requests
import re

# Set your OpenAI API key here
openai.api_key = 'YOUR_OPENAI_API_KEY'

# Function to fetch data from knowledge base repositories
def fetch_knowledge_base():
    urls = [
        "https://raw.githubusercontent.com/interfinetwork/smart-contract-audits/main/README.md",
        "https://raw.githubusercontent.com/GeorgeHNTR/portfolio/main/README.md",
        "https://raw.githubusercontent.com/razzorsec/AuditorsRoadmap/main/README.md",
        "https://raw.githubusercontent.com/TechRate/Smart-Contract-Audits/main/README.md"
    ]
    knowledge_base = ""
    for url in urls:
        response = requests.get(url)
        if response.status_code == 200:
            knowledge_base += response.text
    return knowledge_base

# Function to call GPT-4 for detailed explanations
def gpt4_explanation(issue):
    response = openai.Completion.create(
        engine="text-davinci-003",  # Use "text-davinci-003" or replace with the latest GPT-4 model name if available
        prompt=f"Explain the following smart contract issue in detail:\n\n{issue}",
        max_tokens=150,
        temperature=0.5
    )
    explanation = response.choices[0].text.strip()
    return explanation

# Function to analyze smart contract code
def analyze_contract(code):
    knowledge_base = fetch_knowledge_base()
    vulnerabilities = []
    good_practices = []

    # Define some patterns to look for based on common vulnerabilities
    patterns = {
        "selfdestruct": "Potential use of selfdestruct detected. This can be risky because it destroys the contract and might lead to loss of funds.",
        "delegatecall": "Potential use of delegatecall detected. This can be insecure because it allows execution of code in the context of the caller.",
        "tx.origin": "Use of tx.origin detected. This can be insecure because it can be phished to make unintended calls."
    }
    
    # Define good practices
    good_patterns = {
        "require": "Use of require statement detected. This is a good practice to ensure conditions are met before executing further.",
        "assert": "Use of assert statement detected. This is useful for catching conditions that should never happen."
    }

    # Check for vulnerabilities
    for pattern, message in patterns.items():
        if re.search(pattern, code):
            explanation = gpt4_explanation(message)
            vulnerabilities.append(f"{message}\nExplanation: {explanation}")
    
    # Check for good practices
    for pattern, message in good_patterns.items():
        if re.search(pattern, code):
            explanation = gpt4_explanation(message)
            good_practices.append(f"{message}\nExplanation: {explanation}")
    
    # Check against knowledge base for further insights
    knowledge_insights = []
    for line in knowledge_base.split('\n'):
        if any(pattern in line for pattern in patterns.keys()):
            knowledge_insights.append(line)

    response = "## Analysis Report\n"
    if vulnerabilities:
        response += "### Vulnerabilities Found:\n"
        for vuln in vulnerabilities:
            response += f"- {vuln}\n"
    else:
        response += "No vulnerabilities detected.\n"

    if good_practices:
        response += "\n### Good Practices Detected:\n"
        for practice in good_practices:
            response += f"- {practice}\n"

    if knowledge_insights:
        response += "\n### Additional Insights from Knowledge Base:\n"
        for insight in knowledge_insights:
            response += f"- {insight}\n"

    return response

def main():
    # Create the Gradio interface
    interface = gr.Interface(
        fn=analyze_contract,
        inputs=gr.Textbox(lines=20, placeholder="Paste your smart contract code here..."),
        outputs="markdown",
        title="Smart Contract Auditor",
        description="Upload your smart contract code to get a detailed security analysis."
    )

    # Launch the interface
    interface.launch()

if __name__ == "__main__":
    main()