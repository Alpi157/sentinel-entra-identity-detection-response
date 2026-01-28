# AI Triage Summarizer (Human-in-the-loop)

## What it does
Reads an **investigation bundle JSON** and generates a structured Markdown triage summary:
- what happened
- why it’s suspicious
- key evidence highlights
- recommended actions
- confidence score + rationale

## Safety model
- **No autonomous containment actions**
- Produces recommendations for a human analyst
- Designed to feed PB-01 ticketing and PB-02 manual containment workflows

## Run
From repo root:

```bash
python ai-triage-summarizer/src/summarize.py
