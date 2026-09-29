---
title: "AWS AI Practitioner: AI Services Cheat Sheet"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2026-09-30T01:10:23+05:30
categories: [Cheat Sheets]
tags: [AWS, Cheat Sheet]
render_with_liquid: false
---

**Disclaimer**: _I put this review cheat sheet together using Claude AI and tweaked it a bit to make it easier for my own study sessions in Q2 2026. Hope it helps you on your journey!_

**This cheat sheet only contains AWS AI and ML Services (Domain 2-5). Please review the official [AWS AI Practitioner Study Guide](https://docs.aws.amazon.com/aws-certification/latest/ai-practitioner-01/ai-practitioner-01.html).**

**Other Resources:**

- **Tutorials Dojo** Practice Sets (highly recommended)
- [CloudNinja AI Practitioner Cheat Sheet](https://cloudninja.pro/cheat-sheets/ai-practitioner)

---

## Quick Exam Domain Map

| Domain                                           | Weight | What it Tests                                                        |
| ------------------------------------------------ | ------ | -------------------------------------------------------------------- |
| **Domain 1** — ML Fundamentals                   | 20%    | ML & AI concepts and definitions                                     |
| **Domain 2** — Fundamentals of Generative AI     | 24%    | GenAI concepts, LLMs, prompt engineering, FM types                   |
| **Domain 3** — Applications of Foundation Models | 28%    | Bedrock, RAG, fine-tuning, agentic AI, Amazon Q                      |
| **Domain 4** — Guidelines for Responsible AI     | 14%    | Bias, fairness, explainability, safety, human review                 |
| **Domain 5** — Security, Compliance & Governance | 14%    | IAM, encryption, Macie, GuardDuty, CloudTrail, shared responsibility |

---

<br/>

# Domain 2–5: AI Services Cheat Sheet

---

> **Note:** ML Fundamentals (Domain 1, 20%) is its own cheat sheet. This one covers other domains, mostly AWS AI Services.

---

## DOMAIN 2 + 3 — GENERATIVE AI & FOUNDATION MODELS

---

### 1. Key GenAI Concepts (Exam Vocabulary)

| Term                           | Plain Definition                                                                                                      | Exam Trigger Words                                        |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **Foundation Model (FM)**      | A very large pre-trained model trained on massive datasets; can be adapted to many tasks via prompting or fine-tuning | "pre-trained," "general-purpose model," "multi-task"      |
| **Large Language Model (LLM)** | A transformer-based FM trained on vast text; generates, summarizes, translates, and reasons about language            | "text generation," "chat," "summarize," "language"        |
| **Prompt**                     | The text input you give to an LLM to guide its response                                                               | "input to the model," "instruction," "query"              |
| **Inference**                  | Running a trained/pre-trained model to get a prediction/response                                                      | "generate output," "get response from model"              |
| **Token**                      | Roughly one word or subword; LLMs are billed and limited by token counts                                              | "context length," "token limit," "input/output size"      |
| **Context Window**             | The maximum amount of text (tokens) an LLM can "see" at once                                                          | "max input size," "long document support"                 |
| **Hallucination**              | When an LLM confidently generates false or fabricated information                                                     | "factually incorrect," "made up," "grounding problem"     |
| **Grounding**                  | Connecting LLM output to real, verified data sources to reduce hallucination                                          | "accurate," "up-to-date," "real data," "RAG"              |
| **Embedding**                  | A numerical vector representation of text that captures semantic meaning                                              | "similarity search," "vector database," "semantic search" |
| **Vector Database**            | A database that stores embeddings and supports similarity search                                                      | "OpenSearch," "relevant chunks," "semantic retrieval"     |
| **Temperature**                | Controls randomness/creativity of LLM output (0 = deterministic, >1 = creative)                                       | "consistent output," "creative variation"                 |
| **Multimodal**                 | A model that processes multiple input types (text + image + audio)                                                    | "image and text together," "vision model"                 |

---

### 2. Prompt Engineering (How to Get Better LLM Outputs)

Prompt engineering is the art of crafting inputs to guide LLM behavior — **no model retraining required**.

| Technique                  | What It Is                                                       | When to Use                                           | Example                                                                       |
| -------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------- |
| **Zero-Shot**              | Give the task with no examples                                   | Simple, direct tasks                                  | "Translate this to French:"                                                   |
| **Few-Shot**               | Provide a few input->output examples before the task             | Need consistent format/style                          | "Q: Capital of France? A: Paris. Q: Capital of Japan? A:"                     |
| **Chain-of-Thought (CoT)** | Ask the model to show its reasoning step-by-step                 | Math, logic, complex reasoning                        | "Let's think step by step..."                                                 |
| **System Prompt**          | Hidden pre-prompt that sets the model's role/persona/constraints | Chatbot character, safety rules                       | "You are a helpful financial advisor. Never give specific investment advice." |
| **RAG**                    | Inject relevant retrieved documents into the prompt as context   | Real-time data, private data, reducing hallucinations | "Based on the following document: [retrieved text], answer the question:"     |

> **Exam Tip:** Prompt engineering is **always cheaper and faster** than fine-tuning. Prefer it unless behavior change is needed.

#### **Prompt Engineering vs. Fine-Tuning vs. RAG — The Most Tested Triad**

| Method                        | Changes Model Weights?          | Use When                                                        | AWS Service                      |
| ----------------------------- | ------------------------------- | --------------------------------------------------------------- | -------------------------------- |
| **Prompt Engineering**        | No                              | Task is straightforward; quick iteration needed                 | Amazon Bedrock (prompt directly) |
| **RAG**                       | No                              | Model needs access to real-time/private/current data            | Bedrock Knowledge Bases          |
| **Fine-Tuning**               | Yes                             | Need to change model tone/behavior; teach domain-specific style | Bedrock Fine-Tuning / SageMaker  |
| **Pre-Training from Scratch** | Yes (builds entirely new model) | You have massive proprietary data and budget                    | SageMaker Training               |

> **Exam Trick:** "Reduce hallucinations with up-to-date company data" = **RAG**. "Change how the model writes/responds" = **Fine-Tuning**.

---

### 3. Amazon Bedrock (Managed FM API — Serverless GenAI Platform)

**What it is:** A fully managed, serverless service that gives you API access to top Foundation Models from multiple providers — without managing any infrastructure.

**Simple analogy:** Like a power grid — you don't build the generator, you just plug in and use the electricity (the AI model).

#### **Available Model Providers on Bedrock**

- **Amazon** — Titan (text, embeddings, image), Nova
- **Anthropic** — Claude (strong reasoning, long context)
- **Meta** — Llama
- **Mistral AI** — Mistral
- **Stability AI** — Stable Diffusion (image generation)
- **Cohere** — Command (text), Embed (embeddings)

#### **Bedrock Sub-Features (All High-Yield Exam Topics)**

##### **3a. Bedrock Knowledge Bases (RAG as a Service)**

- **What it does:** Connects your FM to a private data source (S3, Confluence, SharePoint, etc.), automatically chunks/embeds documents into a vector store (OpenSearch Serverless), and retrieves relevant context at query time.
- **Why use it:** Keeps LLM answers grounded in your real, private data without retraining.
- **Exam Trigger Words:** "company data," "internal documents," "reduce hallucinations," "private knowledge base," "real-time data," "RAG"
- **Example:** HR chatbot that answers policy questions by retrieving from the latest employee handbook stored in S3.
- **Don't Confuse With:**
  - **Amazon Kendra:** Kendra is a standalone _enterprise search engine_ (returns ranked document passages/links for human search). Bedrock Knowledge Bases is a _fully managed RAG pipeline_ built specifically to convert documents into vector embeddings, store them in a vector DB, and feed relevant context directly into an FM prompt.
    - _Why Knowledge Bases replaces Kendra:_ Kendra was originally designed for human enterprise search. When GenAI emerged, developers initially wired Kendra into custom RAG pipelines, but it was complex and costly. AWS built Bedrock Knowledge Bases as a native, serverless RAG engine (automating chunking, embeddings, vector search, and prompt injection). Because Knowledge Bases is faster, cheaper, and purpose-built for LLMs, **AWS placed Kendra into maintenance mode** and officially recommends Bedrock Knowledge Bases for new RAG and enterprise search workloads.
    - _Exam Trigger:_ "search internal documents for human users / enterprise search engine" → **Kendra**. "ground an FM response in enterprise data / RAG pipeline" → **Bedrock Knowledge Bases**.
  - **Bedrock Fine-Tuning:** Knowledge Bases retrieves dynamic/real-time facts without modifying model weights (solves knowledge gaps). Fine-Tuning updates model weights on labeled data to change tone, style, or task behavior (solves format/style gaps).
    - _Exam Trigger:_ "fresh / private company data," "reduce hallucinations" → **Knowledge Bases**. "brand voice," "domain-specific behavior" → **Fine-Tuning**.
  - **Bedrock Agents:** Knowledge Bases is **read-only retrieval** (fetching context). Agents can **take actions** (invoking APIs, executing Lambda functions, making bookings/updates).
    - _Exam Trigger:_ "find context / answer from docs" → **Knowledge Bases**. "execute multi-step actions / automate task" → **Agents**.
  - **Amazon OpenSearch Service:** OpenSearch is the underlying _vector database infrastructure_. Bedrock Knowledge Bases is the _end-to-end RAG orchestrator_ that uses OpenSearch Serverless (or Aurora/Pinecone) behind the scenes.
    - _Exam Trigger:_ "vector database engine" → **OpenSearch**. "turnkey managed RAG for Bedrock" → **Bedrock Knowledge Bases**.

##### **3b. Bedrock Agents (Autonomous Multi-Step Workflows)**

- **What it does:** Lets an FM take _actions_ — not just answer questions. The agent can call APIs, query databases, run Lambda functions, and chain multiple steps together to complete a goal.
- **Exam Trigger Words:** "automate a task," "take action," "multi-step workflow," "book a flight," "update a record," "execute code," "agentic AI"
- **Example:** Customer service agent that looks up your order in a database, checks shipping status via an API, and then sends you an email — all autonomously.
- **Don't Confuse With:**
  - **Knowledge Bases** = retrieval only (read). **Agents** = can _act_ (read + write + execute).
  - **Amazon Q Developer** = IDE-based code assistant. **Bedrock Agents** = custom agentic workflow builder.

##### **3c. Bedrock Guardrails (Content Safety Filter)**

- **What it does:** Acts as an input/output filter for your FM application. Blocks harmful content, redacts PII, restricts off-topic conversations, and prevents jailbreaks.
- **Exam Trigger Words:** "block harmful content," "filter toxic output," "PII redaction," "off-limits topics," "content safety," "jailbreak prevention"
- **Example:** A children's education chatbot that uses Guardrails to block any violent or adult content in responses.
- **Don't Confuse With:**
  - **SageMaker Clarify** = detects _statistical bias in training data_ (offline, pre/post-training). **Guardrails** = runtime content safety filter.
  - **Amazon Macie** = finds PII in **S3 buckets** (data at rest). **Guardrails** = redacts PII in **LLM conversations** (in-flight).

##### **3d. Bedrock Model Evaluation**

- **What it does:** Lets you compare multiple FMs side-by-side on your own prompts/datasets, using automated metrics (ROUGE, BERTScore, accuracy) or human reviewers.
- **Exam Trigger Words:** "compare models," "which model performs better," "evaluate accuracy," "model selection," "benchmark"
- **Example:** Testing Claude vs. Titan on your customer support FAQ dataset to pick the best model before deploying.

##### **3e. Bedrock Fine-Tuning**

- **What it does:** Adapts an existing FM's behavior using your own labeled examples — without training from scratch.
- **Exam Trigger Words:** "teach the model our style," "domain-specific behavior," "customize responses," "labeled training data," "change tone," "fine-tune"
- **Example:** Fine-tuning a model to always respond in your company's brand voice.
- **Limitation:** Not all Bedrock models support fine-tuning — only select models (e.g., Amazon Titan, some Anthropic/Meta variants). Check model availability.

#### **Fine-Tuning vs. Prompt Engineering — The Deciding Factor Guide**

This is one of the trickiest exam traps because both can technically produce "better outputs." The question always contains a **deciding factor** that locks in the answer. Learn to spot these signals:

| Deciding Factor in the Question                                                                | → Pick This                                                                 |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| "The team doesn't want to rewrite prompts every time" / "consistent behavior across all users" | **Fine-Tuning** — behavior is baked into weights, not prompt-dependent      |
| "The model must respond in our brand voice / legal writing style / medical terminology"        | **Fine-Tuning** — style/tone changes require weight updates                 |
| "We have thousands of labeled input-output examples"                                           | **Fine-Tuning** — you have the training data for it                         |
| "We need this deployed quickly / minimal effort / no training data"                            | **Prompt Engineering** — fastest path, zero cost                            |
| "The change is small / just needs clearer instructions"                                        | **Prompt Engineering** — simple behavior tweaks don't need retraining       |
| "The output needs to reflect the latest news / real-time data"                                 | **RAG (Knowledge Bases)** — fine-tuning can't give real-time knowledge      |
| "The model keeps making factual errors about our products"                                     | **RAG** if it's a knowledge gap; **Fine-Tuning** if it's a style/format gap |
| "We want the cheapest option"                                                                  | **Prompt Engineering** — free. Fine-Tuning has training + storage costs     |
| "Prompting has already been tried and isn't sufficient"                                        | **Fine-Tuning** — the question is explicitly ruling out prompting           |
| "The model needs to learn a new task format it has never seen"                                 | **Fine-Tuning** — e.g., teach it to always output JSON in a specific schema |

#### **The Core Mental Model**

```
Ask: "Can I solve this with a better prompt?"
  │
  ├── YES, and the team is okay maintaining prompts → Prompt Engineering
  │
  ├── YES technically, but the question says "already tried prompting" or
  │   "needs to be consistent without relying on prompts" → Fine-Tuning
  │
  ├── The problem is KNOWLEDGE (stale data, missing facts, private info) → RAG
  │
  └── The problem is BEHAVIOR/STYLE/FORMAT (tone, structure, domain syntax) → Fine-Tuning
```

#### **Side-by-Side Comparison**

|                                            | **Prompt Engineering**            | **RAG**                                                   | **Fine-Tuning**                                                                    |
| ------------------------------------------ | --------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Changes model weights?**                 | No                                | No                                                        | Yes                                                                                |
| **Training data needed?**                  | No                                | No (just documents)                                       | Yes — labeled input/output pairs                                                   |
| **Cost**                                   | Lowest                            | Medium (vector store + retrieval)                         | Highest (training compute + storage)                                               |
| **Solves knowledge gaps?**                 | Partially (context injection)     | Yes — best for this                                       | No — weights don't update knowledge cleanly                                        |
| **Solves behavior/style gaps?**            | Partially (system prompt)         | No                                                        | Yes — best for this                                                                |
| **Output consistent without user effort?** | No — depends on how you prompt    | No — depends on retrieval                                 | Yes — behavior is baked in permanently                                             |
| **Speed to deploy**                        | Immediate                         | Hours (index documents)                                   | Days (training job)                                                                |
| **Exam trigger signal**                    | "quick," "no data," "tried first" | "real-time data," "private docs," "reduce hallucinations" | "labeled examples," "consistent behavior," "brand voice," "prompting isn't enough" |

#### **Bedrock vs. SageMaker — The Big One**

|                    | **Amazon Bedrock**                              | **Amazon SageMaker**                             |
| ------------------ | ----------------------------------------------- | ------------------------------------------------ |
| **Model source**   | Pre-built FMs from top providers                | Your own custom model or open-source             |
| **Infrastructure** | Fully serverless (zero management)              | You choose/manage instance types                 |
| **Use case**       | Consume GenAI via API; build AI applications    | Build, train, fine-tune, deploy custom ML models |
| **When to choose** | Speed, no infra expertise, GenAI apps           | Full ML pipeline control, custom training        |
| **Exam shortcut**  | "Fully managed," "no infra," "foundation model" | "Custom training," "full control," "MLOps"       |

---

### 4. Amazon Nova (Amazon's Next-Gen FM Family)

**What it is:** Amazon's own family of state-of-the-art multimodal foundation models, available on Bedrock.

| Model           | Capability                                        |
| --------------- | ------------------------------------------------- |
| **Nova Micro**  | Text only; fastest and cheapest                   |
| **Nova Lite**   | Text + image + video; fast and low-cost           |
| **Nova Pro**    | Text + image + video; highest accuracy/capability |
| **Nova Canvas** | Image generation from text/image prompts          |
| **Nova Reel**   | Video generation from text/image prompts          |

> **Exam Tip:** If a question asks about Amazon's own first-party multimodal FM, think **Amazon Nova** (not Titan, which is older).

---

### 5. Amazon Q — The Generative AI Assistant Family

Amazon Q has **two totally separate products** — knowing which is which is a common exam trap.

#### **5a. Amazon Q Business (Enterprise AI Assistant)**

- **What it is:** A fully managed GenAI-powered enterprise chatbot that connects to 40+ data sources (Confluence, Salesforce, SharePoint, Jira, S3, etc.) and answers employee questions using company data, **respecting existing access controls (ACLs)**.
- **Use Case:** An employee asks "What is our parental leave policy?" and Q Business retrieves the answer from the internal HR wiki — only showing results the user has permission to see.
- **Exam Trigger Words:** "enterprise chatbot," "internal company data," "employee productivity," "business user," "40+ connectors," "respect access permissions," "knowledge worker"
- **Don't Confuse With:**
  - **Amazon Kendra** — pure enterprise search (keyword + semantic) with no chat interface. Q Business uses Kendra-like retrieval _plus_ a conversational LLM layer.
  - **Amazon Q Developer** — for _developers writing code_, not employees searching documents.
  - **Amazon Lex** — also builds chatbots, but they are a completely different kind. Lex makes **intent-based bots** (you define the conversation flows, intents, and slots — it's a structured bot-building framework). Q Business is a **pre-built GenAI chatbot** that you simply connect to your data sources — no conversation design needed. Think of it this way: Lex = build a chatbot from scratch with rules. Q Business = plug in your company data and get a chatbot instantly.

|                               | **Amazon Lex**                                           | **Amazon Q Business**                                      |
| ----------------------------- | -------------------------------------------------------- | ---------------------------------------------------------- |
| **Who designs conversation?** | You — define every intent, slot, and utterance           | AWS — LLM handles it automatically                         |
| **Powered by**                | NLU + rule-based intent model                            | Foundation Model (GenAI)                                   |
| **Data source**               | Your backend (via Lambda)                                | Your company documents (40+ connectors)                    |
| **Audience**                  | Developer building a custom bot                          | Business deploying an enterprise assistant                 |
| **Exam trigger**              | "intent," "slot," "IVR," "Alexa-like," "build a chatbot" | "enterprise chatbot," "internal documents," "employee Q&A" |

> **Note:** As of mid-2026, Amazon Q Business is in **maintenance mode** and no longer accepting new customers. AWS recommends Bedrock Knowledge Bases + Agents for new builds. But **it may still appear on the exam** — know what it did.

#### **5b. Amazon Q Developer (AI Coding Assistant)**

- **What it is:** An AI pair programmer integrated into IDEs (VS Code, JetBrains), the AWS Console, and CLI. It generates code, explains code, detects bugs, suggests security fixes, and transforms legacy code (e.g., Java 8 to Java 17).
- **Use Case:** A developer types a comment `// function to parse a JSON response` and Q Developer auto-generates the full function body.
- **Exam Trigger Words:** "coding assistant," "IDE integration," "code suggestions," "debug code," "code transformation," "VS Code," "developer productivity," "security scan in IDE"
- **Don't Confuse With:**
  - **Amazon SageMaker Studio** — a full ML development IDE (notebooks, experiments, pipelines). Q Developer is a _coding helper plugin_, not an ML workspace.
  - **GitHub Copilot** — a competitor; Q Developer is the AWS equivalent.

#### **Q Business vs. Q Developer — The Quick Cheat**

```
Person using it is a...
  Business employee (HR, finance, marketing) --> Q Business
  Software developer / DevOps engineer       --> Q Developer
```

---

### 6. Amazon Kendra (Enterprise Intelligent Search)

- **What it is:** A managed ML-powered enterprise search service that understands natural-language queries and searches across your internal documents, databases, and S3 — not a chatbot, returns ranked results/passages, not generated answers.
- **Exam Trigger Words:** "enterprise search," "find information in documents," "natural language search," "internal knowledge base search," "search across data sources"
- **Example:** Employees search the legal document repository by typing "What are the penalties for late payment?" and Kendra finds the relevant contract clauses.
- **Limitation:** Kendra is a _search_ engine, not a _generative_ engine. It retrieves; it doesn't generate answers. For a full chatbot, pair Kendra with Bedrock.
- **Don't Confuse With:**
  - **Amazon Q Business** = Kendra-style search + generative chat layer (Kendra++ with conversation).
  - **Bedrock Knowledge Bases** = AWS's modern replacement for Kendra-based RAG pipelines.

> **Note:** Amazon Kendra is also in **maintenance mode** (no new customers). Understand the concept; know Bedrock Knowledge Bases is the replacement.

---

## TRADITIONAL AWS AI SERVICES (Pre-Built APIs)

These are **purpose-built AI APIs** — you send data in, get predictions out. No model training needed.

---

### 7. Amazon Rekognition (Computer Vision — Image & Video Analysis)

- **What it is:** A managed computer vision service that analyzes images and videos using pre-trained deep learning models.
- **Exam Trigger Words:** "detect objects," "facial analysis," "content moderation," "celebrity recognition," "PPE detection," "video analysis," "label detection," "text in image (OCR in images)"

#### **Capabilities**

| Feature                      | What It Does                                             | Example Use Case                              |
| ---------------------------- | -------------------------------------------------------- | --------------------------------------------- |
| **Object/Scene Detection**   | Identifies objects, scenes, activities                   | Security camera detecting a person            |
| **Facial Analysis**          | Detects faces, age range, emotions, gender               | Retail analytics measuring customer reactions |
| **Face Comparison**          | Compares two faces to determine if same person           | Identity verification app                     |
| **Celebrity Recognition**    | Identifies famous people                                 | Media company tagging news photos             |
| **Content Moderation**       | Flags explicit, violent, or disturbing content           | Social media platform auto-moderation         |
| **Text Detection in Images** | Reads text embedded in images (but NOT structured forms) | License plate recognition                     |
| **PPE Detection**            | Detects personal protective equipment (hard hats, masks) | Workplace safety compliance                   |
| **Video Analysis**           | All above features applied to video streams              | Security surveillance monitoring              |

#### **Limitations**

- Works only on **images and video** — not on documents or text files.
- For reading text from **scanned PDFs or forms**, use **Amazon Textract** instead.
- Face search requires a face collection to be created and indexed first.

#### **Don't Confuse With**

These three are the most commonly confused trio on the exam because all deal with "reading" something. The master rule: **what format is the input in?**

|                               | **Rekognition**                                          | **Textract**                                                   | **Comprehend**                                            |
| ----------------------------- | -------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------- |
| **Input**                     | Image file / Video stream                                | Scanned PDF / Image of a document                              | Plain text (already extracted)                            |
| **Output**                    | Labels: faces, objects, scenes, unsafe flags             | Extracted text + structure (key-value pairs, tables)           | Meaning: sentiment, entities, PII, topics                 |
| **Core question it answers**  | "What is IN this image/video?"                           | "What does this document SAY?"                                 | "What does this text MEAN?"                               |
| **Knows document structure?** | No                                                       | Yes — understands forms, tables, field names                   | No — needs clean text as input                            |
| **Understands text meaning?** | No                                                       | No — extracts, doesn't interpret                               | Yes — this is its whole job                               |
| **Exam trigger**              | "detect," "face," "object," "video," "moderation," "PPE" | "extract," "PDF," "form," "table," "OCR," "invoice," "scanned" | "sentiment," "entity," "PII in text," "classify," "topic" |

**Common exam pipeline:** scanned document → **Textract** (extract text) → **Comprehend** (analyze meaning). Rekognition is only in the picture when the input is a photo or video.

> **Quick one-liners:**
>
> - Image of a face/car/scene → **Rekognition**
> - Image of a tax form / invoice / contract → **Textract**
> - Raw text that needs to be understood → **Comprehend**

---

### 8. Amazon Textract (Document Intelligence — OCR + Structure Extraction)

- **What it is:** Goes beyond basic OCR to extract text, **form key-value pairs**, and **tables** from scanned documents, PDFs, and images — understanding document structure.
- **Exam Trigger Words:** "extract text from PDF," "read form fields," "extract tables," "scanned document," "handwritten text," "OCR," "process invoices/receipts," "key-value pairs"
- **Example:** Automatically extracting Name, Date, Amount from thousands of scanned insurance claim forms.

#### **Capabilities**

| Feature             | What It Does                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------- |
| **OCR**             | Extracts raw text from images/PDFs                                                          |
| **Forms Analysis**  | Detects key-value pairs (e.g., `Name: John Doe`)                                            |
| **Tables Analysis** | Extracts structured table data from documents                                               |
| **Queries**         | You ask questions like "What is the patient's date of birth?" and Textract finds the answer |
| **Signatures**      | Detects presence of signatures                                                              |

#### **Limitations**

- Textract reads **documents** — does not understand the _meaning_ of the text. For sentiment or entity extraction on extracted text, pipe output to **Amazon Comprehend**.
- Not a real-time video analysis service — document/image focused.

#### **Don't Confuse With**

> **See Rekognition (Section 7) for the full 3-way Rekognition vs. Textract vs. Comprehend comparison table.**

- **vs. Rekognition:** Rekognition takes images/video; Textract takes document images/PDFs. Trigger: if you're reading a _form or structured doc_ → Textract. If you're analyzing a _photo or video scene_ → Rekognition.
- **vs. Comprehend:** Textract gets the text _out_ of a document. Comprehend finds _meaning_ in text that's already been extracted. They are complementary, not competing — Textract feeds Comprehend.

---

### 9. Amazon Comprehend (NLP — Text Understanding & Analysis)

- **What it is:** A managed NLP service that finds insights and relationships in text — sentiment, entities, key phrases, language, topics, and PII.
- **Exam Trigger Words:** "sentiment analysis," "entity recognition," "detect PII in text," "key phrase extraction," "topic modeling," "language detection," "classify documents"

#### **Capabilities**

| Feature                       | What It Does                                                | Example                                   |
| ----------------------------- | ----------------------------------------------------------- | ----------------------------------------- |
| **Sentiment Analysis**        | Positive / Negative / Neutral / Mixed                       | Product review classifier                 |
| **Entity Recognition**        | Identifies people, places, organizations, dates, quantities | News article parsing                      |
| **Key Phrase Extraction**     | Pulls out the most important phrases                        | Meeting notes summarization               |
| **Language Detection**        | Identifies the language of text                             | Multi-language customer support routing   |
| **PII Detection & Redaction** | Finds and optionally redacts PII in text                    | Sanitizing text before storing or sharing |
| **Topic Modeling**            | Groups documents by discovered themes                       | Categorizing support tickets              |
| **Document Classification**   | Custom categories you train it on                           | Routing support emails to departments     |
| **Custom Entity Recognition** | Train it to find your domain-specific entities              | Identifying medical product names         |

#### **Limitations**

- Works on **text input only** — cannot read PDFs/images directly. Pair with **Textract** first for scanned documents.
- PII detection is for **text** data — NOT S3 scanning. For PII discovery in S3, use **Amazon Macie**.
- Not for medical/clinical text — use **Comprehend Medical** instead.

#### **Don't Confuse With**

> **See Rekognition (Section 7) for the full 3-way Rekognition vs. Textract vs. Comprehend comparison table.**

- **vs. Rekognition:** Rekognition handles image/video input; Comprehend handles text input. If the scenario has an image, it's never Comprehend.
- **vs. Textract:** Textract extracts text structure _from a document_. Comprehend interprets the _meaning_ of text. Use both together: Textract first, then pipe its output into Comprehend.
- **vs. Comprehend Medical:** Same idea, different domain. General text → Comprehend. Clinical/medical notes, PHI, ICD-10 → Comprehend Medical.

---

### 10. Amazon Comprehend Medical (Clinical NLP)

- **What it is:** A specialized version of Comprehend trained on medical and clinical text. Extracts medical entities, links them to medical ontologies (ICD-10-CM, RxNorm), and detects Protected Health Information (PHI).
- **Exam Trigger Words:** "medical records," "clinical notes," "medications," "diagnoses," "ICD-10," "PHI," "healthcare NLP," "conditions," "procedures," "RxNorm"
- **Example:** A hospital system automatically extracting all medication names and dosages from thousands of handwritten doctor's notes.
- **Limitation:** Works only on medical text — not general NLP. For general PII in text, use standard Comprehend.
- **Don't Confuse With AWS HealthScribe:** Comprehend Medical analyzes _already-written_ clinical text. HealthScribe works on _live audio conversations_ between patient and clinician and generates notes automatically.

---

### 10b. AWS HealthScribe (Clinical Conversation AI — Doctor-Patient Transcription + Note Generation)

- **What it is:** A HIPAA-eligible, fully managed generative AI service that automatically **transcribes doctor-patient conversations** (audio) and then **generates clinical notes** — including a structured summary with sections like medical history, assessment, and plan. It combines ASR (speech-to-text) + clinical NLP + generative summarization in a single pipeline.
- **Exam Trigger Words:** "doctor-patient conversation," "clinical notes from audio," "auto-generate clinical documentation," "physician documentation," "medical conversation," "HIPAA audio transcription + summarization," "ambient clinical intelligence"
- **Example:** A doctor consults with a patient for 20 minutes. HealthScribe listens to the audio, identifies who is speaking (doctor vs. patient), and automatically produces a structured clinical note with sections like Chief Complaint, History of Present Illness, and Treatment Plan — ready for EHR entry.

#### **What HealthScribe Does Under the Hood**

```
Doctor-Patient Audio
  --> [ASR: Transcribes speech to text]
  --> [Speaker diarization: Labels doctor vs. patient turns]
  --> [Clinical NLP: Identifies medical entities — symptoms, medications, diagnoses]
  --> [GenAI Summarization: Generates structured clinical note]
  --> Output: Transcript + Structured clinical note sections
```

#### **Capabilities**

| Feature                        | Detail                                                                                                                 |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| **Transcription**              | Converts the audio conversation to a full transcript                                                                   |
| **Speaker Role Detection**     | Distinguishes between CLINICIAN and PATIENT turns                                                                      |
| **Clinical Entity Extraction** | Identifies medications, symptoms, diagnoses, procedures                                                                |
| **Note Generation**            | Auto-generates structured clinical documentation (SOAP note style)                                                     |
| **Evidence Mapping**           | Each generated note section is linked back to the specific utterance in the transcript that supports it (auditability) |
| **HIPAA Eligible**             | Designed for healthcare workloads requiring HIPAA compliance                                                           |

#### **Limitations**

- HealthScribe is for **audio conversations only** — not for analyzing pre-existing written clinical notes (use Comprehend Medical for that).
- It is a **healthcare-specific service** — not suitable for general transcription + summarization use cases.
- Currently supports English language only.
- Output needs clinician review before entering EHR — it is an **AI assist**, not a fully autonomous documentation system.

#### **The Healthcare AI Services — Don't Confuse These Three**

|                     | **Transcribe Medical**                       | **Comprehend Medical**                                               | **AWS HealthScribe**                                                                   |
| ------------------- | -------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Input**           | Medical audio (doctor dictation)             | Clinical text (already written)                                      | Doctor-patient conversation audio                                                      |
| **Output**          | Transcript only                              | Entities, PHI, ontology links                                        | Transcript + speaker labels + structured clinical note                                 |
| **Use case**        | Doctor dictates notes, needs transcription   | Analyze existing EHR/clinical records                                | Live conversation auto-documentation                                                   |
| **GenAI involved?** | No                                           | No                                                                   | Yes (generative note summarization)                                                    |
| **Trigger**         | "doctor dictation," "medical speech-to-text" | "analyze medical records," "extract diagnoses/medications from text" | "auto-generate clinical notes," "doctor-patient conversation," "ambient documentation" |

---

### 11. Amazon Transcribe (Speech-to-Text / ASR)

- **What it is:** Converts spoken audio into written text (Automatic Speech Recognition).
- **Exam Trigger Words:** "speech-to-text," "transcribe audio," "call center recordings," "subtitles/captions," "voice to text," "speaker identification"

#### **Capabilities**

| Feature                    | What It Does                                                   |
| -------------------------- | -------------------------------------------------------------- |
| **Standard Transcription** | Converts audio/video to text                                   |
| **Speaker Diarization**    | Identifies and labels multiple speakers (Speaker 1, Speaker 2) |
| **Custom Vocabulary**      | Handles domain-specific terms (medical jargon, brand names)    |
| **Medical Transcription**  | Specialized model for clinical dictation                       |
| **Redaction**              | Removes PII from transcripts automatically                     |
| **Subtitles/Captions**     | Outputs WebVTT / SRT subtitle files                            |

#### **Limitations**

- Transcribes audio/video to text — does NOT _understand_ the content. Pipe to **Comprehend** for sentiment/entity analysis.
- For converting text _back_ to speech, use **Amazon Polly**.

#### **Don't Confuse With**

|               | **Transcribe**                      | **Transcribe Medical**               | **Polly**                        | **Lex**                    |
| ------------- | ----------------------------------- | ------------------------------------ | -------------------------------- | -------------------------- |
| **Input**     | Any audio                           | Clinical dictation audio             | Text                             | Text or voice              |
| **Output**    | General transcript                  | Medical transcript                   | Spoken audio                     | Conversation response      |
| **Direction** | Audio → Text                        | Audio → Text                         | Text → Audio                     | Text/Voice → Conversation  |
| **Trigger**   | "speech-to-text," "call recordings" | "doctor dictation," "clinical terms" | "text-to-speech," "voice output" | "chatbot," "intent," "IVR" |

---

### 12. Amazon Polly (Text-to-Speech / TTS)

- **What it is:** Converts written text into lifelike spoken audio using deep learning. Supports 30+ languages, 60+ voices, and neural TTS voices (NTTS) for highest quality.
- **Exam Trigger Words:** "text-to-speech," "generate audio from text," "read aloud," "voice output," "narration," "audiobook," "accessibility," "neural voice"
- **Example:** An e-learning platform that reads lesson content aloud for visually impaired students.

#### **Capabilities**

- **Standard voices** — fast, cost-effective
- **Neural TTS (NTTS)** — highest naturalness (sounds most human)
- **Speech Marks** — metadata for lip-syncing (word timestamps)
- **SSML (Speech Synthesis Markup Language)** — fine-grained control over prosody, emphasis, pauses, pronunciation

#### **Limitations**

- Polly only converts text to speech — it does not understand context or hold conversations. For an interactive voice chatbot, use **Amazon Lex**.
- Audio is one-directional (output only) — not transcription.

---

### 13. Amazon Translate (Neural Machine Translation)

- **What it is:** Translates text between 75+ languages using neural machine translation.
- **Exam Trigger Words:** "translate," "language translation," "multilingual," "localize content," "real-time translation," "batch translation"
- **Example:** Auto-translating customer support tickets filed in Spanish, French, and German into English for an agent review queue.

#### **Capabilities**

- **Real-time translation** — translate text on-the-fly via API
- **Batch translation** — translate large files/datasets stored in S3
- **Custom terminology** — preserve brand names, product names, and industry jargon during translation
- **Language auto-detection** — detects source language automatically

#### **Limitations**

- Translate works on **text** only — not audio (use Transcribe first), not images (use Textract first).
- Custom terminology must be explicitly configured; not applied by default.

#### **Don't Confuse With**

|              | **Translate**                                     | **Comprehend**                              |
| ------------ | ------------------------------------------------- | ------------------------------------------- |
| **Function** | Changes the language of text                      | Understands meaning/entities in text        |
| **Output**   | Same content in a different language              | Labels (sentiment, entities, PII)           |
| **Trigger**  | "translate," "multilingual," "Spanish to English" | "sentiment," "entity," "language detection" |

---

### 14. Amazon Lex (Conversational AI — Chatbot & Voice Bot Builder)

- **What it is:** A managed service for building conversational chatbots and voice bots using the same engine that powers **Amazon Alexa**. Handles natural language understanding (NLU) and automatic speech recognition (ASR).
- **Exam Trigger Words:** "chatbot," "virtual assistant," "conversational AI," "voice bot," "IVR (Interactive Voice Response)," "Alexa-like," "intents," "slots," "utterances"
- **Example:** A bank's customer service chatbot that understands "I want to check my balance" and extracts the intent (`CheckBalance`) and any parameters (account type).

#### **Key Concepts**

| Term            | Meaning                                                                        |
| --------------- | ------------------------------------------------------------------------------ |
| **Intent**      | What the user wants to do (e.g., `BookFlight`, `CheckBalance`)                 |
| **Utterance**   | A phrase a user might say to trigger an intent (e.g., "I want to fly to NYC")  |
| **Slot**        | A required piece of information (e.g., destination city, date)                 |
| **Fulfillment** | What happens when the bot has all slots — usually calls an AWS Lambda function |

#### **Limitations**

- Lex builds chatbots — it does not host the underlying AI model (that's handled internally). For generative, open-ended conversations, pair with Bedrock.
- Pre-GenAI style: Lex works with **defined intents**. It's not a general LLM chat interface.

#### **Don't Confuse With**

|                               | **Lex**                                                                            | **Q Business**                                                      | **Bedrock + Agents**                                   |
| ----------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------ |
| **Type**                      | Intent-rule-based bot (you design the flows)                                       | Pre-built GenAI enterprise chatbot (plug in your data)              | Open-ended LLM agent (takes real-world actions)        |
| **You define conversation?**  | Yes — every intent, slot, utterance                                                | No — LLM handles it                                                 | No — agent reasons autonomously                        |
| **Data source**               | Your own backend via Lambda                                                        | Company documents (Confluence, S3, SharePoint...)                   | APIs, databases, Lambda functions                      |
| **Structured or open-ended?** | Structured (only handles defined intents)                                          | Open-ended (answers any question from your data)                    | Open-ended (and executes tasks)                        |
| **Exam trigger**              | "build a chatbot," "IVR," "intent/slot," "Alexa-like," "define conversation flows" | "enterprise chatbot," "internal company data," "employee assistant" | "automate tasks," "take action," "multi-step workflow" |

> **The one-line rule:** Lex = **you build** the chatbot logic. Q Business = **AWS gives you** a chatbot, you just connect your data. Bedrock Agents = **the AI decides** what to do and does it.

---

### 15. Amazon Personalize (Real-Time Recommendation Engine)

- **What it is:** A fully managed ML service for building real-time, personalized recommendation systems — using the same technology as Amazon.com's product recommendations.
- **Exam Trigger Words:** "personalized recommendations," "product recommendations," "user-item interactions," "collaborative filtering," "real-time recommendations," "e-commerce," "streaming," "next best action"
- **Example:** A streaming service that recommends movies to users based on their watch history and similar users' preferences.

#### **Capabilities**

- Works with your own **user-item interaction data** (clicks, purchases, views, ratings)
- Supports **user personalization**, **similar items**, **re-ranking**, and **trending items** recipes
- Integrates with real-time event streaming for up-to-the-second recommendations

#### **Limitations**

- You **must provide your own interaction data** — Personalize doesn't work without historical data.
- Not a search engine — for keyword/semantic search, use **Kendra** or OpenSearch.
- Minimum data requirements: typically **1000+ interactions** and **25+ users/items** for meaningful results.

#### **Don't Confuse With**

|              | **Personalize**                        | **Kendra**                                     |
| ------------ | -------------------------------------- | ---------------------------------------------- |
| **Function** | Recommends items based on behavior     | Searches documents based on queries            |
| **Input**    | User interaction history               | Document corpus                                |
| **Trigger**  | "recommendations," "suggested for you" | "search," "find document," "enterprise search" |

- **vs. Amazon Forecast:** Both take historical data and make predictions, which makes them easy to mix up. See Forecast (Section 16) for the master comparison table. One-liner: Personalize predicts _what a specific user will like next_. Forecast predicts _what a metric (e.g., sales volume) will be next_.

---

### 16. Amazon Forecast (Time-Series Forecasting)

- **What it is:** A fully managed ML forecasting service that uses ML (including deep learning) to generate accurate demand/time-series forecasts — no ML expertise required.
- **Exam Trigger Words:** "forecast future values," "demand forecasting," "inventory planning," "time-series data," "predict next quarter sales," "predict future demand," "weather-influenced demand"
- **Example:** A retailer uses Forecast to predict product demand for each store for the next 30 days, incorporating weather data, promotions, and holidays.

#### **Capabilities**

- Incorporates **related time-series** (weather, promotions, events) alongside the target metric
- AutoML: automatically selects the best forecasting algorithm (ARIMA, DeepAR, etc.)
- Provides **probabilistic forecasts** (P10, P50, P90) — not just a single point prediction

#### **Limitations**

- Requires **historical time-series data** (at minimum a few hundred data points per series).
- Not for general regression — specifically designed for chronological data with time-based patterns.

#### **Don't Confuse With**

Forecast and Personalize are the most commonly confused pair because both say "give us your historical data and we'll predict something."

|                  | **Forecast**                                                      | **Personalize**                                                  | **SageMaker (Regression)**                |
| ---------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------- |
| **Predicts**     | A future _metric value_ (demand, sales, stock level)              | What a specific _user_ will like or do next                      | Any custom target you define              |
| **Input**        | Chronological time-series data (sales by day, week)               | User-item interaction history (clicks, purchases)                | Any tabular data                          |
| **Output**       | Numeric future values (e.g., "predicted demand: 450 units")       | Ranked list of recommended items per user                        | Custom prediction                         |
| **Who benefits** | Supply chain, operations, finance teams                           | Product, marketing, UX teams                                     | Data scientists building custom models    |
| **Trigger**      | "demand," "inventory," "time-series," "how many units next month" | "recommended for you," "what will this user buy," "personalized" | "custom ML," "full control," "regression" |

> **The one-line rule:** Forecast answers "_How much?_" (quantity over time). Personalize answers "_What next?_" (item for a user).

---

### 17. Amazon Fraud Detector (Real-Time Fraud Detection)

- **What it is:** A fully managed service that uses ML to detect potentially fraudulent online activities in real time — using the same technology Amazon uses for its own fraud detection.
- **Exam Trigger Words:** "detect fraud," "fraudulent transactions," "online fraud," "new account fraud," "payment fraud," "real-time risk score," "account takeover"
- **Example:** An e-commerce company checks every checkout event through Fraud Detector and blocks suspicious transactions with a risk score above a threshold.

#### **Capabilities**

- Built-in **fraud detection models** for common use cases (online payment fraud, new account fraud, guest checkout fraud)
- Can use your own **historical event data** with labeled fraud outcomes
- Provides a **risk score** (0-1000) and an **outcome** (approve/review/block) for each event

#### **Limitations**

- Purpose-built for fraud/risk detection — not a general anomaly detection service. For general anomaly detection in metrics, consider SageMaker's Random Cut Forest algorithm.
- Requires labeling past events as fraud/not-fraud to train effectively.

#### **Don't Confuse With**

|             | **Fraud Detector**                                   | **GuardDuty**                                                        |
| ----------- | ---------------------------------------------------- | -------------------------------------------------------------------- |
| **Scope**   | Business-level transaction fraud (your application)  | AWS account-level security threats                                   |
| **Trigger** | "payment fraud," "account takeover," "checkout risk" | "unusual API calls," "compromised credentials," "AWS account threat" |

---

### 18. Amazon Augmented AI — A2I (Human Review in the Loop)

- **What it is:** A managed service that makes it easy to build **human review workflows** for ML predictions. When a model's confidence is low (or randomly sampled), A2I routes the prediction to a human reviewer before final output.
- **Exam Trigger Words:** "human review," "human in the loop," "low confidence prediction," "manual review workflow," "auditing AI decisions," "human oversight," "verify AI output"
- **Example:** A document processing pipeline uses Textract to extract data. When Textract's confidence is below 80%, A2I automatically routes that document to a human reviewer via a customizable web UI.

#### **Built-In Integrations**

A2I works natively with:

- **Amazon Textract** (document review)
- **Amazon Rekognition** (content moderation review)
- Any **custom ML model** via the generic API

#### **Reviewer Workforces**

- **Amazon Mechanical Turk** — crowd-sourced reviewers
- **AWS Marketplace** — vendor-supplied reviewers
- **Private workforce** — your own employees

#### **Limitations**

- A2I adds **latency and cost** — it's not designed for pure real-time inference where speed is critical.
- A2I is the review mechanism — the actual labeling/annotation tool for training data is **SageMaker Ground Truth**.

#### **Don't Confuse With**

|               | **A2I**                                                                  | **SageMaker Ground Truth**                                |
| ------------- | ------------------------------------------------------------------------ | --------------------------------------------------------- |
| **Purpose**   | Human review of **production** ML predictions                            | Human labeling of **training data**                       |
| **When used** | During inference (live predictions)                                      | During data preparation (before training)                 |
| **Trigger**   | "review AI output," "low confidence," "human-in-the-loop on live system" | "label training data," "annotate dataset," "Ground Truth" |

---

## AMAZON SAGEMAKER — THE ML PLATFORM

SageMaker is AWS's comprehensive ML platform for **building, training, and deploying** ML models. It has many sub-services — each maps to a specific stage of the ML lifecycle.

---

### 19. SageMaker Studio (ML IDE / Development Environment)

- **What it is:** A web-based, unified IDE for all ML development tasks — notebooks, training jobs, experiments, model registry, pipelines, debugging, and monitoring — all in one place.
- **Exam Trigger Words:** "ML development environment," "data science workspace," "Jupyter notebooks on AWS," "track experiments," "manage ML pipeline," "MLOps workspace"
- **Don't Confuse With:**
  - **Amazon Q Developer** — a code completion plugin for general software developers in VS Code/JetBrains. Studio is a full ML platform IDE.
  - **SageMaker Canvas** — a no-code tool for business analysts. Studio is for data scientists who write code.

---

### 20. SageMaker Canvas (No-Code ML for Business Analysts)

- **What it is:** A visual, drag-and-drop interface for non-technical business users to build ML predictions without writing code. Just upload data, select the target column, and Canvas automatically trains and deploys a model.
- **Exam Trigger Words:** "no-code ML," "business analyst," "non-technical user," "drag-and-drop," "no programming," "self-service ML"
- **Don't Confuse With:**
  - **SageMaker Autopilot** — also AutoML, but outputs full code notebooks (Python + SageMaker scripts) and is aimed at **data scientists** who want transparency and code access. Canvas is for **business users** who want a black-box result.

---

### 21. SageMaker Autopilot (AutoML with Code Transparency)

- **What it is:** Automated ML that automatically performs data analysis, feature engineering, algorithm selection, training, and hyperparameter tuning — and gives you the full generated Python/SageMaker code to see exactly what it did.
- **Exam Trigger Words:** "AutoML," "automatic model selection," "automated training," "code notebooks generated," "data scientist with AutoML," "best model automatically"
- **Limitation:** Unlike Canvas, Autopilot is for users who want to understand and inspect the code. Not a pure point-and-click for business users.

---

### 22. SageMaker JumpStart (Pre-Built Models & Solutions Hub)

- **What it is:** A model hub inside SageMaker that provides ready-to-deploy pre-trained models (from Hugging Face, PyTorch Hub, etc.) and end-to-end ML solution templates, deployed onto **your own SageMaker-managed infrastructure**.
- **Exam Trigger Words:** "pre-trained models," "ready-to-deploy," "model hub," "solution templates," "deploy open-source model on SageMaker"
- **Don't Confuse With Bedrock:** JumpStart deploys models on **your** SageMaker infrastructure (you manage instance types). Bedrock is fully serverless — no infrastructure at all.

---

### 23. SageMaker Ground Truth (Data Labeling)

- **What it is:** A managed data labeling service that uses a combination of automated ML labeling and human workforce annotation to generate high-quality training labels.
- **Exam Trigger Words:** "label training data," "annotate dataset," "create ground truth," "human labeling," "active learning for labeling," "bounding boxes," "text classification labeling"
- **Example:** Labeling 100,000 images with bounding boxes around cars for a self-driving car training dataset.
- **Don't Confuse With A2I:** Ground Truth = labeling **training data** (pre-training). A2I = reviewing **live predictions** (post-deployment).

---

### 24. SageMaker Data Wrangler (Visual Data Prep)

- **What it is:** A visual tool inside SageMaker Studio for importing, cleaning, normalizing, and transforming ML training data — with 300+ built-in transforms and no code required.
- **Exam Trigger Words:** "data preparation," "feature engineering (visual)," "data transformation," "clean data," "normalize," "encode categorical variables"

---

### 25. SageMaker Feature Store (Feature Repository)

- **What it is:** A centralized, managed repository to store, share, and serve ML features — ensuring the same features used during training are also used during real-time inference (preventing training-serving skew).
- **Exam Trigger Words:** "feature repository," "training-serving consistency," "reuse features," "share features," "feature store," "online and offline feature serving"

---

### 26. SageMaker Clarify (Bias Detection & Explainability)

- **What it is:** Detects **statistical bias** in datasets and trained models, and provides **explainability** reports (SHAP values — feature importance) to understand why a model makes predictions.
- **Exam Trigger Words:** "detect bias," "explain model predictions," "feature importance," "SHAP," "fairness," "pre-training bias," "post-training bias," "model explainability"
- **Example:** A hiring ML model is audited with Clarify, which reveals the model scores resumes from certain zip codes 20% lower due to historical bias in training data.
- **Don't Confuse With:**
  - **Bedrock Guardrails** — runtime content safety filter. Clarify = _offline_ statistical analysis of bias in training/model data.
  - **SageMaker Model Monitor** — detects _drift_ in production. Clarify = _evaluates_ bias/explainability at training time.

---

### 27. SageMaker Model Monitor (Production Drift Detection)

- **What it is:** Continuously monitors deployed SageMaker model endpoints in production for **data drift** and **model quality degradation** — alerts you when inputs deviate from training distribution.
- **Exam Trigger Words:** "data drift," "model degradation," "monitor production model," "detect drift," "performance decline," "data quality in production"

#### **Don't Confuse With**

- **vs. SageMaker Clarify:** These two are the top exam trap in the SageMaker family. Both deal with "is something wrong with my model?" — but at different times and for different problems. Clarify runs _at training time_ and asks "is my model biased or unexplainable?" Model Monitor runs _in production_ and asks "are my live inputs drifting away from what the model was trained on?" Trigger: "bias" or "SHAP" → Clarify. "Drift" or "production degradation" → Model Monitor.
- **vs. Amazon CloudWatch:** CloudWatch monitors _infrastructure and application health_ (latency, error rate, invocation count). Model Monitor monitors _the data going into the model_ (are feature distributions changing?). Both can be used together — CloudWatch for ops, Model Monitor for ML data quality.

---

### 28. SageMaker Pipelines (ML Workflow Automation / CI/CD for ML)

- **What it is:** An orchestration tool for building, automating, and managing reproducible end-to-end ML workflows (pipelines) — from data prep to training to evaluation to deployment.
- **Exam Trigger Words:** "ML pipeline," "automate ML workflow," "CI/CD for ML," "MLOps," "reproducible training," "orchestrate steps"

---

### 29. SageMaker Model Registry

- **What it is:** A centralized catalog to register, version, track, and manage trained ML models. Includes approval workflows before models are deployed to production.
- **Exam Trigger Words:** "model versioning," "model registry," "approve model for deployment," "track model versions," "governance for models"

---

### 30. SageMaker Sub-Service Quick Reference

| Sub-Service        | Stage               | Who Uses It       | Exam Trigger                                         |
| ------------------ | ------------------- | ----------------- | ---------------------------------------------------- |
| **Studio**         | All stages          | Data Scientists   | "ML IDE," "notebook workspace," "manage experiments" |
| **Canvas**         | Training (no-code)  | Business Analysts | "no-code," "drag-and-drop," "non-technical"          |
| **Autopilot**      | Training (AutoML)   | Data Scientists   | "AutoML," "auto model selection," "generated code"   |
| **JumpStart**      | Training/Deployment | ML Engineers      | "pre-trained model hub," "deploy open-source model"  |
| **Ground Truth**   | Data Labeling       | All               | "label data," "annotate," "bounding boxes"           |
| **Data Wrangler**  | Data Prep           | Data Scientists   | "visual data prep," "300+ transforms"                |
| **Feature Store**  | Feature Management  | Data Scientists   | "feature repository," "training-serving consistency" |
| **Clarify**        | Evaluation          | Data Scientists   | "bias detection," "SHAP," "explainability"           |
| **Model Monitor**  | Monitoring          | MLOps             | "drift detection," "production monitoring"           |
| **Pipelines**      | Orchestration       | MLOps             | "ML CI/CD," "automate workflow," "orchestrate"       |
| **Model Registry** | Governance          | MLOps             | "model versioning," "approval workflow"              |

---

## DOMAIN 4 — RESPONSIBLE AI

---

### 31. Responsible AI Principles (AWS Framework)

AWS organizes Responsible AI around these pillars:

| Pillar             | Definition                                                               | AWS Tool/Service                                                      |
| ------------------ | ------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| **Fairness**       | Model outputs are equitable across demographic groups; no discrimination | SageMaker Clarify (bias detection)                                    |
| **Explainability** | Understanding _why_ a model made a decision                              | SageMaker Clarify (SHAP values), Model Cards                          |
| **Privacy**        | Protecting personal and sensitive data used in AI training/inference     | Macie (PII in S3), Guardrails (PII in chat), Comprehend (PII in text) |
| **Safety**         | Preventing harmful, toxic, or misleading AI outputs                      | Bedrock Guardrails                                                    |
| **Transparency**   | Documenting model behavior, limitations, and intended use                | Model Cards, AI Service Cards                                         |
| **Robustness**     | Model performs consistently even with noisy or adversarial inputs        | SageMaker Model Monitor                                               |
| **Governance**     | Processes for managing the AI lifecycle, audit trails, accountability    | SageMaker Model Registry, CloudTrail                                  |

---

### 32. Bias in AI — Types & Detection

| Bias Type             | Definition                                      | Example                                                     |
| --------------------- | ----------------------------------------------- | ----------------------------------------------------------- |
| **Data Bias**         | Training data is unrepresentative or skewed     | Facial recognition trained mostly on lighter-skinned faces  |
| **Algorithmic Bias**  | The model amplifies existing data biases        | Loan model denies more applications from minority zip codes |
| **Confirmation Bias** | Only collecting data that confirms a hypothesis | Only surveying satisfied customers for a satisfaction study |
| **Sampling Bias**     | Non-random sample from the population           | Training medical model only on data from one hospital       |

> **AWS Tool for Bias Detection:** **Amazon SageMaker Clarify** — provides pre-training bias metrics (data imbalance) and post-training bias metrics (model output disparities).

---

### 33. Model Cards & AI Service Cards

- **Model Cards:** Structured documents attached to a trained ML model in SageMaker that describe model purpose, training data, performance metrics, limitations, and intended use. Improves transparency.
- **AI Service Cards:** AWS-published documentation for their managed AI services (Rekognition, Comprehend, etc.) explaining capabilities, limitations, use cases, and responsible AI considerations.
- **Exam Trigger Words:** "document model," "model transparency," "model limitations," "intended use," "responsible documentation"

---

### 34. Human Review — Amazon A2I (Responsible AI Context)

A2I enables the **"Human in the Loop"** pattern — critical for high-stakes AI decisions where automation alone is insufficient:

- Medical diagnosis assistance
- Loan approvals
- Content moderation at scale
- Legal document analysis

> **Exam Tip:** Whenever a question mentions "ensure accuracy of AI predictions" or "human oversight for critical decisions," the answer is **Amazon A2I**.

---

## DOMAIN 5 — SECURITY, COMPLIANCE & GOVERNANCE FOR AI

---

### 35. Shared Responsibility Model (Applied to AI)

```
AWS Responsible For ("Security OF the Cloud"):
  - Physical data center security
  - Hardware, networking, and global infrastructure
  - Managed service infrastructure (Bedrock servers, SageMaker clusters)

Customer Responsible For ("Security IN the Cloud"):
  - IAM: Who can access your AI resources
  - Data encryption: Encrypting training data and model artifacts (KMS)
  - Guardrails configuration: Applying content filters to your Bedrock apps
  - Model governance: Registering, approving, and auditing model versions
  - Network security: VPC configurations for your SageMaker endpoints
```

> **Exam Tip:** "AWS ensures the hardware is secure" is AWS's responsibility. "You ensure the right people have access to your S3 training data" is the customer's responsibility.

---

### 36. AWS IAM (Identity & Access Management for AI)

- **Role:** Controls which users, roles, and services can access AWS AI resources.
- **Exam Trigger Words:** "access control," "least privilege," "who can invoke Bedrock," "restrict SageMaker access," "permissions"
- **Key concepts:**
  - Use **IAM Roles** (not users) for AWS services to access each other (e.g., Bedrock reading from S3).
  - Apply **least-privilege principle** — only grant what's needed.
  - **Resource-based policies** on S3 buckets to control which services can read training data.

---

### 37. Amazon Macie (PII/Sensitive Data Discovery in S3)

- **What it is:** Uses ML to automatically discover, classify, and protect **sensitive data (PII, financial data, credentials)** stored in **Amazon S3**.
- **Exam Trigger Words:** "PII in S3," "sensitive data in S3," "automatically find PII," "data privacy compliance," "GDPR data discovery," "S3 data classification"
- **Example:** An organization runs Macie across all S3 buckets to find buckets that accidentally contain credit card numbers or Social Security Numbers.

#### **CRITICAL LIMITATION**

> **Macie only works with Amazon S3.** It does NOT scan databases (RDS, DynamoDB), EBS volumes, Glacier, or other storage services. For PII in live text/conversations, use **Comprehend** or **Bedrock Guardrails**.

#### **Don't Confuse With**

|                  | **Macie**                                | **Comprehend**       | **Bedrock Guardrails**              |
| ---------------- | ---------------------------------------- | -------------------- | ----------------------------------- |
| **PII Location** | S3 buckets (data at rest)                | Raw text (API call)  | LLM chat conversations (runtime)    |
| **Trigger**      | "PII in S3," "sensitive data scan on S3" | "detect PII in text" | "redact PII from chatbot responses" |

---

### 38. Amazon GuardDuty (Threat Detection / Security Monitoring)

- **What it is:** A managed threat detection service that continuously monitors your AWS account using ML and threat intelligence to detect **malicious activity, unauthorized behavior, and compromised resources**.
- **Exam Trigger Words:** "unusual API calls," "compromised credentials," "unauthorized access," "crypto-mining," "threat detection," "AWS account security," "anomalous behavior," "prompt injection detection"
- **AI Protection feature:** GuardDuty now includes **AI threat detection** — detecting anomalous Bedrock model invocations (e.g., cost-harvesting attacks, prompt injection, unusual usage patterns).
- **Example:** GuardDuty alerts when an IAM user from an unknown IP in a foreign country starts invoking Bedrock models at 3 AM.

#### **Don't Confuse With**

|             | **GuardDuty**                                        | **Inspector**                                                     | **Macie**                                    |
| ----------- | ---------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------- |
| **Focus**   | Account-level threat/behavior                        | Infrastructure vulnerability scanning                             | Data classification/PII in S3                |
| **Trigger** | "unusual activity," "account threat," "malicious IP" | "CVE vulnerabilities," "software vulnerabilities," "EC2 patching" | "PII in S3," "sensitive data classification" |

---

### 39. Amazon Inspector (Infrastructure Vulnerability Assessment)

- **What it is:** Automatically scans AWS infrastructure (EC2, Lambda, container images) for **software vulnerabilities (CVEs)** and unintended network exposure.
- **Exam Trigger Words:** "vulnerability scanning," "CVE," "software vulnerabilities," "patch management," "network exposure," "EC2/Lambda security scan"
- **Example:** Inspector scans the EC2 instances hosting your SageMaker training jobs and flags that an outdated Python library has a known CVE.
- **Limitation:** Inspector scans **software/infrastructure** — not data content. Does not find PII (that's Macie).

---

### 40. AWS CloudTrail (Audit Log — Who Did What When Where)

- **What it is:** Records all API calls made in your AWS account — creating an immutable audit trail of who did what, when, from where.
- **Exam Trigger Words:** "audit trail," "who made this API call," "logging API activity," "compliance audit," "track changes," "governance," "who invoked Bedrock"
- **Example:** Security team queries CloudTrail to see who invoked a Bedrock model at an unusual time, and which IAM role was used.
- **Limitation:** CloudTrail logs _events/actions_ — **NOT the content of the data**. For data sensitivity, use Macie.

---

### 41. AWS Config (Resource Compliance Tracking)

- **What it is:** Continuously evaluates your AWS resource configurations against compliance rules and tracks configuration changes over time.
- **Exam Trigger Words:** "compliance rules," "resource configuration," "S3 public access enabled," "configuration drift," "resource inventory," "compliance check"
- **Example:** Config rule that alerts when a SageMaker endpoint becomes publicly accessible (violating security policy).

---

### 42. AWS KMS (Key Management Service — Encryption for AI)

- **What it is:** Creates and manages cryptographic keys used to encrypt your AI/ML data — training datasets, model artifacts, and inference inputs/outputs.
- **Exam Trigger Words:** "encrypt training data," "encryption at rest," "KMS key," "customer-managed key," "encrypt S3 training data," "model artifact encryption"
- **Example:** Using a customer-managed KMS key to encrypt sensitive medical training data in S3 before using it for SageMaker training.

---

## SUPPORTING INFRASTRUCTURE FOR AI/ML PIPELINES

> These services appear on the official AIF-C01 in-scope list. They aren't AI services themselves but are commonly used **alongside** AI/ML services. The exam tests you on their role in an AI/ML context, not on deep configuration.

---

### 43. AWS Glue (ETL & Data Cataloging — Prep Data for AI)

- **What it is:** A _serverless data integration and ETL (Extract, Transform, Load)_ service. Discovers raw data schemas automatically and transforms data for downstream use.
- **Role in AI/ML:** Cleans and prepares raw data in S3 or databases before it goes into SageMaker training or a Bedrock Knowledge Base.
- **Exam Trigger Words:** "ETL pipeline," "prepare data for ML," "data cataloging," "transform raw data," "data integration," "clean S3 data before training"
- **Example:** Using Glue to convert messy CSV logs from S3 into a clean Parquet format before SageMaker ingests them for training.
- **Sub-service:** **AWS Glue DataBrew** — a visual, no-code data preparation tool (like Data Wrangler but for general analytics, not ML-specific).

---

### 44. Amazon CloudWatch (Monitoring & Logging for AI Workloads)

- **What it is:** AWS's primary monitoring and observability service — collects logs, metrics, and events from AWS services and applications.
- **Role in AI/ML:** Monitors SageMaker endpoint latency, invocation counts, error rates, and Bedrock API usage. Can trigger alarms or Lambda functions when thresholds are breached.
- **Exam Trigger Words:** "monitor endpoint performance," "track inference latency," "set alarms on model errors," "logs for AI pipeline," "operational visibility"
- **Don't Confuse With SageMaker Model Monitor:** Model Monitor detects _data/concept drift in model inputs_. CloudWatch monitors _infrastructure health and application metrics_ (latency, errors, cost).

---

### 45. Amazon OpenSearch Service (Vector Database & Semantic Search)

- **What it is:** A managed search and analytics engine. For AI use cases, it functions as the **vector database** that stores document embeddings for RAG pipelines.
- **Role in AI/ML:** Bedrock Knowledge Bases uses OpenSearch Serverless as its default vector store. Embeddings from your documents are stored here; at query time, OpenSearch finds the semantically closest chunks.
- **Exam Trigger Words:** "vector database," "semantic search," "store embeddings," "RAG vector store," "similarity search," "knowledge base backend"
- **Don't Confuse With Kendra:** Kendra = keyword + ML-powered document search. OpenSearch = vector embedding similarity search (lower-level, used as backend for RAG).

---

### 46. Amazon Redshift (Data Warehouse — Structured Data for AI)

- **What it is:** A fully managed, petabyte-scale cloud data warehouse for running analytical SQL queries on structured data.
- **Role in AI/ML:** Acts as the structured data source for ML training (export data to S3 for SageMaker) or for analytics feeding AI dashboards (QuickSight + ML Insights).
- **Exam Trigger Words:** "structured data warehouse," "analytical queries on large datasets," "source data for ML," "SQL at scale"
- **Don't Confuse With S3:** S3 = raw data lake (unstructured/structured files). Redshift = relational, SQL-queryable data warehouse for structured/aggregated data.

---

### 47. Amazon Quick (formerly QuickSight — Agentic AI Workspace + BI)

> **Naming note:** In late 2025, AWS rebranded Amazon QuickSight to **Amazon Quick**. QuickSight is now the BI/dashboarding sub-feature _within_ Amazon Quick. The official AIF-C01 in-scope list uses the name **Amazon Quick**. All existing QuickSight APIs, SDKs, and dashboards continue working unchanged.

- **What it is:** An agentic AI-powered enterprise workspace that combines BI/data visualization (the former QuickSight) with AI agents that can research, automate workflows, and integrate across work tools (Slack, Outlook, Salesforce, internal databases).
- **Role in AI/ML:** Applies GenAI to business analytics and daily enterprise workflows. The **QuickSight** component visualizes data with ML-powered insights (anomaly detection, forecasting). The **AI agent** component lets users ask questions and automate tasks in natural language.
- **Exam Trigger Words:** "BI dashboard," "visualize data," "ML insights," "anomaly detection in dashboards," "generative BI," "natural language querying of data," "agentic enterprise workspace"

#### **Amazon Quick / QuickSight — Key Capabilities**

| Capability                     | What It Does                                                                       |
| ------------------------------ | ---------------------------------------------------------------------------------- |
| **Dashboards & Visualization** | Traditional BI charts, reports, and KPI dashboards (the former QuickSight core)    |
| **ML Insights**                | Auto-detects anomalies, forecasts trends, identifies key drivers — no code needed  |
| **Q in QuickSight (NLQ)**      | Business users ask data questions in plain English → instant charts + AI narrative |
| **AI Agents**                  | Autonomous agents that research, summarize, and automate cross-app workflows       |

- **Don't Confuse With:**
  - **Amazon Q Business** — answers questions from internal _documents and knowledge bases_ (HR wikis, Confluence). Amazon Quick answers questions from _structured business data/databases_ and visualizes them.
  - **Amazon Q Developer** — AI coding assistant for developers. Amazon Quick is for business users doing analytics and productivity tasks.

---

### 48. Amazon S3 (Object Storage — The AI Data Lake)

- **What it is:** AWS's primary object storage. Effectively the default home for all AI/ML data.
- **Role in AI/ML:** Stores training datasets, model artifacts, Textract inputs, Bedrock Knowledge Base documents, Transcribe audio files, and inference outputs. Almost every AI service either reads from or writes to S3.
- **Exam Trigger Words:** "store training data," "model artifacts," "data lake," "source documents for RAG"
- **Key AI integrations:** SageMaker (training data), Bedrock Knowledge Bases (source docs), Macie (PII scanning), KMS (encryption), Glue (ETL source/target)

---

### 49. AWS Lake Formation (Data Lake Governance)

- **What it is:** Simplifies building, securing, and managing a data lake on S3. Provides centralized access control and data governance on top of S3/Glue.
- **Role in AI/ML:** Governs who can access which training datasets in the data lake; enforces column/row-level security on data used for ML.
- **Exam Trigger Words:** "data lake governance," "centralized access control for S3 data," "manage data lake permissions"

---

### 50. Amazon CloudWatch + AWS Trusted Advisor + AWS Well-Architected Tool (Governance & Cost)

- **Trusted Advisor:** Analyzes your AWS account and gives recommendations across cost optimization, security, performance, and reliability. For AI: flags over-provisioned SageMaker instances or unused Bedrock quotas.
- **Well-Architected Tool:** Helps you review your AI/ML architecture against AWS best practices across six pillars (operational excellence, security, reliability, performance, cost optimization, sustainability).
- **Exam Trigger Words for Trusted Advisor:** "cost optimization recommendations," "security best practices check," "unused resources"
- **Exam Trigger Words for Well-Architected:** "review architecture against best practices," "six pillars," "architecture assessment"

---

### 51. Security & Compliance Supporting Services

#### **AWS Secrets Manager (Secure Credential Storage)**

- **What it is:** Stores, rotates, and retrieves secrets (API keys, database passwords, model API credentials) securely.
- **Role in AI/ML:** Store API keys for third-party LLM providers or database credentials used by Bedrock Agents.
- **Exam Trigger Words:** "store API keys," "rotate credentials," "secrets," "secure credentials for AI app"
- **Don't Confuse With KMS:** KMS encrypts data with cryptographic keys. Secrets Manager stores application secrets (passwords, tokens) and handles rotation.

#### **AWS Audit Manager (Compliance Evidence Collection)**

- **What it is:** Continuously collects evidence (logs, config snapshots) to simplify compliance audits for frameworks like GDPR, HIPAA, SOC 2.
- **Role in AI/ML:** Automates evidence gathering for AI compliance audits — proving your Bedrock/SageMaker usage meets regulatory requirements.
- **Exam Trigger Words:** "compliance audit," "collect evidence," "GDPR compliance for AI," "automated audit reports"

#### **AWS Artifact (Compliance Reports Repository)**

- **What it is:** A self-service portal to download AWS's own compliance reports (SOC 2, ISO 27001, PCI DSS certifications, etc.).
- **Role in AI/ML:** When a customer/regulator asks "prove AWS is compliant with X" — download the report from Artifact.
- **Exam Trigger Words:** "download AWS compliance reports," "AWS certification documents," "SOC 2 report for AWS"
- **Don't Confuse With Audit Manager:** Artifact = download AWS's own compliance documents. Audit Manager = collect evidence about _your_ AWS usage for _your_ compliance audits.

---

## NEW AGENTIC AI SERVICES (2025–2026 Additions)

> These services were added to the official AIF-C01 in-scope list in 2025-2026. They represent AWS's push into the **Agentic AI** era — AI that doesn't just answer questions but takes real-world multi-step actions.

---

### 52. AWS Strands Agents (Open-Source Agentic AI Framework)

- **What it is:** An open-source Python SDK/framework released by AWS (May 2025) for building autonomous AI agents with minimal code. Defines an agent as 3 things: a **Model** (the LLM reasoning engine) + a **System Prompt** (role/goal instructions) + **Tools** (functions the agent can call). Strands manages the full _agentic loop_ — plan → call tool → observe result → repeat until done.
- **Role in AI/ML:** Developer-facing framework for building custom agentic applications. AWS uses it internally to power Amazon Q Developer, AWS Glue, and other services.
- **Example:** A developer builds a customer support agent in 20 lines of Python using Strands. The agent reads the customer's email, queries an order database via a tool, and generates a personalized response — all autonomously.
- **Exam Trigger Words:** "open-source agent framework," "build custom AI agents," "agentic loop," "model + tools + prompt," "multi-agent orchestration," "developer SDK for agents"
- **Don't Confuse With:**
  - **Bedrock Agents** — a fully managed, no-code/low-code agent _service_ inside the Bedrock console. Strands is the _developer SDK/framework_ for building agents in code with full flexibility.
  - **Bedrock AgentCore** — the managed _production runtime_ for hosting Strands agents at scale with enterprise security, memory, and observability. Think: Strands = build the agent. AgentCore = run the agent in production.

---

### 53. Amazon Bedrock AgentCore (Managed Agent Production Runtime)

- **What it is:** A fully managed, serverless platform within Amazon Bedrock for **deploying, running, and operating AI agents in production** at enterprise scale. It is **framework-agnostic** (works with Strands Agents, LangGraph, CrewAI, LlamaIndex, etc.) and **model-agnostic**.
- **Role in AI/ML:** Removes the "infrastructure tax" of running agents in production — you don't manage servers, sessions, or security plumbing. AgentCore provides all the enterprise-grade runtime capabilities agents need.
- **Example:** A company builds a multi-step procurement agent using Strands Agents locally, then deploys it to Bedrock AgentCore which handles secure execution, persistent memory across sessions, credential management, and full audit logging.

#### **AgentCore Sub-Capabilities**

| Capability        | What It Provides                                                                     |
| ----------------- | ------------------------------------------------------------------------------------ |
| **Runtime**       | Serverless, isolated execution environment for agents; supports long-running tasks   |
| **Memory**        | Short-term (session) and long-term (cross-session) persistent memory for agents      |
| **Gateway**       | Managed entry point routing traffic to tools, APIs, and MCP servers                  |
| **Identity**      | Centralized agent identity and credential management for secure AWS/3rd-party access |
| **Observability** | Monitoring, tracing, and debugging of agent behavior in production                   |
| **Evaluations**   | Systematic assessment of agent accuracy and performance                              |

- **Exam Trigger Words:** "managed agent runtime," "deploy agents in production," "agent memory," "agent observability," "enterprise-grade agent infrastructure," "serverless agent hosting"
- **Don't Confuse With:**
  - **Bedrock Agents** — the managed service for building agents _inside_ Bedrock using a visual workflow (no custom code needed). AgentCore is for deploying _custom-coded_ agents built with any framework into a managed runtime.
  - **Strands Agents** — the SDK used to _build_ agents. AgentCore is the managed _infrastructure_ used to _run_ them. They are designed to work together: Strands builds → AgentCore hosts.
  - **Bedrock Knowledge Bases** — read-only retrieval (context for LLMs). AgentCore is the full runtime for agents that take _actions_.

---

### 54. AWS Transform (Agentic AI-Powered Legacy Modernization)

- **What it is:** A fully managed, agentic AI service that automates **migrating and modernizing legacy enterprise workloads** to AWS — using autonomous AI agents to analyze codebases, map dependencies, generate migration plans, and execute refactoring. Targets VMware environments, mainframe applications, and Windows/.NET stacks.
- **Role in AI/ML:** Applies agentic AI to the cloud migration problem. AI agents autonomously discover infrastructure, generate transformation plans, and perform code refactoring — dramatically accelerating what used to take months of manual effort.
- **Example:** A bank runs AWS Transform on its 30-year-old COBOL mainframe codebase. The AI agents map all dependencies, generate a phased migration plan, refactor relevant logic into modern services, and containerize applications for ECS — a process that previously took 18 months is accelerated to weeks.
- **Exam Trigger Words:** "modernize legacy applications," "migrate mainframe," "VMware migration," "agentic migration," "automated code refactoring," "cloud transformation"
- **Don't Confuse With:**
  - **AWS Glue** — ETL service for transforming _data_ (moving and cleaning data between sources). AWS Transform transforms entire _applications and infrastructure_.
  - **AWS Migration Hub** — tracks and coordinates migrations but does NOT use AI agents to automate the migration work. Transform actively _executes_ the migration using AI.
  - **Amazon Q Developer** — an AI coding assistant that helps developers write/debug code. Transform autonomously migrates and modernizes entire legacy systems end-to-end.

---

## MASTER CHEAT SHEETS

---

### Service-to-Use-Case Quick Reference

| Scenario / Trigger                                         | AWS Service                   |
| ---------------------------------------------------------- | ----------------------------- |
| Build a GenAI app using a Foundation Model (serverless)    | **Amazon Bedrock**            |
| Connect GenAI app to private company data (RAG)            | **Bedrock Knowledge Bases**   |
| AI that can take actions / multi-step automated workflow   | **Bedrock Agents**            |
| Filter harmful/toxic LLM output or redact PII from chat    | **Bedrock Guardrails**        |
| Compare or select between multiple FM models               | **Bedrock Model Evaluation**  |
| Change model behavior / tone / domain via labeled examples | **Bedrock Fine-Tuning**       |
| Enterprise chatbot over company documents / 40+ connectors | **Amazon Q Business**         |
| AI coding assistant in VS Code / JetBrains / AWS CLI       | **Amazon Q Developer**        |
| Enterprise document search (natural language)              | **Amazon Kendra**             |
| Image/video analysis — objects, faces, moderation          | **Amazon Rekognition**        |
| Extract text, forms, tables from scanned PDFs              | **Amazon Textract**           |
| Sentiment, entities, PII detection in text                 | **Amazon Comprehend**         |
| Medical/clinical NLP (medications, conditions, PHI)        | **Amazon Comprehend Medical** |
| Auto-generate clinical notes from doctor-patient audio     | **AWS HealthScribe**          |
| Speech to text / transcribe audio recordings               | **Amazon Transcribe**         |
| Text to speech / generate voice narration                  | **Amazon Polly**              |
| Translate text between languages                           | **Amazon Translate**          |
| Build chatbot / voice bot (intent-based)                   | **Amazon Lex**                |
| Personalized product/content recommendations               | **Amazon Personalize**        |
| Demand/time-series forecasting                             | **Amazon Forecast**           |
| Detect online transaction fraud in real time               | **Amazon Fraud Detector**     |
| Human review of low-confidence AI predictions (live)       | **Amazon A2I**                |
| Label training data with human reviewers                   | **SageMaker Ground Truth**    |
| Full ML platform for custom training & deployment          | **Amazon SageMaker AI**       |
| No-code ML for business analysts                           | **SageMaker Canvas**          |
| AutoML with generated code (data scientist)                | **SageMaker Autopilot**       |
| Pre-trained model hub, deploy on SageMaker infra           | **SageMaker JumpStart**       |
| Visual data prep and feature engineering                   | **SageMaker Data Wrangler**   |
| Store and share ML features for consistency                | **SageMaker Feature Store**   |
| Detect bias in training data or model outputs              | **SageMaker Clarify**         |
| Monitor production model for data drift                    | **SageMaker Model Monitor**   |
| ML pipeline automation / CI-CD for ML                      | **SageMaker Pipelines**       |
| Version and approve models before deployment               | **SageMaker Model Registry**  |
| ML IDE / workspace for data scientists                     | **SageMaker Studio**          |
| Find PII / sensitive data in S3 buckets                    | **Amazon Macie**              |
| Detect threats / unusual activity in AWS account           | **Amazon GuardDuty**          |
| Scan EC2/Lambda for software vulnerabilities               | **Amazon Inspector**          |
| Audit trail — who made what API call                       | **AWS CloudTrail**            |
| Compliance rules for resource configurations               | **AWS Config**                |
| Encrypt training data / model artifacts                    | **AWS KMS**                   |
| Access control for AI resources                            | **AWS IAM**                   |

---

### The Confusingly Similar Services Matrix

| Pair                                    | Service A                                      | Service B                                      | How to Tell Apart                                                           |
| --------------------------------------- | ---------------------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Bedrock vs. SageMaker**               | Consume pre-built FMs, serverless              | Build/train/deploy custom ML, manage infra     | "Foundation Model API" = Bedrock. "Custom training" = SageMaker             |
| **RAG vs. Fine-Tuning**                 | Update context at query time, no weight change | Update model weights with training data        | "Real-time/private data" = RAG. "Change behavior/tone" = Fine-Tuning        |
| **Q Business vs. Q Developer**          | Enterprise chatbot for employees               | Coding assistant for developers                | "Business employee" = Q Business. "Developer/IDE" = Q Developer             |
| **Q Business vs. Kendra**               | Chat interface + retrieval + GenAI answer      | Search engine returning document passages      | "Generate an answer" = Q Business. "Return search results" = Kendra         |
| **Rekognition vs. Textract**            | Analyze images/video (faces, objects)          | Extract structured data from documents         | "Image of a car" = Rekognition. "Scanned insurance form" = Textract         |
| **Textract vs. Comprehend**             | Extract text/structure from documents          | Analyze meaning of already-extracted text      | "Get data OUT of PDF" = Textract. "Understand what text MEANS" = Comprehend |
| **Comprehend vs. Comprehend Medical**   | General text analysis                          | Medical/clinical text (PHI, medications)       | "Clinical notes/medical" = Comprehend Medical. "General text" = Comprehend  |
| **Transcribe vs. Polly**                | Audio to Text                                  | Text to Audio                                  | "Record to Transcript" = Transcribe. "Text to Voice" = Polly                |
| **Lex vs. Bedrock Agents**              | Structured chatbot with defined intents/slots  | Open-ended LLM agent that takes actions        | "IVR / intent-based bot" = Lex. "AI agent that executes tasks" = Agents     |
| **Personalize vs. Kendra**              | Recommendations from user behavior             | Search through document corpus                 | "Recommend products" = Personalize. "Find documents" = Kendra               |
| **Forecast vs. SageMaker Regression**   | Time-series forecasting (managed AutoML)       | Custom ML regression pipeline                  | "Demand/inventory forecast" = Forecast. "Custom ML model" = SageMaker       |
| **A2I vs. Ground Truth**                | Human review of LIVE predictions               | Human labeling of TRAINING data                | "Production review" = A2I. "Label training data" = Ground Truth             |
| **Clarify vs. Model Monitor**           | Detect bias in data/model (at training time)   | Detect drift in production (at inference time) | "Is my model biased?" = Clarify. "Is my live model degrading?" = Monitor    |
| **Macie vs. Comprehend vs. Guardrails** | PII in S3 (data at rest)                       | PII in text (API call)                         | PII in LLM chat (runtime)                                                   | "S3 scan" = Macie. "Text API" = Comprehend. "Chat filter" = Guardrails    |
| **GuardDuty vs. Inspector vs. Macie**   | AWS account threats (behavioral)               | Software vulnerabilities in infra              | PII in S3                                                                   | "Threat/anomaly" = GuardDuty. "CVE/patch" = Inspector. "PII data" = Macie |
| **Canvas vs. Autopilot**                | No-code ML (business user, black box)          | AutoML with full code output (data scientist)  | "Non-technical user" = Canvas. "Data scientist + code" = Autopilot          |
| **SageMaker JumpStart vs. Bedrock**     | Pre-trained models on YOUR SageMaker infra     | Pre-built FMs on AWS serverless infra          | "Manage compute myself" = JumpStart. "Zero infra" = Bedrock                 |

---

### Exam Trigger Word Master List

| If the question mentions...                                                                           | Think of...                  |
| ----------------------------------------------------------------------------------------------------- | ---------------------------- |
| "foundation model," "FM," "LLM API," "serverless GenAI"                                               | **Amazon Bedrock**           |
| "RAG," "private data," "real-time data," "grounding," "reduce hallucinations"                         | **Bedrock Knowledge Bases**  |
| "agent," "take action," "multi-step," "automate tasks," "execute API"                                 | **Bedrock Agents**           |
| "harmful content," "filter output," "PII in chat," "off-topic," "jailbreak"                           | **Bedrock Guardrails**       |
| "compare models," "evaluate FMs," "benchmark models"                                                  | **Bedrock Model Evaluation** |
| "fine-tune," "change behavior," "labeled examples," "domain-specific style"                           | **Bedrock Fine-Tuning**      |
| "enterprise chatbot," "internal documents," "business employee," "40+ connectors"                     | **Amazon Q Business**        |
| "coding assistant," "IDE," "code suggestions," "VS Code," "developer productivity"                    | **Amazon Q Developer**       |
| "enterprise search," "natural language search," "search documents"                                    | **Amazon Kendra**            |
| "image analysis," "video analysis," "face recognition," "object detection," "content moderation"      | **Amazon Rekognition**       |
| "scanned document," "PDF," "extract form fields," "tables," "OCR," "invoice"                          | **Amazon Textract**          |
| "sentiment," "entity recognition," "PII in text," "key phrases," "topic modeling"                     | **Amazon Comprehend**        |
| "clinical notes," "medical records," "medications," "ICD-10," "PHI"                                   | **Comprehend Medical**       |
| "doctor-patient conversation," "auto-generate clinical notes," "ambient documentation," "HIPAA audio" | **AWS HealthScribe**         |
| "transcribe audio," "speech-to-text," "call recordings," "subtitles"                                  | **Amazon Transcribe**        |
| "text-to-speech," "TTS," "read aloud," "voice narration," "audio from text"                           | **Amazon Polly**             |
| "translate," "multilingual," "French to English," "localize"                                          | **Amazon Translate**         |
| "chatbot," "virtual assistant," "IVR," "intent," "slots," "Alexa engine"                              | **Amazon Lex**               |
| "recommendations," "personalize," "suggested products," "collaborative filtering"                     | **Amazon Personalize**       |
| "forecast," "demand planning," "inventory prediction," "time-series"                                  | **Amazon Forecast**          |
| "fraud," "fraudulent transactions," "risk score," "payment fraud"                                     | **Amazon Fraud Detector**    |
| "human review," "human in the loop," "low-confidence prediction," "manual review"                     | **Amazon A2I**               |
| "label training data," "annotate," "bounding boxes," "Ground Truth"                                   | **SageMaker Ground Truth**   |
| "no-code ML," "business analyst," "non-technical," "drag-and-drop"                                    | **SageMaker Canvas**         |
| "AutoML," "automatic model selection," "auto training + code output"                                  | **SageMaker Autopilot**      |
| "pre-trained model hub," "open-source model on SageMaker"                                             | **SageMaker JumpStart**      |
| "visual data prep," "feature engineering GUI," "300+ transforms"                                      | **SageMaker Data Wrangler**  |
| "feature repository," "training-serving consistency," "share features"                                | **SageMaker Feature Store**  |
| "bias detection," "SHAP," "explainability," "fairness check"                                          | **SageMaker Clarify**        |
| "data drift," "production monitoring," "model degradation"                                            | **SageMaker Model Monitor**  |
| "ML pipeline," "CI/CD for ML," "orchestrate ML steps"                                                 | **SageMaker Pipelines**      |
| "model versioning," "approve model," "model registry"                                                 | **SageMaker Model Registry** |
| "ML IDE," "notebook workspace," "data science environment"                                            | **SageMaker Studio**         |
| "PII in S3," "sensitive data in S3," "scan S3 buckets," "GDPR S3"                                     | **Amazon Macie**             |
| "unusual API calls," "account threat," "compromised credentials," "prompt injection"                  | **Amazon GuardDuty**         |
| "software vulnerabilities," "CVE," "EC2/Lambda security scan"                                         | **Amazon Inspector**         |
| "audit trail," "who called API," "logging," "governance trail"                                        | **AWS CloudTrail**           |
| "compliance rules," "resource configuration," "config drift"                                          | **AWS Config**               |
| "encrypt data," "encryption at rest," "customer-managed key," "KMS"                                   | **AWS KMS**                  |
| "access control," "permissions," "least privilege," "IAM role"                                        | **AWS IAM**                  |

---

### Service Limitations Summary (Critical for Exam Traps)

| Service                  | Key Limitation                                                                         |
| ------------------------ | -------------------------------------------------------------------------------------- |
| **Macie**                | S3 only — does NOT scan RDS, DynamoDB, EBS, or other storage                           |
| **Comprehend**           | Works on text only — cannot read PDFs/images directly (pipe Textract first)            |
| **Comprehend (general)** | For clinical/medical text, use Comprehend Medical instead                              |
| **AWS HealthScribe**     | Audio conversations only; English only; output needs clinician review before EHR entry |
| **Transcribe Medical**   | Transcription only — does not generate clinical notes (HealthScribe does both)         |
| **Rekognition**          | Images/video only — not for document text extraction (use Textract)                    |
| **Kendra**               | Search only (retrieves); does NOT generate answers (pair with Bedrock for chat)        |
| **Lex**                  | Intent-based chatbots only; not an open-ended LLM conversation                         |
| **Amazon Forecast**      | Time-series data only; needs historical chronological data                             |
| **Personalize**          | Needs minimum interaction data (~1000+ interactions) to work well                      |
| **Bedrock Fine-Tuning**  | Not available for all models; only select providers support it                         |
| **A2I**                  | Adds latency — not for latency-critical real-time inference                            |
| **SageMaker Canvas**     | Designed for business analysts; outputs predictions, not code                          |
| **Transcribe**           | Produces a transcript only; does not understand meaning (pipe to Comprehend)           |
| **GuardDuty**            | Monitors AWS account behavior — not application-level fraud (use Fraud Detector)       |
| **Inspector**            | Infrastructure vulnerability scanning only — not for data classification               |

---

### Common Exam Architecture Patterns

#### **Pattern 1: Intelligent Document Processing Pipeline**

```
Scanned PDF (in S3)
  --> [Macie] --> Flag / redact PII in stored files
  --> [Textract] --> Extract raw text + form fields + tables
      --> [Comprehend] --> Detect entities / sentiment / classify
      --> [A2I] --> Human review (if confidence low)
      --> Processed Output (stored back to S3)
```

#### **Pattern 2: GenAI RAG Chatbot**

```
Step 1 — Ingestion (one-time setup):
  Company Docs (S3) --> [Bedrock Knowledge Base]
                            --> Chunk + Embed --> [OpenSearch vector store]

Step 2 — Query (at runtime):
  User Query --> [Bedrock Agent / FM]
                    --> [Knowledge Base] --> Semantic search in OpenSearch
                    --> Retrieved relevant chunks (context)

Step 3 — Generation:
  User Query + Retrieved Context --> [FM (Claude / Titan)]
      --> Raw Answer --> [Bedrock Guardrails] --> Safe Final Response
```

#### **Pattern 3: Human-in-the-Loop Review**

```
Input Document / Image
  --> [Textract / Rekognition] --> ML Prediction + Confidence Score
      --> IF confidence < threshold --> [A2I] --> Human Reviewer --> Verified Output
      --> IF confidence >= threshold --> Auto-approved Output
```

#### **Pattern 4: ML Model Development Lifecycle on SageMaker**

```
Raw Data (S3)
  --> [Glue / Data Wrangler] --> Cleaned + transformed data
      --> [Ground Truth] --> Human-labeled training dataset
          --> [Feature Store] --> Store reusable features
              --> [SageMaker Training Job] --> Trained model
                  --> [Clarify] --> Bias check + explainability report
                      --> [Model Registry] --> Version + approval gate
                          --> [SageMaker Endpoint] --> Live inference
                              --> [Model Monitor] --> Drift detection in production
```

#### **Pattern 5: Security Monitoring for AI Workloads**

```
Bedrock / SageMaker API calls --> [CloudTrail] --> Audit log of all actions
User / role access             --> [IAM]        --> Access control + least privilege
Training data in S3            --> [Macie]      --> PII detection
                               --> [KMS]        --> Encryption at rest
AWS account behavior           --> [GuardDuty]  --> Threat + anomaly detection
EC2 / Lambda infra             --> [Inspector]  --> Vulnerability scanning
```

---
