---
title: "AWS AI Practitioner: ML Fundamentals Cheat Sheet"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2026-09-30T01:10:23+05:30
categories: [Cheat Sheets, AWS]
tags: [AWS, Cheat Sheet]
render_with_liquid: false
---

**Disclaimer**: *I put this review cheat sheet together using Claude AI and tweaked it a bit to make it easier for my own study sessions in Q2 2026. Hope it helps you on your journey!*

**This cheat sheet only contains AI and ML fundamentals and concepts (Domain 1). Please review the official [AWS AI Practitioner Study Guide](https://docs.aws.amazon.com/aws-certification/latest/ai-practitioner-01/ai-practitioner-01.html).**

**Other Resources:**
- **Tutorials Dojo** Practice Sets (highly recommended)
- [CloudNinja AI Practitioner Cheat Sheet](https://cloudninja.pro/cheat-sheets/ai-practitioner)

---

## Quick Exam Domain Map

| Domain | Weight | What it Tests |
|---|---|---|
| **Domain 1** — ML Fundamentals | 20% | ML & AI concepts and definitions |
| **Domain 2** — Fundamentals of Generative AI | 24% | GenAI concepts, LLMs, prompt engineering, FM types |
| **Domain 3** — Applications of Foundation Models | 28% | Bedrock, RAG, fine-tuning, agentic AI, Amazon Q |
| **Domain 4** — Guidelines for Responsible AI | 14% | Bias, fairness, explainability, safety, human review |
| **Domain 5** — Security, Compliance & Governance | 14% | IAM, encryption, Macie, GuardDuty, CloudTrail, shared responsibility |

---

<br/>

# Domain 1: ML Fundamentals Cheat Sheet

---

## Module 1: The AI/ML/Deep Learning Hierarchy

Understanding the relationship between these three terms is a foundational exam topic.

```md
    Artificial Intelligence (AI)
    ┌───────────────────────────────────────────────────┐
    │  Any technique that enables machines to mimic     │
    │  human intelligence (rules, search, reasoning).   │
    │                                                   │
    │   Machine Learning (ML)                           │
    │   ┌────────────────────────────────────────────┐  │
    │   │  Subset of AI. Systems learn from data     │  │
    │   │  (find patterns) without being explicitly  │  │
    │   │  programmed.                               │  │
    │   │                                            │  │
    │   │   Deep Learning (DL)                       │  │
    │   │   ┌──────────────────────────────────────┐ │  │
    │   │   │  Subset of ML using multi-layered    │ │  │
    │   │   │  Neural Networks to learn from       │ │  │
    │   │   │  very large datasets automatically.  │ │  │
    │   │   └──────────────────────────────────────┘ │  │
    │   └────────────────────────────────────────────┘  │
    └───────────────────────────────────────────────────┘
```

| Term                | Plain Definition                                                                 | Example                           |
| ------------------- | -------------------------------------------------------------------------------- | --------------------------------- |
| **AI**              | Broad field — any system exhibiting intelligent behavior                         | Chess rules engine, chatbots      |
| **ML**              | AI that learns patterns from data without explicit rules                         | Spam filter trained on emails     |
| **Deep Learning**   | ML using deep neural networks; excels at unstructured data                       | Image recognition, LLMs           |
| **Neural Network**  | Computing architecture modeled on the brain; layers of connected nodes (neurons) | Any DL model                      |
| **LLM**             | Very large transformer-based language model trained on massive text corpora      | GPT, Claude, Amazon Titan         |
| **NLP**             | AI field focused on understanding and generating human language                  | Comprehend, Lex, Translate        |
| **Computer Vision** | AI field focused on understanding images and video                               | Rekognition                       |
| **Algorithm**       | The mathematical procedure/method used to learn from data                        | Linear Regression, XGBoost        |
| **Model**           | The output artifact produced after an algorithm trains on data                   | A trained fraud-detection model   |
| **Training**        | The process of feeding data to an algorithm so it learns parameters (weights)    | Fitting a model to labeled data   |
| **Inferencing**     | Using a trained model to make predictions on new, unseen data                    | Running the model in production   |
| **Bias**            | Systematic error in a model's outputs, often from skewed training data           | Model underperforms for a group   |
| **Fairness**        | Ensuring model outputs are equitable across all groups                           | No discrimination by demographics |
| **Fit**             | How well a model captures patterns — can be under-fit or over-fit                | See Module 6                      |

---

### **NLP Evaluation Metrics**

**ROUGE** = RECALL - Did you COVER everything?
Used for _Summarization_. Think: ROUGE = Remembering.

**BLEU** = PRECISION - Is what you wrote CORRECT?
Used for _Translation_. Think: BLEU = Blue tick = Exact.

**BERTScore** = MEANING - Not exact words, but same SENSE?
Think: BERT = Brain / Semantics.

ROUGE has R -> Recall -> Summary.
BLEU has B -> Best precision -> Translation.
BERT has Brain -> Meaning.

<br/>

Evaluation metrics should be used to assess the model's performance:

- **Root Mean Square Error (RMSE)** squares the errors before averaging. This gives a high penalty to large misses. It helps when big forecasting errors cost the business a lot.
- **Mean Absolute Percentage Error (MAPE)** shows the error as a percentage of real revenue. This makes it easy to explain financial accuracy to non-technical teams.

<br/>

---

## Module 2: Data Types in AI/ML

> **Exam Tip:** The exam tests whether you can identify the right data type for a given scenario and the right ML technique to apply to it.

### **A. By Structure**

| Type                | Definition                                                | Examples                               |
| ------------------- | --------------------------------------------------------- | -------------------------------------- |
| **Structured**      | Organized into rows and columns with a defined schema     | SQL databases, CSV files, spreadsheets |
| **Unstructured**    | No predefined format or schema                            | Images, video, audio, raw text, PDFs   |
| **Semi-structured** | Has some organizational properties but not a rigid schema | JSON, XML, email logs                  |

### **B. By Label Status**

| Type               | Definition                                       | Used In                                |
| ------------------ | ------------------------------------------------ | -------------------------------------- |
| **Labeled Data**   | Each data point has a known target value (y)     | Supervised Learning                    |
| **Unlabeled Data** | Raw data with no target value; only features (X) | Unsupervised Learning, Self-supervised |

### **C. By Domain/Format**

| Data Format      | Description                         | Common ML Task                   | AWS Service                  |
| ---------------- | ----------------------------------- | -------------------------------- | ---------------------------- |
| **Tabular**      | Rows and columns (spreadsheet-like) | Classification, Regression       | SageMaker, Autopilot         |
| **Time-Series**  | Data points indexed chronologically | Forecasting, Anomaly detection   | Amazon Forecast              |
| **Image**        | Pixel grids                         | Object detection, Classification | Amazon Rekognition           |
| **Text**         | Natural language sequences          | Sentiment analysis, Translation  | Amazon Comprehend, Translate |
| **Audio/Speech** | Sound waveforms                     | Speech-to-text, Speaker ID       | Amazon Transcribe            |

---

<br/>

## Module 3: ML Learning Paradigms & Problem Types

```md
                            Machine Learning
                                   |
      ┌────────────────────────────┼────────────────────────────┐
      ▼                            ▼                            ▼
Supervised Learning      Unsupervised Learning        Reinforcement Learning
(Labeled Data: X → y)    (Unlabeled Data: X only)     (Trial, Error & Rewards)
  ├── Classification       ├── Clustering               └── Agent + Environment
  └── Regression           └── Dimensionality Red.
```

### **1. Supervised Learning: Classification vs. Regression**

#### **A. Classification**

- **What it is:** Mapping input features (X) to a discrete, categorical label (y).
- **Why/When to use:** When the target is a category, flag, or label (Binary: Yes/No; Multi-class: Red/Blue/Green; Multi-label: Tagging multiple topics).
- **Use Cases:** Email spam filtering, image recognition, fraud detection, customer churn prediction, sentiment analysis.
- **AWS Services:** Amazon Rekognition (objects/moderation), Amazon Comprehend (sentiment/topic classification), Amazon SageMaker.
- **Exam Trigger Words:** _"Categorize"_, _"Is this A or B"_, _"Identify sentiment"_, _"Classify"_, _"Binary"_, _"Labels"_.
- **Don't Confuse With:**
  - **Regression:** Regression outputs a continuous number; classification outputs a discrete class.
  - **Logistic Regression:** Despite having "Regression" in its name, it is a **classification** algorithm.

#### **B. Regression**

- **What it is:** Mapping input features (X) to a continuous numerical value (y).
- **Why/When to use:** When the target value can be any number on a continuous scale.
- **Use Cases:** House price prediction, sales revenue forecasting, temperature estimation, insurance claim amount prediction.
- **AWS Services:** Amazon Forecast, Amazon SageMaker (Linear Learner in regression mode, XGBoost).
- **Exam Trigger Words:** _"Predict numerical value"_, _"Forecast future amount"_, _"How much / How many"_, _"Continuous variable"_.
- **Don't Confuse With:**
  - **Time-Series Classification:** Predicting whether a stock goes _Up/Down_ is classification; predicting the _exact stock price_ ($152.45) is regression.

### **2. Unsupervised Learning: Clustering & Dimensionality Reduction**

#### **A. Clustering**

- **What it is:** Grouping unlabeled data points based on inherent mathematical similarities or distances (e.g., K-Means).
- **Why/When to use:** When you have raw data without target labels and want to discover natural groupings.
- **Use Cases:** Customer market segmentation, document grouping, genetic sequence grouping.
- **AWS Services:** Amazon SageMaker (K-Means algorithm).
- **Exam Trigger Words:** _"Unlabeled"_, _"Find natural groups"_, _"Segment customers without prior labels"_, _"Clusters"_.

#### **B. Dimensionality Reduction**

- **What it is:** Reducing the number of input features while retaining as much meaningful variance/information as possible (e.g., PCA — Principal Component Analysis).
- **Why/When to use:** When dealing with the "curse of dimensionality" (hundreds/thousands of columns), high compute costs, multicollinearity, or data visualization.
- **Use Cases:** Compressing image data, reducing feature set before training, removing correlated redundant noise.
- **AWS Services:** Amazon SageMaker (PCA algorithm).
- **Exam Trigger Words:** _"Reduce feature count"_, _"High-dimensional data"_, _"Compress inputs without losing variance"_, _"PCA"_.
- **Don't Confuse With:**
  - **Feature Selection:** Selecting a subset of existing columns. Dimensionality reduction creates _new, combined_ lower-dimensional components.

### **3. Reinforcement Learning (RL)**

- **What it is:** An **Agent** interacts with a dynamic **Environment**, observes the **State**, takes **Actions**, and receives **Rewards** or penalties to learn an optimal policy.
- **Why/When to use:** For sequential decision-making problems where immediate feedback isn't available, but an overall goal must be optimized.
- **Use Cases:** Autonomous driving, game playing (Chess, Go), robotic arm manipulation, dynamic pricing strategies.
- **AWS Services:** **AWS DeepRacer** (1/18th scale autonomous car learning RL), **AWS DeepComposer**.
- **Exam Trigger Words:** _"Reward function"_, _"Agent and environment"_, _"Policy optimization"_, _"Sequential decisions"_, _"Trial and error"_, _"DeepRacer"_.

---

**Linear regression** refers to supervised learning models that use one or more inputs to _predict a value on a continuous scale_. It is used to predict housing prices. After training a model using a set of historical sales training data that includes those characteristics, you could _forecast_ the price of a property based on its location, age, and number of rooms.

**Logistic regression** is supervised learning algorithm, typically used for binary classification, and is not applicable for the unsupervised tasks.

**Probability density** is generally used to estimate the likelihood or possibility of a random variable falling within a particular range of values, not for predicting future values based on historical data.

**Dimensionality reduction** is primarily used to reduce the number of features in a dataset while retaining as much information as possible. It is not used for prediction tasks directly.

**Anomaly detection** is only used to identify outliers or unusual patterns in data, which is not the primary goal of predicting continuous portfolio values.

**Semantic segmentation** tags every pixel in an image with a class label from a predefined set of classes.

<br/>

---

## Module 4: Practical AI/ML Use Cases

### **When AI/ML IS Appropriate**

| Scenario                          | Why AI/ML Fits                                                           |
| --------------------------------- | ------------------------------------------------------------------------ |
| Human decision support            | Augments experts (e.g., medical imaging AI flags anomalies for a doctor) |
| Scalability                       | A single trained model can serve millions of predictions simultaneously  |
| Automation of repetitive tasks    | Document classification, invoice processing, spam filtering              |
| Pattern recognition in large data | Fraud detection across billions of transactions                          |
| Personalization                   | Recommendation engines (content, products)                               |
| Prediction / Forecasting          | Demand forecasting, predictive maintenance                               |

<br/>

### **When AI/ML is NOT Appropriate**

> **Exam Tip:** This is a commonly tested nuance. Not every problem needs AI.

| Situation                                 | Why AI/ML is NOT the Right Tool                                                          |
| ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| **A perfectly deterministic rule exists** | If `age > 65 → senior discount`, a simple rule is more reliable and cheaper than a model |
| **Cost outweighs benefit**                | Training and running models is expensive; small-scale problems may not justify the cost  |
| **A specific, exact outcome is required** | ML models produce _probabilities/predictions_, not guaranteed exact answers              |
| **Insufficient data**                     | ML needs sufficient data to learn; sparse data leads to unreliable models                |
| **High explainability required**          | Some regulated domains (legal, medical) may require fully auditable deterministic logic  |

<br/>

### **Real-World AI Application Categories**

| Application                      | Description                                      | AWS Service           |
| -------------------------------- | ------------------------------------------------ | --------------------- |
| **Computer Vision**              | Analyzing images/video for objects, faces, text  | Amazon Rekognition    |
| **NLP / Text Analytics**         | Sentiment, entity extraction, language detection | Amazon Comprehend     |
| **Speech Recognition**           | Convert audio to text (speech-to-text)           | Amazon Transcribe     |
| **Text-to-Speech**               | Convert text to natural-sounding audio           | Amazon Polly          |
| **Machine Translation**          | Translate between languages                      | Amazon Translate      |
| **Conversational AI / Chatbots** | Build voice and text chatbots                    | Amazon Lex            |
| **Recommendation Systems**       | Personalized product/content recommendations     | Amazon Personalize    |
| **Fraud Detection**              | Identify anomalous transactions in real time     | Amazon Fraud Detector |
| **Forecasting**                  | Predict future values from time-series data      | Amazon Forecast       |
| **Document Processing**          | Extract text and structured data from documents  | Amazon Textract       |

<br/>

---

## Module 5: The ML Development Lifecycle

```md
[Problem Definition] ➔ [Data Collection] ➔ [EDA] ➔ [Data Preprocessing] ➔ [Feature Engineering] ➔ [Model Training] ➔ [Hyperparameter Tuning] ➔ [Evaluation] ➔ [Deployment] ➔ [Monitoring & Retraining]
```

### **Stage-by-Stage Breakdown**

| Stage                               | What Happens                                                                                        | Key AWS Service                                |
| ----------------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Problem Definition**              | Define the business objective and success metrics                                                   | —                                              |
| **Data Collection & Ingestion**     | Gather raw data from sources (databases, APIs, S3)                                                  | Amazon S3, AWS Glue                            |
| **Exploratory Data Analysis (EDA)** | Understand distributions, correlations, outliers, missing values; visualize data to form hypotheses | SageMaker Studio, Data Wrangler                |
| **Data Preprocessing**              | Handle missing values, remove duplicates, fix errors, encode categoricals, scale features           | SageMaker Data Wrangler                        |
| **Data Labeling**                   | Assign ground truth labels (y) to raw data for supervised learning                                  | **Amazon SageMaker Ground Truth**              |
| **Feature Engineering**             | Create, transform, or select input variables (X) to improve model learning                          | **SageMaker Data Wrangler**, **Feature Store** |
| **Model Training**                  | Feed prepared data to an algorithm so it learns parameters (weights/biases)                         | Amazon SageMaker Training                      |
| **Hyperparameter Tuning**           | Optimize training configurations (learning rate, epochs, batch size) — set _before_ training        | SageMaker Automatic Model Tuning               |
| **Evaluation**                      | Measure model performance on the held-out test set using metrics                                    | SageMaker Experiments, Clarify                 |
| **Deployment**                      | Serve the model for inference in production                                                         | SageMaker Endpoints, Bedrock                   |
| **Monitoring & Retraining**         | Track for drift and model degradation; retrain when performance drops                               | **SageMaker Model Monitor**                    |

<br/>

### **1. Data Labeling vs. Feature Engineering**

| **Concept**             | **What It Is**                                                     | **Purpose**                                                       | **Key AWS Service**                                                          |
| ----------------------- | ------------------------------------------------------------------ | ----------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| **Data Labeling**       | Assigning ground truth target labels (y) to raw unlabeled data.    | Creates the training dataset required for Supervised Learning.    | **Amazon SageMaker Ground Truth** (uses active learning + human workforces). |
| **Feature Engineering** | Transforming, creating, scaling, or selecting input variables (X). | Makes mathematical patterns easier for the ML algorithm to learn. | **Amazon SageMaker Data Wrangler**, **Amazon SageMaker Feature Store**.      |

### **2. Core Data Preprocessing & Feature Engineering Techniques**

#### **A. Encoding Categorical Variables**

- **One-Hot Encoding:** Converts categorical strings (`Red`, `Green`, `Blue`) into binary columns ([1,0,0], [0,1,0], [0,0,1]). Used when there is **no inherent order**.
- **Label / Ordinal Encoding:** Converts ordered categories into numbers (`Small` = 1, `Medium` = 2, `Large` = 3).

#### **B. Feature Scaling**

- **Normalization (Min-Max Scaling):** Rescales values to a range of [0, 1].
- **Standardization (Z-score):** Centers data around a mean of 0 with standard deviation of 1.
- **Why it matters:** Prevents features with large raw numbers (e.g., Annual Salary: $120,000) from mathematically overpowering features with small numbers (e.g., Age: 30).

#### **C. Data Splitting & Leakage**

- **Train / Validation / Test Split:**
  - **Training Set (~70–80%):** Model learns the weights/patterns.
  - **Validation Set (~10–15%):** Used during training for hyperparameter tuning and model selection.
  - **Test Set (~10–15%):** Unseen data used for the final, unbiased performance evaluation.
- **Target / Data Leakage:** When information from outside the training dataset (or from the future target label) inadvertently leaks into the training data, producing unrealistically high training accuracy that fails in production.

### **3. Model Sources**

| Source                             | Description                                                                                     | Example                                                      |
| ---------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Open-source pre-trained models** | Publicly available models already trained on large datasets; can be used directly or fine-tuned | Hugging Face models, open-source LLMs via Amazon Bedrock     |
| **Custom-trained models**          | Models trained from scratch on your own proprietary data for a specific task                    | Training a fraud model on your transaction data in SageMaker |

### **4. Deployment Methods**

| Method                   | Description                                                         | When to Use                                               |
| ------------------------ | ------------------------------------------------------------------- | --------------------------------------------------------- |
| **Managed API Service**  | AWS hosts and manages the model endpoint (scaling, patching, infra) | Most use cases; low operational overhead                  |
| **Self-hosted API**      | You deploy the model on your own EC2/container infrastructure       | Full control, custom hardware, or compliance requirements |
| **Serverless Inference** | Model runs only when invoked; no idle cost                          | Infrequent or unpredictable traffic                       |
| **Batch Inference**      | Runs predictions on a large dataset all at once on a schedule       | Non-real-time, bulk processing needs                      |

### **5. Inferencing Types**

| Type                       | Description                                                            | Use Case                                |
| -------------------------- | ---------------------------------------------------------------------- | --------------------------------------- |
| **Real-Time Inference**    | Low-latency, synchronous prediction for individual requests            | Fraud check at point of sale            |
| **Batch Inference**        | Asynchronous bulk predictions on large datasets                        | Overnight report scoring                |
| **Asynchronous Inference** | Requests are queued; response returned when ready (for large payloads) | Long-running predictions on large files |
| **Serverless Inference**   | Auto-scales to zero; cost based purely on invocations                  | Intermittent or spiky traffic           |

<br/>

---

## Module 6: Model Evaluation & Performance Tuning

### **1. Classification Metrics & The Confusion Matrix**

```md
                      Predicted Positive       Predicted Negative
Actual Positive       True Positive (TP)       False Negative (FN)  <- Type II Error
Actual Negative       False Positive (FP)      True Negative (TN)
                      (Type I Error)
```

#### **Metrics Formula & Purpose Cheat Sheet**

- **Accuracy:** (TP + TN) / (TP + TN + FP + FN)
  - _When to use:_ Only when classes are **balanced**. Misleading for imbalanced datasets (e.g., 99% legitimate, 1% fraud).

- **Precision:** TP / (TP + FP) — _Out of all we predicted positive, how many were right?_
  - _When to prioritize:_ When the cost of a **False Positive (FP)** is high (e.g., Spam filter — don't send crucial client emails to spam).

- **Recall (Sensitivity):** TP / (TP + FN) — _Out of all actual positives, how many did we catch?_
  - _When to prioritize:_ When the cost of a **False Negative (FN)** is high (e.g., Cancer detection, fraud detection — never miss a sick patient or fraudster).

- **F1-Score:** Harmonic mean of Precision and Recall: 2 × (Precision × Recall) / (Precision + Recall)
  - _When to prioritize:_ Imbalanced datasets where you need a balance between Precision and Recall.

- **ROC-AUC (Receiver Operating Characteristic - Area Under Curve):** Measures classifier performance across all classification thresholds. (AUC of 1.0 is perfect; 0.5 is random guessing).

### **2. Regression Metrics**

- **MAE (Mean Absolute Error):** Average of absolute differences. Easy to interpret in original units; treats all errors linearly.
- **MSE (Mean Squared Error):** Averages squared differences. Heavily penalizes large outlier errors.
- **RMSE (Root Mean Squared Error):** Square root of MSE. Penalizes large errors, but brought back into original target units.
- **R-Squared (Coefficient of Determination):** Explains the proportion of variance captured by the model (1.0 = perfect fit, 0 = performs no better than the mean).

### **3. Business Metrics (vs. Model Metrics)**

> **Exam Tip:** The exam distinguishes between technical model metrics and business impact metrics.

| Metric Type          | Examples                                                                           | Purpose                            |
| -------------------- | ---------------------------------------------------------------------------------- | ---------------------------------- |
| **Model Metrics**    | Accuracy, F1, AUC, RMSE                                                            | Measure technical ML performance   |
| **Business Metrics** | Cost per user, Development cost, Customer satisfaction (CSAT), Revenue uplift, ROI | Measure real-world business impact |

A model with high accuracy may still fail if the **cost to build/run it exceeds the business value it generates** (negative ROI). Always evaluate both.

### **4. The Bias-Variance Tradeoff (Overfitting vs. Underfitting)**

```md
        High Bias (Underfitting)             Balanced (Good Fit)             High Variance (Overfitting)
        ─────────────────────────             ───────────────────             ───────────────────────────
        • Model is too simple                • Generalizes well              • Model memorized training data
        • High Train & Test Error            • Low Train & Test Error        • Very Low Train Error, High Test Error
```

| **Problem**                       | **Symptoms**                                           | **Root Cause**                                  | **How to Fix It**                                                                                                             |
| --------------------------------- | ------------------------------------------------------ | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Overfitting** _(High Variance)_ | High training accuracy, poor validation/test accuracy. | Model is too complex; memorized training noise. | 1. Add more training data 2. Regularization (L1/L2, Dropout) 3. Feature reduction / Pruning 4. Early stopping during training |
| **Underfitting** _(High Bias)_    | Poor accuracy on both training and test data.          | Model is too simple; cannot capture patterns.   | 1. Use a more complex model/architecture 2. Add more relevant features 3. Train for more epochs / reduce regularization       |

<br/>

---

## Module 7: Neural Networks & Deep Learning Architectures

Foundational deep learning models often serve as the building blocks for Generative AI and Foundation Models.

```md
                                  Neural Networks
                                         |
        ┌────────────────────────────────┼────────────────────────────────┐
        ▼                                ▼                                ▼
  CNN (Convolutional)            RNN / LSTM (Recurrent)          Transformer (Attention)
  • Grid/Spatial Data            • Sequential/Time Data          • Parallelized Sequences
  • Images, Video, OCR           • Speech, Historical Series     • LLMs, Modern GenAI
```

- **CNN (Convolutional Neural Network):** Uses convolutional filter matrices to process grid/spatial data.
  - _Exam Association:_ Computer Vision, Image Classification, Object Detection (**Amazon Rekognition**).

- **RNN / LSTM (Recurrent Neural Network / Long Short-Term Memory):** Processes sequential data by passing hidden states step-by-step.
  - _Exam Association:_ Legacy NLP, speech-to-text, time-series forecasting.

- **Transformers (Self-Attention Mechanism):** Processes entire sequences in parallel using attention weights to capture context.
  - _Exam Association:_ Modern Foundation Models (FMs), Large Language Models (LLMs), **Amazon Bedrock**, Amazon Titan, Claude, GPT.

<br/>

---

## Module 8: MLOps — Operationalizing ML

> **MLOps** applies DevOps principles to the ML lifecycle to make model development repeatable, scalable, and production-ready.

| MLOps Concept               | Description                                                                             |
| --------------------------- | --------------------------------------------------------------------------------------- |
| **Experimentation**         | Tracking model versions, hyperparameters, and metrics across runs to compare results    |
| **Repeatable Processes**    | Automated, version-controlled pipelines that produce consistent results                 |
| **Scalable Systems**        | Infrastructure that scales training and inference with demand                           |
| **Managing Technical Debt** | Avoiding shortcuts (e.g., hard-coded thresholds) that cause future maintenance problems |
| **Production Readiness**    | Ensuring models pass validation gates before serving real traffic                       |
| **Model Monitoring**        | Continuously tracking a deployed model's performance for degradation                    |
| **Model Retraining**        | Triggering a new training run when performance drops below a threshold                  |

### **Data Drift vs. Concept Drift**

| Drift Type        | Definition                                                             | Example                                                     |
| ----------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Data Drift**    | The distribution of input features (X) changes over time               | Customer age range shifts after targeting a new demographic |
| **Concept Drift** | The relationship between features (X) and target (y) changes over time | Fraud patterns change after fraudsters adapt to detection   |

> **Detection:** **Amazon SageMaker Model Monitor** detects both data drift and model quality degradation automatically.

<br/>

---

## Module 9: AWS AI/ML Ecosystem Mapping

Match each ML concept directly to its managed AWS service:

| **ML Lifecycle Stage / Need**        | **AWS Service**                    | **Key Role**                                                                                                   |
| ------------------------------------ | ---------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| **Data Labeling**                    | **Amazon SageMaker Ground Truth**  | Managed human workforce + active learning automated labeling.                                                  |
| **Data Prep & Feature Engineering**  | **Amazon SageMaker Data Wrangler** | Visual interface to clean, normalize, and engineer features with 300+ built-in transforms.                     |
| **Feature Storage & Reuse**          | **Amazon SageMaker Feature Store** | Central repository to store, share, and serve features for training and real-time inference.                   |
| **Automated ML (No-Code/Low-Code)**  | **Amazon SageMaker Autopilot**     | Automatically cleans data, selects algorithms, trains, tunes hyperparameters, and outputs full code notebooks. |
| **No-Code ML for Business Analysts** | **Amazon SageMaker Canvas**        | Drag-and-drop visual ML for non-technical business users; no code required.                                    |
| **Bias Detection & Explainability**  | **Amazon SageMaker Clarify**       | Detects pre/post-training bias and provides feature attribution (SHAP values) for explainability.              |
| **Model Monitoring & Drift**         | **Amazon SageMaker Model Monitor** | Monitors deployed endpoints for data drift, concept drift, and model quality degradation.                      |
| **Computer Vision**                  | **Amazon Rekognition**             | Image and video analysis — object detection, face recognition, content moderation.                             |
| **NLP / Text Analytics**             | **Amazon Comprehend**              | Sentiment analysis, entity recognition, language detection, topic modeling.                                    |
| **Speech-to-Text**                   | **Amazon Transcribe**              | Converts audio to text with speaker identification and medical vocabulary support.                             |
| **Text-to-Speech**                   | **Amazon Polly**                   | Converts text to lifelike speech in multiple languages.                                                        |
| **Machine Translation**              | **Amazon Translate**               | Neural machine translation between 75+ languages.                                                              |
| **Conversational AI**                | **Amazon Lex**                     | Build voice and text chatbots (same engine as Alexa).                                                          |
| **Recommendations**                  | **Amazon Personalize**             | Real-time personalized recommendations using your own data.                                                    |
| **Fraud Detection**                  | **Amazon Fraud Detector**          | Managed service for detecting online fraud using ML.                                                           |
| **Forecasting**                      | **Amazon Forecast**                | Time-series forecasting using ML (no ML expertise required).                                                   |
| **Document Analysis**                | **Amazon Textract**                | Extracts text, forms, and tables from scanned documents.                                                       |
| **Reinforcement Learning Education** | **AWS DeepRacer**                  | Cloud-based 3D racing simulator and 1/18th scale physical race car for practicing RL.                          |

<br/>

---

## Module 10: High-Yield Exam "Versus" Trap Matrix

Review this table right before sitting exam questions:

| **Concept A**           | **vs.** | **Concept B**            | **How to Distinguish on the Exam**                                                                                                                 |
| ----------------------- | ------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AI**                  | vs.     | **ML**                   | AI is the broad field of intelligent systems; ML is a subset that learns from data.                                                                |
| **ML**                  | vs.     | **Deep Learning**        | Deep Learning is a subset of ML using multi-layer neural networks; requires much more data and compute.                                            |
| **Supervised**          | vs.     | **Unsupervised**         | Supervised **requires labels/ground truth (y)**; Unsupervised works on raw, unlabelled data (X).                                                   |
| **Classification**      | vs.     | **Regression**           | Classification outputs a **category/class**; Regression outputs a **continuous number**.                                                           |
| **Precision**           | vs.     | **Recall**               | Prioritize Precision to avoid **False Alarms (FP)**; prioritize Recall to avoid **Missing Positives (FN)**.                                        |
| **Hyperparameters**     | vs.     | **Model Parameters**     | **Hyperparameters** are set _before_ training (learning rate, batch size, epochs); **Parameters** are learned _during_ training (weights, biases). |
| **Data Drift**          | vs.     | **Concept Drift**        | **Data Drift:** Input feature distribution (X) changes. **Concept Drift:** The X→y relationship changes.                                           |
| **Model Metrics**       | vs.     | **Business Metrics**     | Model metrics (F1, AUC) measure ML performance; Business metrics (ROI, cost/user) measure real-world value.                                        |
| **SageMaker Autopilot** | vs.     | **SageMaker Canvas**     | **Autopilot:** AutoML with full code access (data scientist-focused). **Canvas:** No-code visual drag-and-drop (business analyst-focused).         |
| **Real-Time Inference** | vs.     | **Batch Inference**      | Real-time: single requests, low latency. Batch: large bulk datasets, scheduled, non-urgent.                                                        |
| **Pre-trained Model**   | vs.     | **Custom-trained Model** | Pre-trained: reuse existing model (fast, less data needed). Custom: trained from scratch on proprietary data (more control, more effort).          |
| **Labeled Data**        | vs.     | **Unlabeled Data**       | Labeled: has target y, required for Supervised Learning. Unlabeled: no target, used in Unsupervised Learning.                                      |

---

### **Capabilities of Generative AI**

| Capability                     | Short explanation                                                                                                                   |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Adaptability**               | Can adapt responses to different tasks, contexts, instructions, and domains without being specifically programmed for each one.     |
| **Responsiveness**             | Can quickly generate relevant responses to user inputs, often enabling interactive, conversational experiences.                     |
| **Simplicity**                 | Makes complex tasks easier by allowing users to interact with AI using natural language rather than specialized interfaces or code. |
| **Creativity and exploration** | Can generate new text, images, code, ideas, designs, and alternatives, supporting brainstorming and experimentation.                |
| **Data efficiency**            | Can perform useful tasks with relatively little task-specific training data, especially through prompting or few-shot learning.     |
| **Personalization**            | Can tailor outputs to individual users based on their context, preferences, history, or provided information.                       |
| **Scalability**                | Can serve many users and handle large volumes of content/tasks through cloud-based infrastructure and automated inference.          |

<br/>

### **Challenges of Generative AI**

- Intellectual Property
- Hallucinations
- Toxicity
- Plagiarism and Cheating
- Disruption of Nature of Work

| Challenge                              | Short explanation                                                                                                                                   |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Regulatory violations**              | AI outputs or use of data may violate laws, regulations, intellectual-property requirements, or industry rules.                                     |
| **Social risks**                       | AI can contribute to bias, discrimination, misinformation, job impacts, or loss of trust if used irresponsibly.                                     |
| **Data security and privacy concerns** | Sensitive or proprietary information can be exposed, misused, or improperly processed if data and access are not adequately protected.              |
| **Toxicity**                           | Models may generate harmful, offensive, abusive, or inappropriate content.                                                                          |
| **Hallucinations**                     | The model may confidently generate information that is false, fabricated, or unsupported by facts. ([AWS Documentation][1])                         |
| **Interpretability**                   | It can be difficult to understand why a model produced a particular output or decision, making transparency challenging. ([AWS Documentation][2])   |
| **Nondeterminism**                     | The same or similar input can produce different outputs because generative AI is probabilistic rather than guaranteed to produce identical results. |

[1]: https://docs.aws.amazon.com/prescriptive-guidance/latest/strategy-data-considerations-gen-ai/security.html "Security considerations for data in generative AI - AWS Prescriptive Guidance"
[2]: https://docs.aws.amazon.com/aws-certification/latest/ai-practitioner-01/ai-practitioner-01-domain4.html "Content Domain 4: Guidelines for Responsible AI - AWS Certified AI Practitioner"

<br/>

---

### **Responsible AI**

AWS Docs/Blogs worth reading on Responsible AI and AI Safety:

[Responsible AI - AWS Docs](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/responsible-ai.html)

[Responsible AI - AWS Detailed Blog - Considerations for addressing the core dimensions of responsible AI for Amazon Bedrock applications](https://aws.amazon.com/blogs/machine-learning/considerations-for-addressing-the-core-dimensions-of-responsible-ai-for-amazon-bedrock-applications/)

- **Fairness**: Considering impacts on different groups of stakeholders.

- **Explainability**: Understanding and evaluating system outputs.

- **Privacy and Security**: Appropriately obtaining, using, and protecting data and models.

- **Safety**: Reducing harmful system output and misuse.

- **Controllability**: Having mechanisms to monitor and steer AI system behavior.

- **Veracity and Robustness**: Achieving correct system outputs, even with unexpected or adversarial inputs.

- **Governance**: Incorporating best practices into the AI supply chain, including providers and deployers.

- **Transparency**: Enabling stakeholders to make informed choices about their engagement with an AI system.

<br/>

#### **Fairness**

When your AI system interacts with customers, those interactions reflect your brand values. Consider a mortgage application system: it must evaluate applications based on relevant financial criteria while verifying that decisions aren't influenced by unwanted discriminatory factors. This means implementing robust testing frameworks to detect potential bias, regularly auditing outcomes across different customer segments, and maintaining clear documentation of decision criteria. Leading organizations are integrating these considerations into their development processes, which means that their AI systems enhance rather than compromise their commitment to equitable service.

#### **Explainability**

The ability to understand and communicate how AI makes decisions is both a good practice and is essential for business operations. A wealth management AI advisor must be able to articulate the reasoning behind its investment recommendations. This requires implementing interpretability techniques and developing frameworks to translate complex model decisions into understandable explanations for both customers and regulators. Organizations that excel here find they build deeper customer trust and navigate regulatory requirements more effectively.

#### **Privacy and Security**

Customers want to trust generative AI applications with their most sensitive information. This trust is earned by strong application security and data privacy controls. When implementing AI systems, this trust must be preserved through robust data protection and infrastructure security mechanisms. Leading organizations are implementing sophisticated data governance frameworks that include encryption, access controls, and data minimization practices. They also develop clear policies about data usage, verify that AI systems access only the information necessary for their specific functions, and seek to maintain regulatory compliance.

#### **Safety**

AI systems must operate within a clearly defined use case scope that aligns with your organization's risk tolerance and values. Consider a trading recommendation system: it needs guardrails to remove suggestions that could violate regulatory requirements or exceed risk thresholds. Forward-thinking organizations are implementing comprehensive safety frameworks that include content filtering, output validation, and clear escalation paths for edge cases.

#### **Controllability**

The ability to monitor and adjust AI system behavior aligns with business objectives and risk parameters. Leading organizations implement robust monitoring systems that track performance metrics, user feedback, and system outputs. They maintain clear procedures for adjusting or disabling AI systems when necessary, keeping human oversight effective even as systems scale.

#### **Veracity and Robustness**

AI systems must deliver reliable, veratious results consistently, even when facing unexpected situations. Organizations at the forefront of AI adoption are implementing comprehensive testing frameworks that challenge their systems with diverse inputs, monitoring accuracy across different scenarios, and maintaining clear protocols for handling edge cases. They're building systems that not only perform well in ideal conditions but remain reliable under stress. At the forefront of this field are concepts like automated reasoning, which use mathematically provable statements to capture and correct hallucinations in real-time.

#### **Governance**

Clear governance frameworks align AI systems with organizational policies and regulatory requirements. Leading organizations are establishing AI governance committees that include technical, business, and risk management perspectives. They're developing comprehensive documentation practices, clear escalation paths, and regular review processes so that AI systems continue to serve business objectives while managing risk effectively.

#### **Transparency**

Building trust requires openness about AI system capabilities and limitations. Successful organizations clearly communicate when and how AI is being used, what data informs decisions, and what controls are in place. This commitment to transparency enhances user trust in the AI system, encouraging adoption.

---
