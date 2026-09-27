# CyberGuard AI: Phishing URL Detector

A machine-learning web app that estimates how likely a URL is to be a phishing site. It pulls structural features from the URL, fetches the page to analyse its content (optional), and scores the result with a Random Forest classifier trained on the *Web Page Phishing Detection* dataset.

---

## Features

- **URL scan**: paste a link and get a verdict (phishing or legitimate) with a probability score.
- **87 engineered features**: URL structure, page content (links, forms, iframes, favicon, title, and so on) and DNS lookup.
- **Optional page fetch**: turn it off to classify from the URL alone.
- **Advanced signals**: you can enter WHOIS, PageRank, traffic rank and Google-index values by hand. These need third-party services, so if you leave them blank the app uses the dataset medians.
- **Explainability**: the UI shows every extracted feature value and the model's most important features.
- **SSRF guard**: page fetches to private, loopback and link-local addresses are blocked.
- **REST API**: built with FastAPI, with interactive docs at `/docs`.

---

## Project Structure

```
Phishing-Detector/
├── Backend/
│   ├── main.py          # FastAPI app: API routes + serves the frontend
│   └── features.py      # Feature extraction (URL, page content, DNS)
├── Frontend/
│   ├── index.html       # Single-page UI
│   ├── app.js           # API calls and result rendering
│   └── style.css
├── Dataset/
│   └── dataset_phishing.csv   # 11,430 labelled URLs (balanced 50/50)
├── Notebook/
│   ├── Notebook.ipynb   # EDA, training, evaluation
│   └── phishing_model.pkl     # Trained Random Forest model
├── requirements.txt
└── Readme.md
```

---

## Model

| Item | Value |
|---|---|
| Algorithm | `RandomForestClassifier` (scikit-learn) |
| Trees / max depth | 100 / 15 |
| Dataset | 11,430 URLs: 5,715 phishing, 5,715 legitimate |
| Split | 80% train / 20% test, stratified, `random_state=42` |
| Features | 87 (all dataset columns except `url` and `status`) |

To reproduce the training and see the evaluation metrics (accuracy, classification report, confusion matrix, ROC-AUC, feature importance), run [Notebook/Notebook.ipynb](Notebook/Notebook.ipynb).

---

## Getting Started

### Prerequisites

- Python 3.10+
- VS Code (recommended) with the Python and Jupyter extensions

### 1. Clone and set up the environment

```bash
git clone <repo-url>
cd Phishing-Detector
python -m venv .venv
```

Activate it:

```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 2. (Optional) Retrain the model

Open `Notebook/Notebook.ipynb` in VS Code, select the `.venv` kernel and run all cells. This regenerates `Notebook/phishing_model.pkl`.

### 3. Run the app

From the project root:

```bash
uvicorn Backend.main:app --reload
```

Then open:

- App: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/model-info` | Model type, parameters, top 10 features |
| `POST` | `/api/predict` | Extract features from a URL and predict |
| `POST` | `/api/predict/features` | Predict from a raw feature dictionary |

### `POST /api/predict`

Request:

```json
{
  "url": "http://example.com/login",
  "fetch_page": true,
  "overrides": {
    "google_index": 0,
    "page_rank": 5,
    "web_traffic": 1200,
    "domain_age": 4000,
    "domain_registration_length": 365,
    "whois_registered_domain": 0
  }
}
```

`overrides` and all of its fields are optional.

Response (abridged):

```json
{
  "label": "legitimate",
  "phishing_probability": 0.12,
  "url": "http://example.com/login",
  "features": { "length_url": 24, "nb_dots": 1, "...": "..." },
  "defaulted_features": ["statistical_report", "random_domain"],
  "page_fetched": true,
  "fetch_error": null
}
```

A URL is labelled `phishing` when `phishing_probability >= 0.5`.

### `POST /api/predict/features`

```json
{ "features": { "length_url": 54, "nb_dots": 3, "ip": 0 } }
```

Features you leave out are filled with `0`. An unknown feature name returns HTTP 400.

---

## How Feature Extraction Works

| Group | Source | Examples |
|---|---|---|
| URL-based | Parsed from the URL string | `length_url`, `nb_dots`, `ip`, `prefix_suffix`, `phish_hints`, `suspecious_tld` |
| Page content | Live HTTP fetch + BeautifulSoup | `nb_hyperlinks`, `login_form`, `iframe`, `external_favicon`, `empty_title` |
| DNS | `socket.getaddrinfo` | `dns_record` |
| External | Needs WHOIS / ranking services | `domain_age`, `web_traffic`, `page_rank`, `google_index` |

External features default to the dataset medians unless you supply them in `overrides`. If the page fetch fails or is turned off, the content features use "empty page" values, so the prediction is based on the URL alone.

---

## How the Phishing % Works

The percentage shown in the gauge is the model's **phishing probability** (`phishing_probability` in the API).

1. The backend builds a feature vector of 87 values for the URL.
2. Each of the 100 decision trees in the Random Forest gives its own estimate of whether the URL is phishing.
3. The model averages those estimates. The result is a value from 0 to 1, shown as 0–100%.

| Probability | Gauge | Verdict |
|---|---|---|
| 0–29% | Green | Legitimate |
| 30–49% | Amber (warning) | Legitimate, but borderline |
| 50–100% | Red | Phishing |

The cut-off is **50%**. A higher percentage means more of the forest agrees the URL looks like phishing. It is a confidence score, not a guarantee.

---

## Advanced Signals

Some of the model's features come from **third-party services** such as WHOIS, search engines and traffic-ranking sites. The app can't look these up itself, so by default it fills them with the **dataset median**. The result table marks these values as `(default)`.

Click **Advanced signals** in the UI (or send `overrides` in the API) to enter the real values. Your result will be more accurate.

| UI field | Feature | Meaning | Values |
|---|---|---|---|
| Indexed by Google | `google_index` | Whether Google has indexed the site | Yes = `0`, No = `1` |
| PageRank | `page_rank` | Link-authority score | `0`–`10` (higher = more trusted) |
| Web traffic rank | `web_traffic` | Alexa-style popularity rank | Lower = more popular; `0` = unranked/unknown |
| Domain age | `domain_age` | Days since the domain was registered | Days; `-1` = unknown |
| Registration length | `domain_registration_length` | Days until the domain registration expires | Days; `-1` = unknown |
| WHOIS registered | `whois_registered_domain` | Whether the domain appears in WHOIS | `0` = registered, `1` = not found |

Leave a field blank to keep its median default. Phishing sites are typically **not indexed**, have **low PageRank**, **no traffic rank**, and a **short registration length**. Legitimate sites are usually the opposite.

`statistical_report` and `random_domain` always use their defaults. You can't set them from the UI.

---

## Test URLs

Use these URLs to try out the application. Paste the URL, open **Advanced signals**, and enter the values shown.

### Legitimate

| URL | Google indexed | PageRank | Traffic | Domain age |
|---|---|---|---|---|
| `https://www.wikipedia.org` | Yes | 7 | 13 | 9000 |
| `https://www.python.org` | Yes | 7 | 900 | 11000 |

> The legitimate values are rough estimates, not exact figures.

### Phishing

> ⚠️ **Warning:** These are real phishing URLs taken from the dataset. Do **not** open them in a browser or enter any credentials. Only scan them through the app. For extra safety, you can turn off **Fetch page content**.

| URL | Google indexed | PageRank | Traffic | Domain age |
|---|---|---|---|---|
| `http://www.cndoubleegret.com/admin/secure/cmd-login=688fe4912f76e3cb3ce51b2363d97b20/` | No | 1 | 0 | 4284 |
| `http://aksoydanismanlik.com/microsoft/microsoft` | No | 0 | 0 | 4322 |
| `https://fene-modi.firebaseapp.com/` | No | 2 | 0 | 2837 |

> The phishing values come straight from the dataset.

---

## Limitations

- External signals are not looked up automatically, and the median defaults can bias results.
- The model reflects patterns in the training dataset and may not generalise to new phishing techniques.
- Predictions are probabilistic. Don't use them as the only basis for a security decision.

---

## Tech Stack

**ML:** pandas, NumPy, scikit-learn, joblib, matplotlib, seaborn
**Backend:** FastAPI, Uvicorn, Pydantic, requests, BeautifulSoup4, tldextract
**Frontend:** HTML, CSS, vanilla JavaScript
