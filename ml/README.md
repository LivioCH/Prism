# ML model for Prism (URL phishing check)

The app scans a link in two layers. **Google Web Risk decides** whenever it answers. This model is the **second layer**:
it catches phishing pages that Google has not listed yet, and it keeps working offline or when the Free plan's Google
checks are used up.

## You do NOT need anything here to run the app

The trained model is already in `Prism-main/app/src/main/assets/url_model.json` (about 8 KB: 15 weights, the scaling
numbers and a table of how often each domain ending was phishing). It does not contain the dataset, and the app never
reads the dataset. Clone, build and run.

You only need the steps below to **retrain** the model.

## Retrain

1. Download the **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository, CC BY 4.0, 235,795 URLs, label
   `0` = phishing, `1` = legitimate) and save it as `PhiUSIIL_Phishing_URL_Dataset.csv` in the repository root.
   The file is 57 MB and is git-ignored on purpose, so it is never committed.
2. Run (Node 18 or newer, no packages to install):

   ```
   node ml/train_url_model.js
   node ml/train_url_model.js --data C:\path\to\PhiUSIIL_Phishing_URL_Dataset.csv    # dataset kept elsewhere
   node ml/train_url_model.js --no-write                                              # only print the evaluation
   ```

   It prints the accuracy on a held-out test set, compares it with the old model, and writes
   `url_model.json` plus `ml/parity_vectors.json`.
3. Run the Android unit tests. `matchesTheTrainingScriptExactly` fails if the Kotlin port (`FeatureExtractor.kt`)
   no longer gives the same probabilities as this script.

## What the model is

- Logistic regression on 15 numbers taken from the **host name only** (never the path or the query).
- Why host only: in the dataset almost every legitimate URL is a bare homepage, so a model that also sees the path
  learns "path = phishing" and flags real login pages such as `https://school.edu/login/index.php`.
- A leading `www.` is dropped before the features are computed: nearly every legitimate URL in the dataset starts with
  it, so keeping it teaches "no www = phishing" and flags `github.com`.
- Features: host length, raw IP, number of subdomains, suspicious ending, hyphens and digits in the host, entropy,
  longest label, free hosting (workers.dev, firebaseapp.com ...), a brand name in the address, longest digit run,
  second-level name length, how often the ending was phishing in training, number of dots, and school/government
  endings (`.edu`, `.gov`, `.ac`).
- Split: 80% train / 20% test, split by host so the same site is never in both.

## Results (test set, 48,390 URLs never seen in training, threshold 0.5)

| | Old model (`baseline_url_model_v1.json`) | New model |
|---|---|---|
| AUC | 0.713 | 0.892 |
| Accuracy | 72.0% | 84.7% |
| Recall (phishing caught) | 41.0% | 72.9% |
| F1 | 0.563 | 0.806 |
| Legitimate sites flagged | 3.8% | 6.1% |

Checked by hand in the app with Google switched on (10 URLs): 9 of 10 correct. Google listed none of the 5 phishing
URLs; the model caught 4 of them as a WARNING.

## Limits

- One dataset, with its own bias. Real-world accuracy can differ.
- Host-name features cannot tell a look-alike domain with an innocent shape (for example `uk-ensono.com`).
- The lists of free hosts and brand names are hand-written in `train_url_model.js` and can be extended.
- Without a Google answer the model alone can say DANGER; when Google answers "not listed", the model alone can only
  raise a WARNING (see `CombinedScan.kt`).

## Files

| File | What it is |
|---|---|
| `train_url_model.js` | trains and evaluates the model, writes `url_model.json` |
| `baseline_url_model_v1.json` | the previous model, kept only for the comparison above |
| `parity_vectors.json` | the script's probabilities for sample URLs, checked by the Kotlin unit test |
