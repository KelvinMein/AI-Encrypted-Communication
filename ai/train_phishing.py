"""Trains a small text classifier for spam, promotion and scam wording.

Data:   ai/data/SMSSpamCollection  (UCI SMS Spam Collection: 'ham' or 'spam', a tab, then the text)
Output: ai/results/phishing_model.json  (loaded later by the browser, so scoring happens client-side)

The model reported on is the one exported: it is trained on the training split only and
scored once on the held-out split.
"""
import json
import os
import re

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.pipeline import Pipeline

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "ai", "data", "SMSSpamCollection")
OUT_DIR = os.path.join(ROOT, "ai", "results")
OUT = os.path.join(OUT_DIR, "phishing_model.json")

if not os.path.exists(DATA):
    raise SystemExit(f"Dataset not found at {DATA}\nDownload the UCI SMS Spam Collection and put the file there.")

# ---------- load and clean ----------
df = pd.read_csv(DATA, sep="\t", header=None, names=["label", "text"], encoding="latin-1", quoting=3)
df = df.dropna()
total = len(df)
df = df.drop_duplicates(subset="text")  # duplicates would leak between training and test
df["y"] = (df["label"] == "spam").astype(int)
print(f"Messages: {total}, after removing exact duplicates: {len(df)}")
print(f"  spam: {int(df['y'].sum())}   ham: {int((1 - df['y']).sum())}")

URL = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|net|org|xyz|top|click|link|ly|co|info|biz)\b\S*)", re.I)


def normalise(text):
    return URL.sub(" urltoken ", text.lower())


def make_pipeline(C):
    vec = TfidfVectorizer(
        preprocessor=normalise,
        token_pattern=r"[a-z0-9']+",
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
    )
    lr = LogisticRegression(C=C, class_weight="balanced", max_iter=2000)
    return Pipeline([("tfidf", vec), ("lr", lr)])


train, test = train_test_split(df, test_size=0.2, stratify=df["y"], random_state=42)
print(f"Training messages: {len(train)}   Held-out test messages: {len(test)}")

# ---------- choose C and the threshold using the training data only ----------
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
best = None
print("\nChoosing the regularisation strength (5-fold cross-validation, training data only)")
for C in (1, 3, 10, 30):
    p = cross_val_predict(make_pipeline(C), train["text"], train["y"], cv=cv, method="predict_proba")[:, 1]
    f1 = f1_score(train["y"], p >= 0.5)
    print(f"  C={C:<3} F1 {f1:.3f}")
    if best is None or f1 > best[0]:
        best = (f1, C, p)
_, C, cv_p = best
print(f"Chosen C = {C}")

# A flag costs the reader attention, so keep false alarms low: aim for about 1% of normal messages flagged
ham_scores = cv_p[train["y"].to_numpy() == 0]
threshold = float(np.clip(np.quantile(ham_scores, 0.99), 0.3, 0.9))
print(f"Chosen threshold = {threshold:.3f}  (flags about 1% of normal messages in cross-validation)")

# ---------- fit on the training split, score the held-out split once ----------
pipe = make_pipeline(C)
pipe.fit(train["text"], train["y"])
p_test = pipe.predict_proba(test["text"])[:, 1]
y_test = test["y"].to_numpy()


def report(name, thr):
    pred = p_test >= thr
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    print(
        f"  {name:<22} precision {precision_score(y_test, pred):.3f}  recall {recall_score(y_test, pred):.3f}  "
        f"F1 {f1_score(y_test, pred):.3f}  false alarms {fp} of {fp + tn} normal ({100 * fp / (fp + tn):.1f}%)  "
        f"missed {fn} of {fn + tp} spam"
    )


print(f"\nHELD-OUT RESULTS (messages the model never saw), AUC {roc_auc_score(y_test, p_test):.3f}")
report("threshold 0.5", 0.5)
report(f"threshold {threshold:.2f}", threshold)

# Longest and shortest messages, because SMS text is short and chat messages may not be
lengths = test["text"].str.len().to_numpy()
print("\nHeld-out recall by message length (at the chosen threshold)")
for name, mask in (("short (under 60 chars)", lengths < 60), ("long (60 chars or more)", lengths >= 60)):
    m = mask & (y_test == 1)
    if m.sum():
        print(f"  {name:<24} {int(((p_test >= threshold) & m).sum())} of {int(m.sum())} spam caught")

# ---------- what the model has learned ----------
vec, lr = pipe.named_steps["tfidf"], pipe.named_steps["lr"]
terms = np.array(vec.get_feature_names_out())
order = np.argsort(lr.coef_[0])
print("\nWords and phrases that push a message towards 'suspicious':")
print("  " + ", ".join(terms[order[::-1][:20]]))
print("Words and phrases that push it towards 'normal':")
print("  " + ", ".join(terms[order[:10]]))

# ---------- check the wording from our own earlier tests ----------
samples = [
    "Are we still meeting at 3pm?",
    "Congratulations! You won a free gift. Claim now: bit.ly/win-prize",
    "URGENT: your account is suspended. Verify your account at http://safaricom-login.xyz/verify",
    "Send me your PIN and OTP",
    "Can you send the report by Friday? Thanks",
    "You have won a 1000 prize, call now to claim your reward",
    "Lunch at 1? I'll book a table",
]
sample_p = pipe.predict_proba(samples)[:, 1]
print("\nOur own example messages (these are NOT part of the evaluation):")
for s, pr in zip(samples, sample_p):
    print(f"  {pr:.2f}  {'FLAG' if pr >= threshold else 'ok  '}  {s}")

# ---------- export for the browser ----------
os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(
        {
            "vocabulary": {k: int(v) for k, v in vec.vocabulary_.items()},
            "idf": [round(float(x), 6) for x in vec.idf_],
            "coef": [round(float(x), 6) for x in lr.coef_[0]],
            "intercept": round(float(lr.intercept_[0]), 6),
            "threshold": round(threshold, 4),
            "ngram_range": [1, 2],
            "sublinear_tf": True,
            "trained_on": {"messages": int(len(train)), "source": "UCI SMS Spam Collection (duplicates removed)"},
            "reference": [{"text": s, "probability": round(float(pr), 6)} for s, pr in zip(samples, sample_p)],
        },
        f,
    )
print(f"\nModel saved to {OUT}  ({os.path.getsize(OUT) // 1024} KB)")