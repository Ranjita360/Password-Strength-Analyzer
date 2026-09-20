import re
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


# --------------------------------------------------
# 1. LOAD DATASET
# --------------------------------------------------

print("=" * 60)
print("          PHISHING EMAIL DETECTION MODEL")
print("=" * 60)

try:
    data = pd.read_csv("emails.csv")
except FileNotFoundError:
    print("\nError: emails.csv file not found.")
    print("Place emails.csv in the same folder as this Python file.")
    exit()


# Remove missing values
data = data.dropna(subset=["text", "label"])

# Convert text and labels to string
data["text"] = data["text"].astype(str)
data["label"] = data["label"].astype(str)


# --------------------------------------------------
# 2. EXTRACT URL AND KEYWORD FEATURES
# --------------------------------------------------

def extract_features(text):

    text_lower = text.lower()

    # Count URLs
    url_count = len(
        re.findall(
            r"https?://\S+|www\.\S+",
            text_lower
        )
    )

    # Count suspicious keywords
    phishing_keywords = [
        "urgent",
        "verify",
        "verification",
        "password",
        "account",
        "login",
        "click here",
        "bank",
        "winner",
        "won",
        "prize",
        "suspended",
        "confirm",
        "security",
        "limited time",
        "free",
        "claim"
    ]

    keyword_count = 0

    for keyword in phishing_keywords:
        if keyword in text_lower:
            keyword_count += 1

    # Count special characters
    special_characters = len(
        re.findall(r"[@#$%!]", text)
    )

    # Count numbers
    number_count = len(
        re.findall(r"\d", text)
    )

    return (
        url_count,
        keyword_count,
        special_characters,
        number_count
    )


# Add numerical features
data[
    [
        "url_count",
        "keyword_count",
        "special_characters",
        "number_count"
    ]
] = data["text"].apply(
    lambda x: pd.Series(extract_features(x))
)


# --------------------------------------------------
# 3. SPLIT DATA
# --------------------------------------------------

X = data["text"]
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# --------------------------------------------------
# 4. TEXT FEATURE EXTRACTION
# --------------------------------------------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    max_features=5000,
    ngram_range=(1, 2)
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)


# --------------------------------------------------
# 5. TRAIN MACHINE LEARNING MODEL
# --------------------------------------------------

model = LogisticRegression(
    max_iter=1000
)

model.fit(
    X_train_tfidf,
    y_train
)


# --------------------------------------------------
# 6. TEST MODEL
# --------------------------------------------------

y_pred = model.predict(X_test_tfidf)

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\nModel Training Completed!")

print("\nAccuracy:")
print(f"{accuracy * 100:.2f}%")


# --------------------------------------------------
# 7. CLASSIFICATION REPORT
# --------------------------------------------------

print("\nClassification Report:")
print("-" * 60)

print(
    classification_report(
        y_test,
        y_pred
    )
)


# --------------------------------------------------
# 8. CONFUSION MATRIX
# --------------------------------------------------

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=model.classes_
)

print("\nConfusion Matrix:")
print(cm)


disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=model.classes_
)

disp.plot()

plt.title("Phishing Email Detection - Confusion Matrix")
plt.show()


# --------------------------------------------------
# 9. PREDICT A NEW EMAIL
# --------------------------------------------------

print("\n" + "=" * 60)
print("              TEST A NEW EMAIL")
print("=" * 60)

email = input(
    "\nEnter an email message to analyze:\n"
)

email_vector = vectorizer.transform(
    [email]
)

prediction = model.predict(
    email_vector
)[0]

probability = model.predict_proba(
    email_vector
)[0]

confidence = max(probability) * 100


# --------------------------------------------------
# 10. DISPLAY RESULT
# --------------------------------------------------

print("\n" + "-" * 60)

if prediction.lower() == "phishing":

    print("RESULT: PHISHING")
    print(
        f"Confidence: {confidence:.2f}%"
    )
    print(
        "Warning: This email may contain suspicious content."
    )

else:

    print("RESULT: SAFE")
    print(
        f"Confidence: {confidence:.2f}%"
    )
    print(
        "The email appears legitimate based on the trained model."
    )

print("-" * 60)