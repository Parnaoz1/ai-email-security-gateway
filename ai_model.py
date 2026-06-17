from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

training_emails = [

    "verify your password immediately",
    "your account is suspended",
    "click here to confirm bank account",
    "urgent login verification needed",
    "invoice attached open now",

    "meeting tomorrow at 3pm",
    "project update attached",
    "hello how are you",
    "weekly report completed",
    "team meeting invitation"

]

training_labels = [

    "phishing",
    "phishing",
    "phishing",
    "phishing",
    "phishing",

    "safe",
    "safe",
    "safe",
    "safe",
    "safe"

]

vectorizer = CountVectorizer()

X = vectorizer.fit_transform(training_emails)

model = MultinomialNB()

model.fit(X, training_labels)

def predict_email(text):

    transformed = vectorizer.transform([text])

    prediction = model.predict(transformed)[0]

    probability = model.predict_proba(transformed).max()

    return {
        "prediction": prediction,
        "confidence": round(float(probability), 2)
    }
