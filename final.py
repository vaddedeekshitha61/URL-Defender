# Import necessary libraries
from bs4 import BeautifulSoup
import requests
from sklearn.naive_bayes import MultinomialNB
import numpy as np
import tkinter as tk
from tkinter import messagebox, font
import tldextract  # New library for domain extraction
import time  # To measure response time

# Simulated functions to detect spammy domains, SSL status, and blacklist checks (for illustration)
def check_ssl(url):
    """Simulates SSL check. Returns True if HTTPS is used."""
    return url.startswith('https://')

def check_blacklist(url):
    """Simulates checking if a URL is in a blacklist. Return True if blacklisted."""
    blacklisted_domains = ['badwebsite.com', 'malicious.com']  # Simulated blacklist
    return any(domain in url for domain in blacklisted_domains)

def check_suspicious_keywords(url):
    """Check for presence of suspicious keywords in the URL."""
    suspicious_keywords = ['login', 'secure', 'update', 'account', 'bank', 'verify']
    return any(keyword in url for keyword in suspicious_keywords)

# Define a function to extract features from a webpage
def extract_features(url):
    try:
        start_time = time.time()  # Start timer for response time
        # Send a request to the webpage and get the HTML response
        response = requests.get(url)
        response_time = time.time() - start_time  # Calculate response time
        html = response.content

        # Parse the HTML using BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')

        # Extract features from the HTML
        features = [
            len(soup.find_all('iframe')),   # Number of iframes
            len(soup.find_all('script')),   # Number of scripts
            len(soup.find_all('a', href=True)),  # Number of external links
            int(check_ssl(url)),            # SSL Certificate (1 if HTTPS, 0 otherwise)
            int(check_blacklist(url)),       # Blacklist status (1 if blacklisted, 0 otherwise)
            response_time,                   # Response time
            len(tldextract.extract(url).subdomain.split('.'))  # Number of subdomains
        ]

        # Add suspicious keyword check
        features.append(int(check_suspicious_keywords(url)))

        return features
    except Exception as e:
        messagebox.showerror("Error", f"Failed to extract features: {e}")
        return None

# Define a function to classify a webpage as either malicious, spam, or benign
def classify_webpage(url):
    # Extract features from the webpage
    features = extract_features(url)

    if features is None:
        return

    # Load a pre-trained model or fit one temporarily (for demonstration purposes)
    # Simulating a dataset with known classifications for training (Safe: 0, malicious: 1, spam: 2)
    X_train = np.array([
        [5, 10, 15, 1, 0, 0.5, 1, 0],  # Safe
        [0, 2, 3, 1, 1, 1.5, 3, 1],    # Malicious
        [1, 5, 7, 0, 1, 2.5, 2, 1],    # Spam
        [0, 8, 10, 0, 0, 3.5, 4, 0]    # Spam
    ])
    y_train = np.array([0, 1, 2, 2])  # Labels: 0 = Safe, 1 = Malicious, 2 = Spam
    
    # Create and train the model
    clf = MultinomialNB()
    clf.fit(X_train, y_train)
    
    # Predict based on the extracted features
    features = np.array(features).reshape(1, -1)  # Reshape to match the input expected by the model
    prediction = clf.predict(features)

    # Map prediction to labels
    labels = {0: 'Safe', 1: 'Malicious', 2: 'Spam'}
    return labels[prediction[0]]

# Define the GUI using tkinter
def create_gui():
    # Create the main window
    root = tk.Tk()
    root.title("Webpage Classifier")

    # Set window size and background color
    root.geometry("800x800")
    root.config(bg="#2C3E50")  # Dark background

    # Define fonts
    title_font = font.Font(family="Helvetica", size=35, weight="bold")
    label_font = font.Font(family="Helvetica", size=18)
    button_font = font.Font(family="Helvetica", size=15, weight="bold")

    # Add a title label
    title_label = tk.Label(root, text="Webpage Classifier", font=title_font, fg="white", bg="#2C3E50")
    title_label.pack(pady=20)

    # Label for URL input
    url_label = tk.Label(root, text="Enter URL:", font=label_font, fg="white", bg="#2C3E50")
    url_label.pack(pady=5)

    # Entry widget for URL input
    url_entry = tk.Entry(root, width=40, font=("Arial", 20))
    url_entry.pack(pady=5)

    # Function to handle classification on button click
    def classify():
        url = url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return

        # Perform classification
        result = classify_webpage(url)
        if result:
            messagebox.showinfo("Classification Result", f"The webpage is classified as: {result}")

    # Button to classify the webpage
    classify_button = tk.Button(root, text="Classify Webpage", font=button_font, fg="white", bg="#E74C3C", padx=20, pady=5, command=classify)
    classify_button.pack(pady=20)

    # Start the GUI event loop
    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_gui()
