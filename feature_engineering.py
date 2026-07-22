import math


def get_query_length(domain):
    return len(domain)


def get_num_labels(domain):
    return len(domain.split("."))


def get_avg_label_length(domain):
    labels = domain.split(".")
    return round(sum(len(label) for label in labels) / len(labels), 2)


def get_subdomain_length(domain):
    labels = domain.split(".")

    if len(labels) <= 2:
        return 0

    subdomain = ".".join(labels[:-2])

    return len(subdomain)


def get_entropy(domain):
    char_counts = {}

    for char in domain:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0

    for count in char_counts.values():
        probability = count / len(domain)
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)


def get_digit_ratio(domain):
    digit_count = sum(char.isdigit() for char in domain)

    return round(digit_count / len(domain), 3)


def get_uncomman_tld(domain):

    comman_tlds = [
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "co",
        "io",
        "ai"
    ]

    tld = domain.split(".")[-1].lower()

    if tld in comman_tlds:
        return 0

    return 1
import pandas as pd


def extract_features(domain, query_type):

    data = {
        "query_length": get_query_length(domain),
        "subdomain_length": get_subdomain_length(domain),
        "num_labels": get_num_labels(domain),
        "avg_label_length": get_avg_label_length(domain),
        "entropy": get_entropy(domain),
        "digit_ratio": get_digit_ratio(domain),
        "uncomman_tld": get_uncomman_tld(domain),
        "query_type": query_type
    }

    return pd.DataFrame([data])