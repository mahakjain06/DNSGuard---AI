"""
model_insights.py
------------------
Data-science-facing additions for DNSGuard AI, built directly from the
actual trained pipeline (models/dnsguard_models.pkl) supplied by the
user: ColumnTransformer(StandardScaler + OneHotEncoder) -> LogisticRegression.

Two things live here:

1. Global feature importance  - the model's learned coefficients, mapped
   back to human-readable feature names. Works directly off the fitted
   pipeline, no retraining or extra data needed.

2. Per-prediction SHAP explanation - how much each feature pushed THIS
   specific prediction towards "tunnel" vs "benign". Uses shap.LinearExplainer
   since the final estimator is a linear model.

   IMPORTANT CAVEAT: SHAP needs a "background" reference point to measure
   contributions against. We don't have access to the original training
   set here (the notebook loads it from a local path), so the background
   is a zero vector in the transformed feature space. Because the numeric
   features were fit with StandardScaler, a zero vector there IS the
   training-set mean for those features - a legitimate baseline. For the
   one-hot encoded query_type, zero doesn't correspond to a real category;
   it's a "no query type active" baseline rather than a true average, which
   is a reasonable approximation but worth knowing about if you inspect the
   per-category contributions closely.

3. Static training-time metrics - copied directly from the model
   comparison the notebook already ran (Logistic Regression vs Decision
   Tree vs Random Forest). These are NOT recomputed live because no
   held-out test set ships with this app - they're exactly the numbers
   from the notebook's own evaluation. If the model is retrained, update
   this dict to match.
"""

import numpy as np

try:
    import shap
except ImportError:  # pragma: no cover
    shap = None


# Copied verbatim from the training notebook's model comparison cell.
TRAINING_METRICS = {
    "dataset": {
        "total_samples": 10000,
        "benign": 7000,
        "tunnel": 3000,
        "test_size": 0.20,
    },
    "models": [
        {"name": "Logistic Regression", "accuracy": 0.9990, "precision": 1.000000, "recall": 0.996667, "f1": 0.998331, "selected": True},
        {"name": "Random Forest", "accuracy": 0.9985, "precision": 1.000000, "recall": 0.995000, "f1": 0.997494, "selected": False},
        {"name": "Decision Tree", "accuracy": 0.9975, "precision": 0.996661, "recall": 0.995000, "f1": 0.995830, "selected": False},
    ],
}


def _humanize(raw_name):
    """Turns ColumnTransformer output names like 'num__query_length' or
    'cat__query_type_A' into something readable for the UI."""
    name = raw_name.split("__", 1)[-1]
    if name.startswith("query_type_"):
        return f"Query Type = {name.replace('query_type_', '')}"
    return name.replace("_", " ").title()


def get_feature_importance(model):
    """
    Returns a list of {"feature": str, "coefficient": float, "abs": float}
    sorted by absolute coefficient size (largest influence first).
    Positive coefficient = pushes prediction toward the model's classes_[1]
    ("tunnel"); negative = pushes toward classes_[0] ("benign").
    """
    preprocessor = model.named_steps["preprocessor"]
    clf = model.named_steps["model"]

    feature_names = preprocessor.get_feature_names_out()
    coefs = clf.coef_[0]

    items = [
        {"feature": _humanize(name), "coefficient": round(float(c), 4), "abs": abs(float(c))}
        for name, c in zip(feature_names, coefs)
    ]
    items.sort(key=lambda x: x["abs"], reverse=True)
    return items


def explain_prediction(model, features_df):
    """
    Per-prediction SHAP explanation for a single-row feature DataFrame
    (the same DataFrame extract_features() produces).

    Returns a list of {"feature": str, "value": float, "shap": float},
    largest |shap| first, or None if shap isn't installed / anything
    goes wrong (this must never break the main prediction flow).
    """
    if shap is None:
        return None

    try:
        preprocessor = model.named_steps["preprocessor"]
        clf = model.named_steps["model"]

        x_transformed = preprocessor.transform(features_df)
        if hasattr(x_transformed, "toarray"):
            x_transformed = x_transformed.toarray()

        background = np.zeros((1, x_transformed.shape[1]))
        explainer = shap.LinearExplainer(clf, background)
        shap_values = explainer.shap_values(x_transformed)[0]

        feature_names = preprocessor.get_feature_names_out()
        items = [
            {
                "feature": _humanize(name),
                "value": round(float(val), 3),
                "shap": round(float(sv), 4),
            }
            for name, val, sv in zip(feature_names, x_transformed[0], shap_values)
        ]
        items.sort(key=lambda x: abs(x["shap"]), reverse=True)
        return items
    except Exception:
        return None
