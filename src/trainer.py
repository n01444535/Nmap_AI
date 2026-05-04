# EN: Train machine learning models from scan features.
# VI: Dạy máy học từ các con số lấy từ scan.

import json
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from constants import (
    MIN_SAMPLES_TO_TRAIN, MIN_SAMPLES_FOR_STRATIFY, MIN_SAMPLES_FOR_LR,
    SMALL_DATASET_ROW_LIMIT, TEST_SPLIT_SMALL_DATASET, TEST_SPLIT_NORMAL_DATASET,
    DT_MAX_DEPTH, DT_MIN_SAMPLES_SPLIT, DT_MIN_SAMPLES_LEAF,
)
from features import feature_columns

# EN: Read model internals and rank the most useful learning signals.
# VI: Đọc bên trong mô hình rồi xếp hạng dấu hiệu quan trọng nhất.
def get_feature_importance_rows(bundle, top_n=20):
    if bundle is None:
        return []

    # EN: Pull the trained model and the feature names saved beside it.
    # VI: Lấy mô hình đã học và tên các dấu hiệu đi kèm.
    model = bundle.get("model")
    features = bundle.get("features", [])
    rows = []

    # EN: Tree models already tell us how much each feature helped.
    # VI: Mô hình cây tự nói dấu hiệu nào giúp nhiều hay ít.
    if hasattr(model, "feature_importances_"):
        importance_values = model.feature_importances_
        for feature, importance_value in zip(features, importance_values):
            rows.append((feature, float(importance_value), "tree_importance"))
    # EN: Linear models use coefficient size as a simple importance score.
    # VI: Mô hình đường thẳng dùng độ lớn hệ số làm điểm quan trọng.
    elif hasattr(model, "coef_"):
        coefficients = model.coef_[0]
        for feature, coefficient in zip(features, coefficients):
            rows.append((feature, abs(float(coefficient)), "absolute_coefficient"))

    # EN: Put the biggest learning signals at the top of the report.
    # VI: Đưa dấu hiệu quan trọng nhất lên đầu báo cáo.
    rows.sort(key=lambda importance_row: importance_row[1], reverse=True)
    return rows[:top_n]

# EN: Write the feature importance report so people can see what the AI used.
# VI: Ghi báo cáo để thấy AI dựa vào dấu hiệu nào.
def write_feature_importance_report(bundle, output_path, top_n=20):
    rows = get_feature_importance_rows(bundle, top_n=top_n)

    # EN: Always write a file, even when training was skipped.
    # VI: Luôn ghi file, kể cả khi máy chưa học được.
    with open(output_path, "w", encoding="utf-8") as f:
        if bundle is None:
            f.write("No trained model is available, so feature importance could not be calculated.\n")
            return

        if not rows:
            f.write("This model does not expose feature importance values.\n")
            return

        f.write("Top AI factors used by the model\n")
        f.write("================================\n")
        f.write(f"Model: {bundle.get('model_name', 'unknown')}\n\n")

        for i, (feature, score, method) in enumerate(rows, 1):
            f.write(f"{i}. {feature}: {score:.6f} ({method})\n")

# EN: Train and choose the best model.
# VI: Dạy và chọn mô hình tốt nhất.
def train_models(train_csv, output_model):
    df = pd.read_csv(train_csv)

    if "label" not in df.columns:
        return None, "Training CSV must contain a label column.\n"

    if len(df) < MIN_SAMPLES_TO_TRAIN:
        return None, "Not enough samples to train machine learning models.\n"

    if df["label"].nunique() < 2:
        return None, "Training data contains only one class, so machine learning training was skipped.\n"

    X_cols = feature_columns(df)
    X = df[X_cols]
    y = df["label"].astype(str)

    use_stratify = y.value_counts().min() >= MIN_SAMPLES_FOR_STRATIFY
    stratify_value = y if use_stratify else None

    test_size = TEST_SPLIT_SMALL_DATASET if len(df) <= SMALL_DATASET_ROW_LIMIT else TEST_SPLIT_NORMAL_DATASET

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=42,
            stratify=stratify_value
        )
    except Exception:
        X_train = X
        X_test = X
        y_train = y
        y_test = y

    if len(set(y_train)) < 2:
        return None, "Training split contains only one class, so machine learning training was skipped.\n"

    candidate_models = []

    if len(df) >= MIN_SAMPLES_FOR_LR:
        candidate_models.append(
            ("logistic_regression", LogisticRegression(max_iter=2000, class_weight="balanced"))
        )

    candidate_models.append(
        ("decision_tree", DecisionTreeClassifier(max_depth=DT_MAX_DEPTH, min_samples_split=DT_MIN_SAMPLES_SPLIT, min_samples_leaf=DT_MIN_SAMPLES_LEAF, class_weight="balanced", random_state=42))
    )

    results = {}
    best_name = None
    best_f1 = -1.0
    best_model = None

    for name, model in candidate_models:
        try:
            model.fit(X_train, y_train)
            preds = model.predict(X_test)

            acc = accuracy_score(y_test, preds)
            prec = precision_score(y_test, preds, pos_label="suspicious", zero_division=0)
            rec = recall_score(y_test, preds, pos_label="suspicious", zero_division=0)
            f1 = f1_score(y_test, preds, pos_label="suspicious", zero_division=0)
            cm = confusion_matrix(y_test, preds, labels=["normal", "suspicious"]).tolist()
            report = classification_report(y_test, preds, zero_division=0, output_dict=True)

            results[name] = {
                "accuracy": acc,
                "precision_suspicious": prec,
                "recall_suspicious": rec,
                "f1_suspicious": f1,
                "confusion_matrix_labels": ["normal", "suspicious"],
                "confusion_matrix": cm,
                "classification_report": report
            }

            if f1 > best_f1:
                best_f1 = f1
                best_name = name
                best_model = model

        except Exception as e:
            results[name] = {
                "error": str(e)
            }

    if best_model is None:
        return None, "All machine learning models failed during training.\n"

    bundle = {
        "model_name": best_name,
        "model": best_model,
        "features": X_cols,
        "metrics": results
    }

    joblib.dump(bundle, output_model)
    return bundle, None

# EN: Write model score details to a file.
# VI: Ghi điểm mô hình vào file.
def write_metrics_report(bundle, output_path, note=None):
    with open(output_path, "w", encoding="utf-8") as f:
        if note is not None:
            f.write(note)
            return

        lines = []
        lines.append(f"Best model: {bundle['model_name']}")
        lines.append("")

        for model_name, metrics in bundle["metrics"].items():
            lines.append(f"Model: {model_name}")

            if "error" in metrics:
                lines.append(f"Error: {metrics['error']}")
                lines.append("")
                continue

            lines.append(f"Accuracy: {metrics['accuracy']:.4f}")
            lines.append(f"Precision suspicious: {metrics['precision_suspicious']:.4f}")
            lines.append(f"Recall suspicious: {metrics['recall_suspicious']:.4f}")
            lines.append(f"F1 suspicious: {metrics['f1_suspicious']:.4f}")
            lines.append(f"Confusion matrix labels: {metrics['confusion_matrix_labels']}")
            lines.append(f"Confusion matrix: {metrics['confusion_matrix']}")
            lines.append("")

        f.write("\n".join(lines))

# EN: Print model score details on the screen.
# VI: In điểm mô hình ra màn hình.
def print_metrics(bundle, note=None):
    if note is not None:
        print(note)
        return

    print(f"Best model: {bundle['model_name']}")
    print(json.dumps(bundle["metrics"], indent=2))
