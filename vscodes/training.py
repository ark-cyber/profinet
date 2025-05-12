#Load the CSV 📄
#Preprocess the data (prepare inputs and labels) 🛠️
#Train a simple Random Forest Classifier 🌳
#Save the model for later use (for live traffic!) 💾

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib

def train_model(csv_file, model_file):
    # Step 1: Load the data
    df = pd.read_csv(csv_file)
    print(f"Loaded {len(df)} samples")

    # Step 2: Preprocessing
    # For now, let's create a fake "label" column (since PCAPs don't have labels usually)
    # You will later replace this with real labels (Normal, Anomaly, etc.)

    # Example: Let's assume traffic from certain MACs is "Normal", others "Anomaly"
    df['label'] = df['src_mac'].apply(lambda x: 0 if x.startswith('08:00:06:6b:f6') else 1)

    print(df[['src_mac', 'label']].head())

    # Encode MAC addresses into numbers
    le_src = LabelEncoder()
    le_dst = LabelEncoder()
    df['src_mac_encoded'] = le_src.fit_transform(df['src_mac'])
    df['dst_mac_encoded'] = le_dst.fit_transform(df['dst_mac'])

    # Step 3: Features and Labels
    X = df[['packet_size', 'src_mac_encoded', 'dst_mac_encoded']]
    y = df['label']

    # Step 4: Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Step 5: Model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Step 6: Evaluation
    y_pred = clf.predict(X_test)
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Step 7: Save the model and encoders
    joblib.dump(clf, model_file)
    joblib.dump(le_src, 'src_mac_encoder.pkl')
    joblib.dump(le_dst, 'dst_mac_encoder.pkl')
    print(f"\nModel saved to {model_file}")

if __name__ == "__main__":
    csv_file = r"output.csv"   # <-- Your features CSV
    model_file = r"C:\Users\sebae_a\OneDrive - University of Warwick\Academic Private\Supervision\Summer Pedagogical research\Summer 25\vscodes\rf_model.pkl"  # <-- Model save path
    train_model(csv_file, model_file)


#You will have a trained model file: rf_model.pkl

#Encoders for MAC addresses: src_mac_encoder.pkl, dst_mac_encoder.pkl

#Ready to detect live traffic next!