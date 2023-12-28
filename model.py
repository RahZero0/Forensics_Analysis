import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import RandomOverSampler
from sklearn.model_selection import train_test_split

def scale_dataset(dataframe, oversample=False):
    X = dataframe[dataframe.columns[1:]].values
    y = dataframe[dataframe.columns[0]].values
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    if oversample:
   
       ros = RandomOverSampler()
       X, y = ros.fit_resample(X, y)

    data = np.hstack((X, np.reshape(y, (-1, 1))))

    return data, X, y

def knn_model(X_train, y_train, p):

    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.metrics import classification_report

    knn_model = KNeighborsClassifier(n_neighbors=2,weights='uniform',metric='euclidean',algorithm='ball_tree')
    knn_model.fit(X_train, y_train)
    knn_pred = knn_model.predict(p)
    # print(knn_pred, "KNN_MODEL PREDICTION")
    return knn_pred


def lg_model(X_train, y_train, p):

    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report

    from sklearn.pipeline import make_pipeline
    # lg_model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))

    lg_model = LogisticRegression(solver='liblinear', max_iter=1000)

    # lg_model = LogisticRegression(max_iter=1000)

    lg_model = lg_model.fit(X_train, y_train)
    lg_pred = lg_model.predict(p)
    # print(lg_pred,"LOGISTICAL_REGRESSION PREDICTION")
    return lg_pred

def rf_model(X_train, y_train, p):

    from sklearn.ensemble import RandomForestClassifier

    # Create a Random Forest Classifier
    rf_model = RandomForestClassifier(max_depth=5, max_features=None, max_leaf_nodes=9,n_estimators=170)

    rf_model.fit(X_train, y_train)
    rf_pred = rf_model.predict(p)

    # print(rf_pred,"RANDOM_FOREST PREDICTION")
    return rf_pred

def run_model():
    df = pd.read_csv("data.csv")

    df = df.drop(columns=['psxview.not_in_eprocess_pool', 'psxview.not_in_ethread_pool',
    'psxview.not_in_pspcid_list', 'psxview.not_in_csrss_handles','psxview.not_in_session',
    'psxview.not_in_deskthrd','psxview.not_in_pslist_false_avg','psxview.not_in_eprocess_pool_false_avg',
    'psxview.not_in_ethread_pool_false_avg','psxview.not_in_pspcid_list_false_avg','psxview.not_in_csrss_handles_false_avg',
    'psxview.not_in_session_false_avg', 'psxview.not_in_deskthrd_false_avg','psxview.not_in_pslist'])

    df['Category'] = [label.split('-')[0] for label in df['Category']]
    df['Category'] = df['Category'].replace(['Benign', "Ransomware","Spyware","Trojan" ], [0,1,2,3])
    df = df.drop(columns=["Class"])

    # train, test = np.split(df.sample(frac=1), [int(0.6*len(df))])


    train, test = train_test_split(df, test_size=0.4, random_state=42)
    train, X_train, y_train = scale_dataset(train, oversample=True)
    #valid, X_valid, y_valid = scale_dataset(valid, oversample=False)
    test, X_test, y_test = scale_dataset(test, oversample=False)

    scaler = StandardScaler()
    trialdf=pd.read_csv("trial.csv")

    a = trialdf.iloc[0]
    nda = np.array([a])
    p = scaler.fit_transform(nda)
    if knn_model(X_train, y_train, p) == lg_model(X_train, y_train, p)==rf_model(X_train, y_train, p):
        print("\nYayyy your system is not infected . Hurrayy!!!")
    else:
        print("Hacked 😥")
