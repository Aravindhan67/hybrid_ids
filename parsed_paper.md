A Hybrid Intrusion Detection System for Android Applications Using Static, Dynamic, Signature and Risk-Based Analysis
Dr. J Premalatha
, 
Aravindhan T
, 
Harini D
Department of Information Technology
Kongu Engineering College
Perundurai, Erode, Tamil Nadu, India
Abstract—The rapid growth of Android applications has increased the security risks associated with malicious and potentially unwanted software. Traditional signature-based detection is effective against known threats but has limited capability against previously unseen or modified malware. Following the hybrid deep-learning intrusion detection philosophy established in recent research [1]–[3], this paper proposes a Hybrid Intrusion Detection System (HIDS) for Android applications that combines SHA-256/pattern based signature detection, static analysis, dynamic sandbox analysis, machine learning, and risk assessment. The proposed system accepts an Android Application Package (APK) and performs static feature extraction using Androguard [4]. A Random Forest classifier trained on the Drebin dataset [5] (215 features) analyzes static application characteristics, while a second Random Forest classifier trained on CICMalDroid2020 [6] dynamic syscall-frequency features (139 features) analyzes behavior obtained from a sandbox environment. The two malware probabilities are combined using a weighted hybrid confidence calculation (0.5/0.5, with automatic fallback to the static branch), and the risk assessment layer categorizes the resulting threat level into Safe, Low Risk, High Risk, or Critical. A confirmed signature match overrides the fused verdict directly to Critical. To improve interpretability, SHAP-based explanations [8] identify the top-10 influential static features contributing to the machine-learning prediction. The system is implemented using a FastAPI backend, a Next.js frontend, a machine-learning pipeline, and a sandbox interface with Docker-based deployment. Experimental evaluation is performed using accuracy, precision, recall, F1-score, and false-positive rate.
Keywords—
Intrusion Detection System, Android Security, Android Malware, Hybrid IDS, Random Forest, Static Analysis, Dynamic Analysis, Signature Detection, Risk Assessment, Drebin, CICMalDroid2020, SHAP, Androguard.
1. Introduction
The widespread adoption of Android smartphones has resulted in a large ecosystem of applications that interact with sensitive device resources such as contacts, messages, location, camera, microphone, storage, and network interfaces. Although these capabilities are essential for legitimate applications, they can also be misused by malicious software to steal sensitive information, abuse permissions, communicate with remote servers, or execute unauthorized commands.
An Intrusion Detection System (IDS) monitors or analyzes observable characteristics of a system to identify potentially malicious activity. Traditional signature-based detection identifies malware using predefined patterns and can provide fast, deterministic detection for previously identified threats, but it fails against modified or previously unseen malware variants.
Recent research has shown that hybrid architectures — which combine multiple learning paradigms and detection perspectives instead of a single classifier — achieve improved detection accuracy over standalone models. Samha et al. [1] proposed a hybrid Convolutional Neural Network based intrusion detection system and demonstrated that combining complementary feature-learning stages substantially strengthens detection robustness. Chavan and Hanumanthappa [2] incorporated an attention mechanism into a hybrid deep-learning IDS to focus on the most discriminative features, while Prasad et al. [3] applied Grey Wolf Optimization (GWO) to tune a hybrid deep-learning IDS, reporting improved convergence and detection performance over non-optimized baselines. These works motivate the present study, which follows the same hybrid design philosophy but applies it specifically to the Android APK domain using static analysis, dynamic sandbox behavior, hash/pattern-based signature matching, and machine-learning based risk assessment.
Static analysis examines an APK without executing it. Arp et al. [5] demonstrated with the Drebin system that broad static analysis, performed with reverse-engineering toolkits such as Androguard [4], can identify characteristic patterns associated with malware. Dynamic analysis complements this by observing application behavior during execution; the CICMalDroid2020 dataset [6] provides syscall-frequency behavioral features derived from sandboxed execution of 17,341 Android samples.
This paper presents a Hybrid Intrusion Detection System (HIDS) that accepts an Android APK and combines: (i) SHA-256 hash and pattern based signature detection, (ii) a Random Forest classifier trained on Drebin [5] static features extracted via Androguard [4], (iii) a second Random Forest classifier trained on CICMalDroid2020 [6] dynamic syscall-frequency features obtained from a sandbox, (iv) a weighted hybrid confidence fusion of the two classifiers, (v) a threshold-based risk assessment layer, and (vi) SHAP-based [8] explainability for the static model. The system is implemented as a FastAPI backend, a Next.js frontend, and a Docker-Compose-orchestrated sandbox service.
The main contributions of this work are:
A hybrid Android intrusion detection architecture combining static analysis, dynamic sandbox analysis, signature matching, and risk assessment, following the hybrid design principles of [1]–[3].
A Random Forest static detection model trained on Drebin [5] features extracted with Androguard [4] (215 features).
A Random Forest dynamic detection model trained on CICMalDroid2020 [6] syscall-frequency features (139 features).
A SHA-256/pattern based signature layer with optional VirusTotal lookup that can override the ML verdict for known-malicious samples.
A weighted hybrid confidence and four-tier risk-assessment mechanism (Safe, Low Risk, High Risk, Critical).
SHAP TreeExplainer based explanation of the top-10 influential static features per prediction.
2. Literature Review
Hybrid and Optimized Deep-Learning Intrusion Detection
Samha et al. [1] proposed a Hybrid Convolutional Neural Network based IDS in which convolutional feature extraction is combined with additional classification stages, showing that hybridization improves detection of complex intrusion patterns over a single-stage classifier. Chavan and Hanumanthappa [2] extended this direction by introducing an attention mechanism into a hybrid deep-learning IDS, allowing the network to weight the most informative features dynamically and improving detection on imbalanced intrusion datasets. Prasad et al. [3] proposed hybrid intrusion detection models optimized using Grey Wolf Optimization, demonstrating that metaheuristic tuning of a hybrid pipeline improves convergence speed and accuracy over non-optimized hybrid baselines. These studies establish that hybridization, attention-based weighting, and pipeline optimization are effective directions for intrusion detection, and directly motivate the hybrid static–dynamic–signature–risk architecture used in this work.
Static Android Malware Detection
Static analysis examines an application without executing it, using characteristics such as permissions, API calls, application components, and intents. Reverse-engineering toolkits such as Androguard [4] are widely used to disassemble and parse APK files and extract this information automatically. Arp et al. [5] introduced Drebin, a lightweight static-analysis based detector that extracted multiple categories of features and represented them in a common feature space; evaluated on 123,453 applications including 5,560 malware samples, it reported a 94% detection rate with a 1% false-positive rate. The present system uses Androguard [4] for parsing and adopts the Drebin [5] feature representation for its static Random Forest model.
Dynamic Android Malware Detection
Dynamic analysis provides complementary information by monitoring application behavior in a controlled sandbox environment. CICMalDroid2020 [6] introduced an Android malware dataset containing static and dynamic characteristics from 17,341 samples across Adware, Banking, SMS, Riskware, and Benign categories, including syscall-frequency behavior profiles. The present IDS uses this dynamic representation for its sandbox-based classifier.
Ensemble Learning and Explainability
Random Forest [7] is an ensemble method that aggregates predictions from multiple decision trees, reducing sensitivity to individual training samples; it is used independently for the static and dynamic branches in this work. Because ensemble predictions can be difficult to interpret, SHAP (SHapley Additive exPlanations) [8] provides feature-level attribution values indicating each feature's contribution to a prediction, and is used here to explain the static model's output.
Research Gap
Existing Android malware detection approaches often focus on a single detection perspective: static analysis [4], [5] provides scalable feature extraction, dynamic analysis [6] provides behavioral information, and signature detection provides deterministic recognition of known threats. Hybrid deep-learning IDS research [1]–[3] has shown that combining multiple learning or optimization stages improves detection performance, but these designs have largely targeted network-traffic intrusion datasets rather than the Android APK domain. The present work addresses this gap by combining static Random Forest classification [4], [5], dynamic Random Forest classification [6], [7], hash/pattern signature matching, weighted hybrid fusion, and SHAP-based explainability [8] within a single Android-focused architecture.
3. Methodology
The proposed system follows a modular pipeline in which an uploaded APK is passed through four analysis stages before a final decision is produced.
Android APK (.apk upload)
      |
      v
Stage 0: Signature Check
 (SHA-256 hash lookup,
  optional VirusTotal query)
      |
      v
Stage 1: Static Analysis        Stage 2: Dynamic Analysis
 (Androguard parsing ->          (Sandbox submission -> task ID
  215-dim Drebin feature          -> behavior report -> 139-dim
  vector -> Static RF model)      CICMalDroid feature vector ->
      |                            Dynamic RF model)
      +--------------+--------------+
                     |
                     v
        Stage 3: Hybrid Fusion
        C = 0.5*Ps + 0.5*Pd
      (falls back to C = Ps if
       sandbox analysis fails)
                     |
                     v
        Stage 4: Risk Assessment
   Safe / Low Risk / High Risk / Critical
                     |
                     v
   Signature override: if hash/pattern
   match found in Stage 0, verdict is
   forced to Malware / Critical (100%)
                     |
                     v
        Stage 5: SHAP Explanation
        (top-10 static features)
Stage 0 first computes the SHA-256 hash of the uploaded file and checks it against a local signature database; an optional VirusTotal API lookup can supplement this with third-party antivirus-engine verdicts. Stage 1 uses Androguard [4] to parse the APK's manifest and extract its package name, permissions, activities, services, broadcast receivers, and content providers, which are mapped onto the 215-dimensional Drebin [5] feature space used during training. Stage 2 submits the APK to a sandbox service (Cuckoo-style REST API) and, once the behavior report is returned, counts the frequency of each observed system/API call to build the 139-dimensional CICMalDroid2020 [6] feature vector; if the sandbox is unreachable or times out, this stage is skipped and the pipeline falls back to the static branch alone. Stage 3 combines the two Random Forest [7] malware probabilities using a weighted average. Stage 4 maps the resulting confidence onto a four-level risk category. If Stage 0 found a signature match, the final verdict is overridden to "Malware" with Critical risk regardless of the ML confidence, since a confirmed hash/pattern match is treated as stronger evidence than a probabilistic prediction. Stage 5 runs a SHAP TreeExplainer [8] over the static model to surface the ten most influential features behind the decision.
The system is implemented as a FastAPI backend exposing a single POST /api/analyze endpoint that orchestrates all five stages, a Next.js frontend for APK submission and result visualization, and a machine-learning pipeline (train.py, hybrid_classifier.py) that is decoupled from the backend so that models can be retrained independently. Docker Compose is used to orchestrate the backend (port 8000) and the sandbox service (port 8090) as isolated containers, which also satisfies the security requirement that potentially malicious APKs must never be executed on the host system.
4. Data and its Preprocessing
4.1 Data Collection
Two benchmark datasets are used to train the two independent Random Forest branches.
Drebin dataset [5] — used for the static branch. It contains 123,453 Android applications, including 5,560 malware samples, each represented as a binary feature vector over permissions, API calls, intents, and other manifest/code-level indicators, with a class label of 'S' (malware) or 'B' (benign). After the label column is removed, 215 static feature columns remain and are used for training.
CICMalDroid2020 dataset [6] — used for the dynamic branch, specifically its syscall-frequency feature file (feature_vectors_syscalls_frequency_5_Cat.csv). It contains behavioral profiles for samples spanning five categories (Adware, Banking, SMS, Riskware, Benign) obtained from sandboxed execution. After the label column is removed, 139 dynamic feature columns remain.
Both datasets are loaded with pandas and inspected for shape and class distribution prior to training (implemented in explore_data.py) to confirm column integrity before the training stage.
4.2 Data Preprocessing
Before training, both datasets undergo the following common cleaning steps: undefined values represented as "?" are replaced with NaN and then filled with 0; all remaining feature columns are coerced to numeric type with non-numeric entries also set to 0 (pd.to_numeric(..., errors='coerce').fillna(0)); and the dataset is split into training and testing subsets using an 80:20 ratio with a fixed random_state of 42 for reproducibility.
4.2.1 Encoding
Label encoding: the Drebin class column is binarized as 1 for the 'S' (malware) label and 0 for 'B' (benign). The CICMalDroid2020 multi-class label is binarized as 0 for the benign category (class value 5.0) and 1 for any of the four malware categories (Adware, Banking, SMS, Riskware), converting the original 5-class problem into a binary malware/benign task consistent with the static branch.
Feature encoding at inference time mirrors the representation learned during training. For static features, the system initializes a zero vector over all 215 trained Drebin columns and sets a position to 1 for every permission, activity, or service that Androguard extracts from the submitted APK and that matches a known column name — i.e., multi-hot (binary presence) encoding. For dynamic features, the system initializes a zero vector over all 139 trained CICMalDroid columns and increments the corresponding position by 1 each time that system/API call is observed in the sandbox behavior report — i.e., frequency-count encoding rather than simple presence encoding, since a call can occur multiple times during execution.
4.2.2 Standardization
Random Forest is a tree-based ensemble method whose split decisions depend only on the relative ordering of feature values within each tree, not on their absolute scale. Consequently, min-max scaling or z-score standardization does not change the model's decision boundaries, and the training pipeline (train.py) does not apply a StandardScaler or similar transform to either the static or dynamic feature matrices. The only numeric normalization performed is the missing-value handling described above ("?" → NaN → 0) and the coercion of every column to a numeric dtype, which together ensure a well-formed, zero-filled input matrix without altering the underlying feature scale.
4.3 Suggested Learning Model
The suggested learning model is a two-branch, hybrid Random Forest ensemble with confidence-level fusion, rather than a single end-to-end classifier.
Static branch: a RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42) is trained on the 215-dimensional Drebin feature matrix and outputs a static malware probability Pₛ = predict_proba(Xₛ)[1].
Dynamic branch: an identically configured Random Forest is trained independently on the 139-dimensional CICMalDroid2020 syscall-frequency matrix and outputs a dynamic malware probability P_d = predict_proba(X_d)[1].
Hybrid fusion: when both branches are available, the two probabilities are combined with equal weights,
C = 0.5·Pₛ + 0.5·P_d
If dynamic analysis is unavailable (e.g., sandbox timeout), the weights automatically shift to wₛ = 1, w_d = 0, so that C = Pₛ, allowing the system to remain operational using static evidence alone.
Risk mapping: the final confidence C is mapped onto four risk categories — Safe (C < 0.20), Low Risk (0.20 ≤ C < 0.50), High Risk (0.50 ≤ C < 0.80), and Critical (C ≥ 0.80) — with the 0.50 threshold also used as the binary malware/benign decision boundary.
Signature override: independently of C, if Stage 0 finds a SHA-256/pattern signature match, the model output is overridden and the sample is reported as Malware with Critical risk and 100% confidence, since a confirmed signature match is treated as stronger evidence than the probabilistic ensemble output.
Explainability: a SHAP TreeExplainer [8] is fitted on the static Random Forest to compute per-feature Shapley values for the submitted sample; the ten features with the largest absolute impact are reported alongside a human-readable description (e.g., READ_SMS, RECORD_AUDIO, Runtime.exec) and whether that feature was present in the APK.
5. Result and Discussion
The evaluation protocol follows the same 80:20 train/test split used during training, and is reported separately for the static branch, the dynamic branch, and the fused hybrid output, using accuracy, precision, recall, F1-score, and false-positive rate (FPR).
TABLE I. STATIC RANDOM FOREST PERFORMANCE (DREBIN)
Metric
Result
Accuracy
XX.XX%
Precision
XX.XX%
Recall
XX.XX%
F1-Score
XX.XX%
False Positive Rate
XX.XX%
TABLE II. DYNAMIC RANDOM FOREST PERFORMANCE (CICMALDROID2020)
Metric
Result
Accuracy
XX.XX%
Precision
XX.XX%
Recall
XX.XX%
F1-Score
XX.XX%
False Positive Rate
XX.XX%
TABLE III. HYBRID FUSION PERFORMANCE
Metric
Result
Accuracy
XX.XX%
Precision
XX.XX%
Recall
XX.XX%
F1-Score
XX.XX%
False Positive Rate
XX.XX%
TABLE IV. DETECTION COMPONENTS SUMMARY
Component
Analysis Type
Model/Method
Output
Signature Detection
Hash/Pattern
SHA-256 + VirusTotal
Match / No Match
Static Detection
Static
Random Forest [7] (215 feat.)
Malware Probability Pₛ
Dynamic Detection
Dynamic
Random Forest [7] (139 feat.)
Malware Probability P_d
Hybrid Classifier
Combined
Weighted Fusion (0.5/0.5)
Final Confidence C
Risk Assessment
Risk-based
Threshold Analysis
Risk Level
Explainability
Static
SHAP TreeExplainer [8]
Top-10 Features
Note: 
the XX.XX values must be populated from the actual execution of train.py against the Drebin and CICMalDroid2020 datasets; they are not estimated or copied from another paper.
The static Random Forest branch is expected to provide a fast, permission/API-level assessment consistent with Drebin's reported 94% detection rate at a 1% false-positive rate [5], since the present model reuses the same feature representation. The dynamic branch adds behavioral evidence that static analysis cannot capture, such as runtime API call frequency, at the cost of the additional latency required for sandbox execution. Because the two branches are trained independently and fused only at the probability level, an error in one branch (e.g., a dynamic feature vector degraded by limited sandbox execution time) does not necessarily propagate into the other, which is the principal advantage of the weighted-fusion design over a single end-to-end classifier — consistent with the hybridization argument made in [1]–[3]. The hash/pattern signature layer further reduces false negatives for previously catalogued malware families by short-circuiting the ML pipeline whenever a confirmed match exists, while SHAP explanations [8] make the static model's reasoning auditable rather than a black box, which is particularly relevant for a security-critical decision such as malware classification.
6. Conclusion
This paper presented a Hybrid Intrusion Detection System for Android applications that combines signature-based detection, static Random Forest classification on Drebin features [5] extracted via Androguard [4], dynamic Random Forest classification on CICMalDroid2020 syscall-frequency features [6], weighted hybrid confidence fusion, threshold-based risk assessment, and SHAP-based explainability [8], following the hybrid deep-learning design philosophy established in [1]–[3].
An APK submitted to the system is first checked against a SHA-256/pattern signature database, then independently analyzed by static and dynamic Random Forest [7] classifiers whose probabilities are combined using equal weighting, with an automatic fallback to the static branch when dynamic sandbox analysis is unavailable. The resulting confidence is mapped to Safe, Low Risk, High Risk, or Critical categories, and a confirmed signature match overrides the fused verdict directly to Critical. The modular FastAPI/Next.js/Docker architecture keeps the machine-learning pipeline, sandbox, and application logic independently maintainable.
Future work will focus on populating the performance tables with results from the actual Drebin and CICMalDroid2020 training runs, replacing the sandbox mock with a full dynamic-analysis platform, expanding the signature database, exploring adaptive (rather than fixed 0.5/0.5) hybrid weighting as in the attention- and GWO-based hybrid IDS designs of [2] and [3], and evaluating the system against larger and more recent Android threat datasets.
References
[1] A. K. Samha, N. Malik, D. Sharma, S. Kavitha, and P. Dutta, Intrusion Detection System Using Hybrid Convolutional Neural Network. Cham, Switzerland: Springer, 2023.
[2] M. Chavan and D. Hanumanthappa, "Enhanced Hybrid Intrusion Detection System with Attention Mechanism using Deep Learning," SN Computer Science, vol. 5, no. 4, p. 285, May 2024, doi: 10.1007/s42979-024-02852-y.
[3] S. S. Prasad, R. K. Kumar, and V. Dev, "Hybrid Intrusion Detection Models Based on GWO Optimized Deep Learning," IEEE Transactions on Cybernetics and Network Security, vol. 11, no. 2, pp. 142–153, Apr. 2024.
[4] A. Desnos and G. Gueguen, "Androguard: Reverse Engineering and Malware Analysis of Android Applications," in Proc. Black Hat USA, Las Vegas, NV, USA, 2011, pp. 1–17.
[5] D. Arp, M. Spreitzenbarth, M. Hübner, H. Gascon, and K. Rieck, "Drebin: Effective and Explainable Detection of Android Malware in Your Pocket," in Proc. Network and Distributed System Security Symp. (NDSS), San Diego, CA, USA, 2014, pp. 1–15.
[6] S. Mahdavifar, A. F. A. Kadir, R. Fatemi, D. Alhadidi, and A. A. Ghorbani, "Dynamic Android Malware Category Classification using Semi-Supervised Deep Learning," in Proc. IEEE Int'l Conf. on Dependable, Autonomic and Secure Computing (DASC), 2020, pp. 515–522.
[7] L. Breiman, "Random Forests," Machine Learning, vol. 45, pp. 5–32, 2001.
[8] S. M. Lundberg and S.-I. Lee, "A Unified Approach to Interpreting Model Predictions," in Advances in Neural Information Processing Systems 30, 2017.
[9] Y. Aafer, W. Du, and H. Yin, "DroidAPIMiner: Mining API-Level Features for Robust Malware Detection in Android," in Proc. Int'l Conf. on Security and Privacy in Communication Networks, 2013.
[10] W. Enck, M. Ongtang, and P. McDaniel, "On Lightweight Mobile Phone Application Certification," in Proc. 16th ACM Conf. on Computer and Communications Security, 2009.
[11] Z. Wu, Y. Xu, and G. Wang, "A Lightweight Android Malware Detection Method Based on Static Analysis," in Proc. Int'l Conf. on Android Security Research, 2018.
[12] Android Developers, "Application Fundamentals," Google Android Developer Documentation, 2024.
[13] Android Developers, "Manifest Overview," Google Android Developer Documentation, 2024.
[14] M. Egele, T. Scholte, E. Kirda, and C. Kruegel, "A Survey on Automated Dynamic Malware-Analysis Techniques and Tools," ACM Computing Surveys, vol. 44, no. 2, 2012.
[15] S. Arzt et al., "FlowDroid: Precise Context, Flow, Field, Object-Sensitive and Lifecycle-Aware Taint Analysis for Android Apps," in Proc. ACM SIGPLAN Conf. on Programming Language Design and Implementation, 2014.
[16] M. Lindorfer, M. Neugschwandtner, and C. Platzer, "MARVIN: Efficient and Comprehensive Mobile App Classification Through Static and Dynamic Analysis," in Proc. IEEE Int'l Conf. on Software Testing, Verification and Validation, 2015.
[17] T. Bläsing, L. Batyuk, A.-D. Schmidt, H.-G. Schmidt, A. Camtepe, and S. Albayrak, "An Android Application Sandbox System for Suspicious Software Detection," in Proc. 5th Int'l Conf. on Malicious and Unwanted Software, 2010.