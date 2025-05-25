🧬 Medical Image Encryption Using ECC and Chaotic Systems
🔒 Overview
This project focuses on the secure encryption of medical images using a hybrid cryptographic approach that combines the Elliptic Curve Cryptosystem (ECC) with chaotic sequence generation. It ensures high levels of confidentiality, security, and integrity for sensitive healthcare data.

🧠 Motivation
Medical images contain critical diagnostic information and must be protected during storage and transmission. Traditional methods fall short in offering both speed and robust security. Our method addresses this by:

Ensuring multi-level encryption

Preserving image integrity

Resisting common attacks

🔧 Technologies Used
Python 3.10+

NumPy

OpenCV

Matplotlib

Random

Chaotic Logistic Map Generator

ECC (Elliptic Curve Cryptography)

Entropy / NPCR / UACI Calculation for Evaluation

🔐 Key Features
📈 High Security: Combines ECC with chaotic sequence for pixel-level encryption

🧮 Efficient Performance: Optimized for speed and memory

🔁 Multi-layer Protection: Prevents statistical and brute-force attacks

🧪 Security Evaluation Metrics:

Entropy (measures randomness)

NPCR (Number of Pixel Change Rate)

UACI (Unified Average Changing Intensity)

📂 Project Structure
bash
Copy
Edit
MedicalImageEncryption/
├── med/
│   ├── encryption.py
│   ├── decryption.py
│   ├── ecc_module.py
│   └── chaos_sequence.py
├── input_images/
├── output_images/
├── requirements.txt
└── README.md
