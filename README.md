# **Lunaris Sentient Core - Version 1.6 Beta**

**Lunaris Sentient Core** is an advanced AI-driven cybersecurity system designed to detect malware and perform detailed file analysis. In this 1.6 Beta release, several improvements have been implemented, focusing on enhanced user experience, performance, and professional logs.

## 🌟 **What's New in Version 1.6 Beta**

### **1. New Web Interface**
- A modern and user-friendly interface for **uploading files** and **malware analysis**.
- Users can submit files directly through the interface, and Lunaris will process and return the analysis result in real-time.

### **2. Automatic Model Download System**
- Lunaris now includes the ability to **automatically download pre-trained models** directly from our GitHub repository. 
- This allows users to keep Lunaris up-to-date with the latest AI models without needing to manually configure anything.

### **3. Bug Fixes and Improvements**
- **Improved logic and performance** throughout the codebase, delivering a smoother and more error-resistant experience.
- **Enhanced neural network** for better malware detection, with faster training times and increased accuracy.

### **4. Organized Folder Structure and Professional Logs**
- The logging system has been **completely redesigned** to provide a **professional and organized view** of activities in Lunaris' terminal.
- **Progress bars** and clean visual messages have been added to make processes like model downloads and AI training more transparent.

---

## 🎯 **Key Features of Lunaris**

- **Malware Detection**: Upload files through the web interface and get real-time analysis results on whether the file contains malware.
- **Training System**: Train the AI model locally using your own data by adding files to designated folders for malware and non-malware data.
- **Model Downloads**: Automatically fetch the latest pre-trained models from GitHub with a simple command.
- **Professional Logs**: Follow Lunaris' activities with detailed and visually appealing logs in the terminal, including progress bars for ongoing tasks.

---

## 🚀 **How to Use**

1. **Install Dependencies**:
   Ensure you have Python and all necessary libraries installed.
   ```bash
   pip install -r requirements.txt
   ```

2. **Train the Model Locally**:
   Add non-malware files to the `training_files/0` folder and malware-related files to the `training_files/amas_reports`. Lunaris will automatically train the model if new files are detected.

3. **Run Lunaris**:
   Start Lunaris and follow the terminal prompts to sync pre-trained models or train locally.
   ```bash
   python3 main.py
   ```

4. **Access the Web Interface**:
   You can access the web interface by visiting:
   ```bash
   http://localhost:5000
   ```

---

## 🔧 **Technologies Used**

- **Python**: Primary language for the neural network and web interface.
- **TensorFlow**: Used for building and training AI models.
- **TensorBoard**: For monitoring training progress and neural network structure.
- **HTML/CSS/JavaScript**: For the web interface.
- **Rich**: For interactive and visually appealing logs in the terminal.

---

## 📢 **Contributing**

Lunaris Sentient Core is an open-source project, and contributions are welcome! If you have any ideas, suggestions, or bug reports, feel free to open an issue or submit a pull request.

---

## 📬 **Contact**

For any questions or feedback, feel free to reach out to us at: **support@mooncloudservices.tech**

---

Thank you for using **Lunaris Sentient Core**! We're committed to continuously improving the project to offer an even more robust and efficient cybersecurity solution.
