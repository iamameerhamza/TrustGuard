# TrustGuard Kaggle Exporter

Due to network constraints blocking Large File Storage (LFS) CDNs in the local environment, this directory contains everything needed to fine-tune the true `distilbert-base-uncased` model natively on Kaggle's free GPU compute.

### Instructions for Kaggle:

1. **Create a New Notebook** on Kaggle.
2. **Turn on the Internet and GPU** in the notebook settings (Session Options -> Accelerator -> GPU P100 / T4 x2).
3. **Upload the Dataset**:
   - In the right sidebar, click **"Add Data"** -> **"Upload"**.
   - Upload `prompts.csv` from this folder.
   - Name the dataset `trustguard-prompts`.
4. **Install Dependencies**:
   Create a cell and run:
   ```bash
   !pip install transformers[torch] onnx onnxruntime
   ```
5. **Upload the Script**:
   - Upload `train_distilbert.py` into your Kaggle workspace (or simply paste its entire contents into a cell).
6. **Execute**:
   ```bash
   !python train_distilbert.py
   ```
7. **Download the Weights**:
   - Once it finishes, look at the Kaggle "Output" directory (`/kaggle/working/kaggle_export`).
   - Download the entire `kaggle_export` folder (which includes `prompt_model.onnx`, `prompt_model_int8.onnx`, `metrics.txt`, and the tokenizer JSONs).

### Bring it Back Local:

Once downloaded locally:
1. Rename the `kaggle_export` folder to `v_<timestamp>` (e.g. `v_1720001111`).
2. Drop it into `models/`.
3. Update `models/prompt_active_version.txt` and `models/prompt_candidate_version.txt` to point to the new folder name.
4. The FastAPI watchdog will hot-reload it instantly. 

You can then run the verification tests locally to see the real DistilBERT qualitative results and latency numbers!
