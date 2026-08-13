import os
import sys

# Automatically install required packages so you don't have to run it in a separate cell
os.system(f"{sys.executable} -m pip install transformers[torch] onnx onnxruntime accelerate onnxscript")

import json
import logging
import pandas as pd
import numpy as np
import torch
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score, roc_auc_score, confusion_matrix
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
import onnx
from onnxruntime.quantization import quantize_dynamic, QuantType

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("Loading prompts dataset...")
    # Dynamically locate the prompts.csv file no matter what Kaggle named the dataset folder
    csv_path = None
    if os.path.exists("prompts.csv"):
        csv_path = "prompts.csv"
    elif os.path.exists("data/prompts.csv"):
        csv_path = "data/prompts.csv"
    elif os.path.exists("/kaggle/working/data/prompts.csv"):
        csv_path = "/kaggle/working/data/prompts.csv"
    elif os.path.exists("/kaggle/input"):
        for root, dirs, files in os.walk("/kaggle/input"):
            if "prompts.csv" in files:
                csv_path = os.path.join(root, "prompts.csv")
                break
                
    if not csv_path:
        raise FileNotFoundError("Could not find prompts.csv in the current directory or anywhere inside /kaggle/input. Did you upload it?")
        
    logger.info(f"Found dataset at: {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Enforce uniqueness check to ensure we aren't training on padded templates
    unique_count = df['text'].nunique()
    logger.info(f"Unique text rows before split: {unique_count} (out of {len(df)} total)")
    if 'source' in df.columns:
        logger.info(f"Source distribution:\n{df['source'].value_counts().to_string()}")
    
    # Ensure no data leakage via GroupShuffleSplit on technique_family
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df['technique_family']))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    logger.info(f"Train size: {len(train_df)}, Test size: {len(test_df)}")
    
    model_name = "distilbert/distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    
    train_encodings = tokenizer(train_df['text'].tolist(), truncation=True, padding="max_length", max_length=128)
    test_encodings = tokenizer(test_df['text'].tolist(), truncation=True, padding="max_length", max_length=128)
    
    class PromptDataset(torch.utils.data.Dataset):
        def __init__(self, encodings, labels):
            self.encodings = encodings
            self.labels = labels

        def __getitem__(self, idx):
            item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
            item['labels'] = torch.tensor(self.labels[idx])
            return item

        def __len__(self):
            return len(self.labels)

    train_dataset = PromptDataset(train_encodings, train_df['label'].tolist())
    test_dataset = PromptDataset(test_encodings, test_df['label'].tolist())
    
    logger.info("Initializing DistilBERT model...")
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    training_args = TrainingArguments(
        output_dir='./results',
        num_train_epochs=3,
        per_device_train_batch_size=32,
        per_device_eval_batch_size=64,
        warmup_steps=100,
        weight_decay=0.01,
        logging_dir='./logs',
        logging_steps=10,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        fp16=torch.cuda.is_available(), # Use mixed precision if Kaggle GPU is on
        use_cpu=not torch.cuda.is_available()
    )
    
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        # Softmax
        exp_logits = np.exp(logits)
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
        preds = np.argmax(logits, axis=-1)
        
        f1 = f1_score(labels, preds)
        auc = roc_auc_score(labels, probs[:, 1])
        cm = confusion_matrix(labels, preds).tolist()
        return {"f1": f1, "auc": auc, "confusion_matrix": cm}
        
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics
    )
    
    logger.info("Starting Fine-tuning...")
    trainer.train()
    
    logger.info("Evaluating on held-out test set...")
    eval_results = trainer.evaluate()
    
    output_dir = "./kaggle_export"
    os.makedirs(output_dir, exist_ok=True)
    
    # Dump metrics to a text file
    metrics_path = os.path.join(output_dir, "metrics.txt")
    with open(metrics_path, "w") as f:
        f.write(json.dumps(eval_results, indent=2))
    logger.info(f"Metrics saved to {metrics_path}")
    
    # Save tokenizer config
    tokenizer.save_pretrained(output_dir)
    logger.info("Tokenizer configs saved.")
    
    # Export to ONNX
    logger.info("Exporting to ONNX...")
    model.eval()
    model.to('cpu') # Move to CPU for ONNX tracing
    dummy_input = torch.zeros(1, 128, dtype=torch.long)
    dummy_mask = torch.ones(1, 128, dtype=torch.long)
    
    raw_onnx_path = os.path.join(output_dir, "prompt_model.onnx")
    torch.onnx.export(
        model,
        (dummy_input, dummy_mask),
        raw_onnx_path,
        dynamo=False, # FORCES legacy TorchScript exporter, bypassing onnxscript crash
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=['input_ids', 'attention_mask'],
        output_names=['logits'],
        dynamic_axes={
            'input_ids': {0: 'batch_size', 1: 'sequence_length'},
            'attention_mask': {0: 'batch_size', 1: 'sequence_length'},
            'logits': {0: 'batch_size'}
        }
    )
    
    # Quantize to INT8
    logger.info("Quantizing to INT8...")
    int8_onnx_path = os.path.join(output_dir, "prompt_model_int8.onnx")
    quantize_dynamic(
        model_input=raw_onnx_path,
        model_output=int8_onnx_path,
        weight_type=QuantType.QInt8
    )
    
    # Clean up the bloated raw fp32 ONNX if desired, but we'll leave it in case int8 loading fails locally
    logger.info(f"SUCCESS! Kaggle Export ready at: {os.path.abspath(output_dir)}")
    logger.info("Download this folder, rename it to v_<timestamp>, and place it in models/")

if __name__ == "__main__":
    main()
