import os
import sys
import datetime
import logging
import pandas as pd
import numpy as np
import torch
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score, roc_auc_score
from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
import onnx
from onnxruntime.quantization import quantize_dynamic, QuantType

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    
    # Softmax for AUC
    exp_logits = np.exp(logits)
    probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
    prob_class_1 = probs[:, 1]
    
    f1 = f1_score(labels, preds)
    auc = roc_auc_score(labels, prob_class_1)
    return {"f1": f1, "auc": auc}

def main():
    logger.info("Loading prompts dataset...")
    df = pd.read_csv("data/prompts.csv")
    logger.info(f"Unique text rows before split: {df['text'].nunique()}")
    
    # GroupShuffleSplit on technique_family to prevent leakage
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df['technique_family']))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    logger.info(f"Train size: {len(train_df)}, Test size: {len(test_df)}")
    
    model_name = "prajjwal1/bert-tiny"
    # Using distilbert tokenizer since tiny lacks the fast tokenizer.json but shares the exact vocab
    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased", use_fast=True)
    
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
    
    logger.info("Initializing BERT model...")
    from transformers import BertForSequenceClassification
    model = BertForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    training_args = TrainingArguments(
        output_dir='./.tmp/results',
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=64,
        warmup_steps=50,
        weight_decay=0.01,
        logging_dir='./.tmp/logs',
        logging_steps=10,
        eval_strategy="epoch",
        use_cpu=True # Running on CPU explicitly for this environment
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics
    )
    
    logger.info("Starting Fine-tuning (1 Epoch)...")
    trainer.train()
    
    eval_results = trainer.evaluate()
    logger.info(f"--- Eval Metrics ---")
    logger.info(f"F1 Score: {eval_results.get('eval_f1', 0):.4f}")
    logger.info(f"ROC-AUC: {eval_results.get('eval_auc', 0):.4f}")
    
    # ── ONNX Export ──
    version = f"v_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    model_dir = os.path.join("models", version)
    os.makedirs(model_dir, exist_ok=True)
    
    logger.info("Exporting to ONNX format...")
    onnx_path = os.path.join(model_dir, "prompt_model.onnx")
    quantized_onnx_path = os.path.join(model_dir, "prompt_model_int8.onnx")
    
    model.eval()
    # Dummy input with static shape to fix ONNX quantization issues on Windows
    dummy_input = tokenizer("dummy text", return_tensors="pt", padding="max_length", max_length=128, truncation=True)
    
    torch.onnx.export(
        model, 
        (dummy_input['input_ids'], dummy_input['attention_mask']),
        onnx_path,
        dynamo=False,
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=['input_ids', 'attention_mask'],
        output_names=['logits']
        # dynamic_axes removed to enforce static shapes and fix ONNX inference bugs
    )
    
    # ── INT8 Quantization ──
    logger.info("Applying Int8 Quantization to ONNX model...")
    quantize_dynamic(
        model_input=onnx_path,
        model_output=quantized_onnx_path,
        weight_type=QuantType.QUInt8
    )
    logger.info(f"Quantized model saved to {quantized_onnx_path}")
    
    if os.path.exists(onnx_path):
        os.remove(onnx_path)
        
    candidate_pointer = "models/prompt_candidate_version.txt"
    candidate_tmp = "models/prompt_candidate_version.tmp"
    with open(candidate_tmp, "w") as f:
        f.write(version)
    os.replace(candidate_tmp, candidate_pointer)
    
    active_pointer = "models/prompt_active_version.txt"
    if not os.path.exists(active_pointer):
        active_tmp = "models/prompt_active_version.tmp"
        with open(active_tmp, "w") as f:
            f.write(version)
        os.replace(active_tmp, active_pointer)
        logger.info(f"No active pointer found. Model automatically promoted to active: {version}")
    else:
        logger.info(f"Model saved as CANARY. Pointer updated at {candidate_pointer}")
        
    logger.info("Prompt model training pipeline complete!")

if __name__ == "__main__":
    main()
