import os
from huggingface_hub import snapshot_download

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
print("Downloading distilbert/distilbert-base-uncased from HF mirror...")
snapshot_download("distilbert/distilbert-base-uncased")
print("Download complete.")
