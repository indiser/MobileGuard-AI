import os
import csv
import json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

from backend.pipeline.orchestrator import PipelineOrchestrator
from metrics import calculate_metrics

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EVAL_DIR = Path("evaluation")
BENIGN_DIR = EVAL_DIR / "benign"
MALWARE_DIR = EVAL_DIR / "malware"

OUTPUT_CSV = EVAL_DIR / "benchmark_results.csv"
OUTPUT_JSON = EVAL_DIR / "metrics.json"
ERROR_LOG = EVAL_DIR / "benchmark_errors.log"

# Set this to 3-5 to parallelize ADB and LLM waits. 
# Do not set it too high or you will crash your emulator / hit LLM rate limits.
MAX_WORKERS = 4 

# Setup isolated logging for the benchmark
logging.basicConfig(
    filename=str(ERROR_LOG),
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def collect_apks():
    samples = []
    if BENIGN_DIR.exists():
        for file in BENIGN_DIR.glob("*.apk"):
            samples.append((str(file), 0))
            
    if MALWARE_DIR.exists():
        for file in MALWARE_DIR.glob("*.apk"):
            samples.append((str(file), 1))
            
    return samples

def get_processed_apks() -> set:
    """Read the CSV to find out which APKs we already processed. Enables safe resuming."""
    if not OUTPUT_CSV.exists():
        return set()
    
    processed = set()
    try:
        with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                processed.add(row["apk_name"])
    except Exception:
        pass
    return processed

def analyze_single_apk(apk_path: str, label: int):
    """Worker function to process a single APK"""
    filename = os.path.basename(apk_path)
    
    # We instantiate a new orchestrator per thread to avoid state leakage, 
    # but the ML model and FeatureStore will use their own internal caching.
    orchestrator = PipelineOrchestrator()
    
    try:
        with open(apk_path, "rb") as f:
            apk_bytes = f.read()

        result = None
        for event in orchestrator.analyze(apk_bytes, filename):
            if event.stage == "error":
                raise Exception(event.error)
            if event.stage == "complete" and event.result:
                result = event.result

        if result is None:
            raise Exception("Pipeline completed but returned no result.")

        # Safely extract scores
        probability = result.score.get("xgb_probability", result.score.get("ml_score", 0.0) / 100.0)
        risk_score = result.score.get("composite_score", 0)
        prediction = 1 if risk_score >= 50 else 0

        row = {
            "apk_name": filename,
            "actual_label": label,
            "prediction": prediction,
            "probability": round(probability, 4),
            "risk_score": risk_score,
            "confidence": result.confidence_score,
            "family": result.family.get("family", "Unknown"),
            "action": result.score.get("action", "UNKNOWN"),
            "error": ""
        }
        return row

    except Exception as e:
        error_trace = traceback.format_exc()
        logging.error(f"Failed on {filename}:\n{error_trace}")
        
        # Return a failure row so we don't infinitely retry broken APKs
        return {
            "apk_name": filename,
            "actual_label": label,
            "prediction": -1,
            "probability": 0.0,
            "risk_score": 0.0,
            "confidence": 0.0,
            "family": "ERROR",
            "action": "ERROR",
            "error": str(e)[:100] # Log short error in CSV
        }

def run_benchmark():
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    
    samples = collect_apks()
    if not samples:
        print("No APKs found in evaluation directories.")
        return

    processed_apks = get_processed_apks()
    pending_samples = [s for s in samples if os.path.basename(s[0]) not in processed_apks]
    
    print(f"\nTotal APKs: {len(samples)}")
    print(f"Already processed: {len(processed_apks)}")
    print(f"Pending analysis: {len(pending_samples)}\n")

    if pending_samples:
        file_exists = OUTPUT_CSV.exists()
        fieldnames = ["apk_name", "actual_label", "prediction", "probability", "risk_score", "confidence", "family", "action", "error"]
        
        # Open CSV in APPEND mode
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()

            # Parallel execution with progress bar
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Submit all tasks
                future_to_apk = {executor.submit(analyze_single_apk, path, label): path for path, label in pending_samples}
                
                with tqdm(total=len(pending_samples), desc="Scanning APKs", unit="apk") as pbar:
                    for future in as_completed(future_to_apk):
                        try:
                            row_result = future.result()
                            writer.writerow(row_result)
                            f.flush() # Force write to disk immediately
                        except Exception as exc:
                            # This catches catastrophic thread failures
                            logging.error(f"Thread exception: {exc}")
                        finally:
                            pbar.update(1)

    # ---------------------------------------------------------
    # Recalculate Metrics from the complete CSV
    # ---------------------------------------------------------
    print("\nCalculating metrics from complete dataset...")
    y_true, y_pred, y_prob = [], [], []
    
    with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["prediction"] == "-1":
                continue # Skip errors
            y_true.append(int(row["actual_label"]))
            y_pred.append(int(row["prediction"]))
            y_prob.append(float(row["probability"]))

    if not y_true:
        print("No valid results to score.")
        return

    metrics = calculate_metrics(y_true, y_pred, y_prob)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    print("\n==================================")
    print("      BENCHMARK RESULTS")
    print("==================================")
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"{k.ljust(25)}: {v:.4f}")
        else:
            print(f"{k.ljust(25)}: {v}")
    print("==================================\n")

if __name__ == "__main__":
    # Ensure warnings don't clutter the progress bar
    import warnings
    warnings.filterwarnings("ignore")
    run_benchmark()