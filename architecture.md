.
├── .agent
│   └── skills
│       └── best_ui
│           └── SKILL.md
├── .dockerignore
├── .env
├── .gitignore
├── .vscode
│   └── tasks.json
├── Dockerfile.backend
├── Dockerfile.frontend
├── Readme.md
├── architecture.md
├── backend
│   ├── __init__.py
│   ├── config.py
│   ├── data
│   │   ├── __init__.py
│   │   ├── audit_logger.py
│   │   ├── feature_store.py
│   │   ├── threat_intel.py
│   │   └── vt_cache.json
│   ├── dataset_feature_extractor.py
│   ├── detection
│   │   ├── yara_engine.py
│   │   └── yara_rules
│   │       ├── banking_trojan.yar
│   │       ├── rat.yar
│   │       ├── sms_fraud.yar
│   │       └── spyware.yar
│   ├── intel
│   │   ├── family_classifier.py
│   │   └── mitre_mapper.py
│   ├── main.py
│   ├── models
│   │   ├── .gitkeep
│   │   ├── feature_columns.json
│   │   ├── model_metrics.json
│   │   ├── scaler.pkl
│   │   ├── shap_feature_importance.png
│   │   └── xgboost_mobileguard.json
│   ├── pipeline
│   │   ├── __init__.py
│   │   ├── behavior_scorer.py
│   │   ├── confidence_engine.py
│   │   ├── dynamic_analyzer.py
│   │   ├── event_mapper.py
│   │   ├── evidence_engine.py
│   │   ├── llm_analyzer.py
│   │   ├── orchestrator.py
│   │   ├── report_generator.py
│   │   ├── resilient_router.py
│   │   ├── risk_scorer.py
│   │   ├── runtime_collectors.py
│   │   ├── runtime_events.py
│   │   └── static_analyzer.py
│   ├── plugins
│   │   ├── __init__.py
│   │   ├── custom_detectors
│   │   │   ├── banking_detectors.py
│   │   │   ├── cerberus_detector.py
│   │   │   ├── hydra_detector.py
│   │   │   ├── ransomware_detector.py
│   │   │   ├── sample_plugin.py
│   │   │   ├── spyware_detector.py
│   │   │   └── telegram_stealer.py
│   │   ├── plugin_base.py
│   │   └── plugin_manager.py
│   ├── requirements.txt
│   ├── tests
│   │   ├── test_api.py
│   │   ├── test_scorer.py
│   │   └── test_static.py
│   └── training
│       ├── __init__.py
│       ├── evaluate.py
│       ├── feature_engineering.py
│       └── train_xgboost.py
├── dataset
│   └── malware_dataset.csv
├── docker-compose.yml
├── evaluation
│   ├── benchmark_runner.py
│   ├── benign
│   │   ├── F-Droid.apk
│   │   ├── app.pwhs.blockads_50.apk
│   │   ├── ch.protonvpn.android_605187501.apk
│   │   ├── com.best.deskclock_2034.apk
│   │   ├── com.newoether.agora_24.apk
│   │   ├── com.yosefario.nclientv3_423.apk
│   │   ├── edge.roll_4.apk
│   │   └── org.lichess.mobileV2_240603.apk
│   ├── malware
│   ├── metrics.py
│   └── reports
│       ├── csv_exporter.py
│       └── pdf_exporter.py
├── frontend
│   ├── .gitignore
│   ├── README.md
│   ├── eslint.config.js
│   ├── index.html
│   ├── package-lock.json
│   ├── package.json
│   ├── postcss.config.js
│   ├── public
│   │   ├── android-chrome-192x192.png
│   │   ├── android-chrome-512x512.png
│   │   ├── apple-touch-icon.png
│   │   ├── favicon-16x16.png
│   │   ├── favicon-32x32.png
│   │   ├── favicon.ico
│   │   ├── icons.svg
│   │   └── site.webmanifest
│   ├── src
│   │   ├── App.jsx
│   │   ├── api
│   │   │   └── client.js
│   │   ├── assets
│   │   │   ├── hero.png
│   │   │   ├── react.svg
│   │   │   └── vite.svg
│   │   ├── components
│   │   │   ├── ActionBanner.jsx
│   │   │   ├── AuditLog.jsx
│   │   │   ├── DimensionChart.jsx
│   │   │   ├── ProgressTracker.jsx
│   │   │   ├── RiskGauge.jsx
│   │   │   ├── ShapExplainer.jsx
│   │   │   ├── ThreatReport.jsx
│   │   │   ├── UploadZone.jsx
│   │   │   └── tabs
│   │   ├── index.css
│   │   ├── main.jsx
│   │   └── utils
│   ├── tailwind.config.js
│   └── vite.config.js
├── get_structure_wsl.txt
├── nginx.conf
└── test.apk

29 directories, 112 files
