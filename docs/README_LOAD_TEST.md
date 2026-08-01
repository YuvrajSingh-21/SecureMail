# SecureMail Load Testing Framework Manual

## 1. Overview

The SecureMail load testing harness is built on Locust. It is designed to evaluate system throughput, latency percentiles, error rates, and resource utilization across various workloads while strictly enforcing SLA limits.

---

## 2. Installation & Prerequisites

Activate the virtual environment and install load testing dependencies:
```bash
source /home/lonewolf/Email_Phisher/email/bin/activate
pip install -r requirements-loadtest.txt
```

---

## 3. Test Execution Runbook (Phases 1 – 8)

### Phase 2: Public Pages Anonymous Traffic
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 5 --spawn-rate 5 --run-time 60s \
       --html reports/phase2_public_pages.html --csv reports/phase2_public_pages
```

### Phase 3: Authenticated Baseline Validation
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 5 --spawn-rate 5 --run-time 60s \
       --html reports/phase3_authenticated.html --csv reports/phase3_authenticated
```

### Phase 4: Email Forensics & Search Workload
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 20 --spawn-rate 5 --run-time 120s \
       --html reports/phase4_email_workflow.html --csv reports/phase4_email_workflow
```

### Phase 5: Attachment Security & PDF Forensics
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 20 --spawn-rate 5 --run-time 120s \
       --html reports/phase5_attachments.html --csv reports/phase5_attachments
```

### Phase 6: Mixed Heavy Enterprise Workload (50 Users)
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 50 --spawn-rate 5 --run-time 300s \
       --html reports/phase6_mixed_heavy.html --csv reports/phase6_mixed_heavy
```

### Phase 7: Dynamic Spike & Auto-Recovery Test (10 Min)
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --html reports/phase7_spike_recovery.html --csv reports/phase7_spike_recovery
```

### Phase 8: Production Endurance Soak Test (30 Min)
```bash
locust -f locustfile.py --headless --host http://127.0.0.1:8000 \
       --users 50 --spawn-rate 5 --run-time 1800s \
       --html reports/phase8_endurance_soak.html --csv reports/phase8_endurance_soak
```

---

## 4. Expected Output & SLA Gates

- **Target P95 Latency**: $\le 500\text{ ms}$
- **Target Error Rate**: $\le 1.0\%$
- **Generated Reports**:
  - HTML Dashboard: `reports/phaseX_*.html`
  - CSV Statistics: `reports/phaseX_*_stats.csv`
  - JSON Summary: `reports/phaseX_summary.json`
