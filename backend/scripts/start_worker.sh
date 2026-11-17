#!/bin/bash
# Start NLP server in background, wait for it, then start Celery worker

python scripts/nlp_server.py &
echo "Waiting for NLP server to load model..."

for i in $(seq 1 120); do
    if python -c "
import urllib.request, json
try:
    r = urllib.request.urlopen('http://127.0.0.1:5062/health', timeout=3)
    d = json.loads(r.read())
    exit(0 if d.get('model_loaded') else 1)
except:
    exit(1)
" 2>/dev/null; then
        echo "NLP server ready"
        break
    fi
    sleep 5
done

exec celery -A app.tasks.celery_app:celery_app worker --loglevel=info
