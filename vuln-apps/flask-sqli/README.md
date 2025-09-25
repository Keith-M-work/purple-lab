# Flask SQLi Vulnerable App

## ⚠️ WARNING
This is an intentionally vulnerable application for security testing.
DO NOT deploy to production or expose to the internet!

## Usage
```bash
docker build -t flask-vuln .
docker run -p 127.0.0.1:5000:5000 flask-vuln
```

## Testing
Try payload: `' OR '1'='1`

## Detection
See `../../detections/sigma/2-intermediate/web_sqli.yml`
