# # 🖥️ AI Infrastructure Monitoring System

A simplified, production-ready AI-powered infrastructure monitoring dashboard built with Streamlit. Features real-time monitoring, anomaly detection, alert management, and predictive analytics.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.29.0-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- **📊 Real-time Dashboard** - Monitor infrastructure health at a glance
- **🖥️ Host Inventory** - Track and manage all your hosts
- **⚠️ Smart Alerts** - Automated alert generation based on thresholds
- **🔍 AI Anomaly Detection** - Machine learning powered anomaly detection using Isolation Forest
- **📈 Predictive Analytics** - Trend analysis and failure predictions
- **📁 Data Import/Export** - Support for CSV uploads and data exports
- **🎨 Modern UI** - Clean, responsive interface with interactive charts

## 🚀 Quick Start

### Option 1: Deploy on Streamlit Cloud (Easiest)

1. Fork this repository to your GitHub account
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click "New app"
4. Connect your GitHub repository
5. Set the main file path to `app.py`
6. Click "Deploy"

Your app will be live in minutes at `https://[your-app-name].streamlit.app`

### Option 2: Deploy on Railway

1. Fork this repository
2. Sign in to [Railway](https://railway.app)
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your forked repository
5. Railway will auto-detect and deploy the app
6. Your app will be available at the provided Railway URL

### Option 3: Run Locally

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-infra-monitor.git
cd ai-infra-monitor

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py

# Open browser to http://localhost:8501
```

## 📁 Project Structure

```
ai-infra-monitor/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── README.md          # Documentation
├── .gitignore         # Git ignore file
└── data/              # Sample data directory (optional)
    └── sample_hosts.csv
```

## 🎯 Usage

### Getting Started

1. **Launch the app** using any deployment method above
2. **Generate sample data** by clicking "🔄 Generate Sample Data" in the sidebar
3. **Or upload your own data** using the CSV uploader in the sidebar

### CSV Format

Your CSV should have these columns:
```csv
hostname,ip_address,os_distribution,falcon_status,owner_name,owner_email
host-001,10.0.0.1,Ubuntu 22.04,Healthy,John Doe,john@example.com
```

Optional columns (will be auto-generated if missing):
- `cpu_usage`, `memory_usage`, `disk_usage`
- `falcon_version`, `is_reachable`, `last_seen`

### Features Guide

#### 📊 Dashboard
- View key metrics and system health
- Monitor resource usage heatmaps
- Track host status distribution

#### 🖥️ Host Inventory
- Search and filter hosts
- View detailed host information
- Export host data

#### ⚠️ Alerts
- View active alerts by severity
- Acknowledge and manage alerts
- Real-time alert generation

#### 🔍 Anomaly Detection
- AI-powered anomaly detection
- Anomaly score visualization
- Detailed anomaly investigation

#### 📈 Analytics
- 24-hour trend analysis
- Failure predictions
- Optimization recommendations

## 🛠️ Configuration

### Environment Variables (Optional)

Create a `.env` file for configuration:

```env
# Streamlit Configuration
STREAMLIT_THEME_PRIMARY_COLOR="#667eea"
STREAMLIT_THEME_BACKGROUND_COLOR="#ffffff"

# Alert Thresholds
CPU_ALERT_THRESHOLD=90
MEMORY_ALERT_THRESHOLD=80
DISK_ALERT_THRESHOLD=85

# Anomaly Detection
ANOMALY_CONTAMINATION=0.1
```

## 📦 Deployment Configuration Files

### For Streamlit Cloud

No additional configuration needed! Just ensure `requirements.txt` is in the root directory.

### For Railway

Create a `railway.json` (optional):
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "streamlit run app.py --server.port=$PORT --server.address=0.0.0.0"
  }
}
```

### For Heroku

Create a `Procfile`:
```
web: sh setup.sh && streamlit run app.py
```

Create `setup.sh`:
```bash
mkdir -p ~/.streamlit/
echo "\
[server]\n\
port = $PORT\n\
enableCORS = false\n\
headless = true\n\
\n\
" > ~/.streamlit/config.toml
```

## 🔧 Customization

### Adding New Metrics

Edit the `generate_sample_data()` function in `app.py`:

```python
def generate_sample_data(n_hosts=50):
    # Add your custom metrics here
    data.append({
        'hostname': f'host-{i:03d}',
        'your_metric': random.uniform(0, 100),
        # ... more metrics
    })
```

### Modifying Alert Thresholds

Adjust thresholds in the Settings page or modify the `generate_alerts()` function:

```python
def generate_alerts(df):
    if host['cpu_usage'] > 90:  # Change threshold here
        alerts.append({...})
```

### Custom Anomaly Detection

Modify the `detect_anomalies()` function to use different algorithms:

```python
from sklearn.ensemble import RandomForestClassifier
# Replace IsolationForest with your preferred algorithm
```

## 📊 Sample Data Generator

The app includes a built-in sample data generator that creates:
- 50 mock hosts with random metrics
- Various OS distributions
- Random resource usage patterns
- Falcon agent status
- Owner information

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Read this README
- **Issues**: Open an issue on GitHub
- **Discussions**: Start a discussion on GitHub

## 🎉 Acknowledgments

- Built with [Streamlit](https://streamlit.io)
- Charts powered by [Plotly](https://plotly.com)
- ML algorithms from [scikit-learn](https://scikit-learn.org)

## 🚦 System Requirements

- Python 3.8 or higher
- 512MB RAM minimum (1GB recommended)
- Modern web browser

## 🔄 Updates

- **v1.0.0** - Initial release with core monitoring features
- Real-time monitoring dashboard
- AI-powered anomaly detection
- Alert management system
- Data import/export functionality

---

**Ready to deploy?** Choose your platform above and get monitoring in minutes! 🚀
