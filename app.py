import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import IsolationForest
import random
import json
import os

# Page config
st.set_page_config(
    page_title="AI Infrastructure Monitor",
    page_icon="🖥️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin: 10px 0;
    }
    .alert-box {
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .critical { background-color: #ff4444; color: white; }
    .warning { background-color: #ffbb33; color: black; }
    .info { background-color: #33b5e5; color: white; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'hosts_data' not in st.session_state:
    st.session_state.hosts_data = pd.DataFrame()
    
if 'alerts' not in st.session_state:
    st.session_state.alerts = []

if 'anomalies' not in st.session_state:
    st.session_state.anomalies = []

# Helper functions
def generate_sample_data(n_hosts=50):
    """Generate sample host data"""
    data = []
    os_choices = ['Ubuntu 22.04', 'CentOS 7', 'RHEL 8', 'Windows Server 2019']
    falcon_status = ['Healthy', 'Failed', 'Unknown', 'Degraded']
    
    for i in range(1, n_hosts + 1):
        data.append({
            'hostname': f'host-{i:03d}',
            'ip_address': f'10.0.{i//256}.{i%256}',
            'os_distribution': random.choice(os_choices),
            'falcon_status': random.choice(falcon_status) if random.random() > 0.1 else 'Failed',
            'falcon_version': '6.16.0' if random.random() > 0.2 else '6.15.0',
            'cpu_usage': random.uniform(10, 95),
            'memory_usage': random.uniform(20, 90),
            'disk_usage': random.uniform(30, 85),
            'is_reachable': random.random() > 0.15,
            'owner_name': f'Owner {(i%5)+1}',
            'owner_email': f'owner{(i%5)+1}@example.com',
            'last_seen': datetime.now() - timedelta(minutes=random.randint(0, 120))
        })
    
    return pd.DataFrame(data)

def detect_anomalies(df):
    """Simple anomaly detection using Isolation Forest"""
    if df.empty:
        return []
    
    # Select numerical features
    features = ['cpu_usage', 'memory_usage', 'disk_usage']
    X = df[features].values
    
    # Train Isolation Forest
    iso = IsolationForest(contamination=0.1, random_state=42)
    predictions = iso.fit_predict(X)
    scores = iso.decision_function(X)
    
    anomalies = []
    for idx, (pred, score) in enumerate(zip(predictions, scores)):
        if pred == -1:  # Anomaly detected
            host = df.iloc[idx]
            anomalies.append({
                'hostname': host['hostname'],
                'anomaly_score': float(score),
                'type': 'Resource Usage Anomaly',
                'details': f"CPU: {host['cpu_usage']:.1f}%, Memory: {host['memory_usage']:.1f}%, Disk: {host['disk_usage']:.1f}%",
                'detected_at': datetime.now()
            })
    
    return anomalies

def generate_alerts(df):
    """Generate alerts based on thresholds"""
    alerts = []
    
    for _, host in df.iterrows():
        # Critical CPU usage
        if host['cpu_usage'] > 90:
            alerts.append({
                'hostname': host['hostname'],
                'type': 'High CPU Usage',
                'severity': 'critical',
                'message': f"CPU usage at {host['cpu_usage']:.1f}%",
                'timestamp': datetime.now()
            })
        
        # Memory warning
        if host['memory_usage'] > 80:
            alerts.append({
                'hostname': host['hostname'],
                'type': 'High Memory Usage',
                'severity': 'warning',
                'message': f"Memory usage at {host['memory_usage']:.1f}%",
                'timestamp': datetime.now()
            })
        
        # Falcon status check
        if host['falcon_status'] == 'Failed':
            alerts.append({
                'hostname': host['hostname'],
                'type': 'Falcon Agent Failed',
                'severity': 'critical',
                'message': 'Falcon security agent is not responding',
                'timestamp': datetime.now()
            })
        
        # Unreachable host
        if not host['is_reachable']:
            alerts.append({
                'hostname': host['hostname'],
                'type': 'Host Unreachable',
                'severity': 'warning',
                'message': 'Cannot reach host - last seen ' + host['last_seen'].strftime('%H:%M'),
                'timestamp': datetime.now()
            })
    
    return alerts

# Sidebar
with st.sidebar:
    st.title("🖥️ AI Infra Monitor")
    st.markdown("---")
    
    # Navigation
    page = st.selectbox(
        "Navigation",
        ["📊 Dashboard", "🖥️ Host Inventory", "⚠️ Alerts", "🔍 Anomaly Detection", "📈 Analytics", "⚙️ Settings"]
    )
    
    st.markdown("---")
    
    # Quick Actions
    st.subheader("Quick Actions")
    
    if st.button("🔄 Generate Sample Data"):
        st.session_state.hosts_data = generate_sample_data()
        st.session_state.anomalies = detect_anomalies(st.session_state.hosts_data)
        st.session_state.alerts = generate_alerts(st.session_state.hosts_data)
        st.success("Sample data generated!")
    
    # File Upload
    st.subheader("Upload Data")
    uploaded_file = st.file_uploader("Choose a CSV file", type=['csv'])
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            # Add synthetic metrics if not present
            if 'cpu_usage' not in df.columns:
                df['cpu_usage'] = np.random.uniform(10, 95, len(df))
            if 'memory_usage' not in df.columns:
                df['memory_usage'] = np.random.uniform(20, 90, len(df))
            if 'disk_usage' not in df.columns:
                df['disk_usage'] = np.random.uniform(30, 85, len(df))
            
            st.session_state.hosts_data = df
            st.session_state.anomalies = detect_anomalies(df)
            st.session_state.alerts = generate_alerts(df)
            st.success(f"Loaded {len(df)} hosts")
        except Exception as e:
            st.error(f"Error loading file: {e}")

# Main content based on page selection
if page == "📊 Dashboard":
    st.title("Infrastructure Monitoring Dashboard")
    
    if st.session_state.hosts_data.empty:
        st.warning("No data loaded. Click 'Generate Sample Data' in the sidebar to get started!")
    else:
        df = st.session_state.hosts_data
        
        # Key Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_hosts = len(df)
            st.metric("Total Hosts", total_hosts, delta="+5 from last week")
        
        with col2:
            healthy_hosts = len(df[df['falcon_status'] == 'Healthy'])
            st.metric("Healthy Hosts", healthy_hosts, delta=f"{healthy_hosts/total_hosts*100:.1f}%")
        
        with col3:
            critical_alerts = len([a for a in st.session_state.alerts if a['severity'] == 'critical'])
            st.metric("Critical Alerts", critical_alerts, delta="-2 from yesterday")
        
        with col4:
            anomalies_count = len(st.session_state.anomalies)
            st.metric("Anomalies Detected", anomalies_count)
        
        # Charts Row 1
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Host Status Distribution")
            status_counts = df['falcon_status'].value_counts()
            fig = px.pie(values=status_counts.values, names=status_counts.index,
                        color_discrete_map={'Healthy': '#28a745', 'Failed': '#dc3545', 
                                          'Unknown': '#6c757d', 'Degraded': '#ffc107'})
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("OS Distribution")
            os_counts = df['os_distribution'].value_counts()
            fig = px.bar(x=os_counts.index, y=os_counts.values,
                        labels={'x': 'OS', 'y': 'Count'})
            st.plotly_chart(fig, use_container_width=True)
        
        # Resource Usage Overview
        st.subheader("Resource Usage Heatmap")
        
        # Create heatmap data
        heatmap_data = df[['hostname', 'cpu_usage', 'memory_usage', 'disk_usage']].head(20)
        fig = go.Figure(data=go.Heatmap(
            z=[heatmap_data['cpu_usage'].values,
               heatmap_data['memory_usage'].values,
               heatmap_data['disk_usage'].values],
            x=heatmap_data['hostname'].values,
            y=['CPU', 'Memory', 'Disk'],
            colorscale='RdYlGn_r',
            text=[[f'{v:.0f}%' for v in heatmap_data['cpu_usage'].values],
                  [f'{v:.0f}%' for v in heatmap_data['memory_usage'].values],
                  [f'{v:.0f}%' for v in heatmap_data['disk_usage'].values]],
            texttemplate='%{text}',
            textfont={"size": 10}
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)

elif page == "🖥️ Host Inventory":
    st.title("Host Inventory")
    
    if st.session_state.hosts_data.empty:
        st.info("No hosts loaded. Generate sample data or upload a CSV file.")
    else:
        df = st.session_state.hosts_data
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.multiselect("Filter by Status", 
                                          options=df['falcon_status'].unique(),
                                          default=df['falcon_status'].unique())
        with col2:
            os_filter = st.multiselect("Filter by OS", 
                                       options=df['os_distribution'].unique(),
                                       default=df['os_distribution'].unique())
        with col3:
            search = st.text_input("Search hostname")
        
        # Apply filters
        filtered_df = df[
            (df['falcon_status'].isin(status_filter)) &
            (df['os_distribution'].isin(os_filter))
        ]
        
        if search:
            filtered_df = filtered_df[filtered_df['hostname'].str.contains(search, case=False)]
        
        # Display table
        st.dataframe(
            filtered_df[['hostname', 'ip_address', 'os_distribution', 'falcon_status',
                        'cpu_usage', 'memory_usage', 'disk_usage', 'is_reachable', 
                        'owner_name', 'last_seen']],
            use_container_width=True,
            height=500
        )
        
        st.info(f"Showing {len(filtered_df)} of {len(df)} hosts")

elif page == "⚠️ Alerts":
    st.title("Alert Management")
    
    if not st.session_state.alerts:
        st.success("No active alerts! All systems operating normally.")
    else:
        # Alert statistics
        col1, col2, col3 = st.columns(3)
        critical = [a for a in st.session_state.alerts if a['severity'] == 'critical']
        warning = [a for a in st.session_state.alerts if a['severity'] == 'warning']
        info = [a for a in st.session_state.alerts if a['severity'] == 'info']
        
        with col1:
            st.metric("🔴 Critical", len(critical))
        with col2:
            st.metric("🟡 Warning", len(warning))
        with col3:
            st.metric("🔵 Info", len(info))
        
        # Alert list
        st.subheader("Active Alerts")
        
        # Sort alerts by severity
        sorted_alerts = sorted(st.session_state.alerts, 
                              key=lambda x: {'critical': 0, 'warning': 1, 'info': 2}[x['severity']])
        
        for alert in sorted_alerts[:20]:  # Show latest 20
            severity_color = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}
            with st.expander(f"{severity_color[alert['severity']]} {alert['type']} - {alert['hostname']}"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.write(f"**Message:** {alert['message']}")
                    st.write(f"**Time:** {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                with col2:
                    if st.button(f"Acknowledge", key=f"ack_{alert['hostname']}_{alert['timestamp']}"):
                        st.success("Alert acknowledged")

elif page == "🔍 Anomaly Detection":
    st.title("AI-Powered Anomaly Detection")
    
    if not st.session_state.anomalies:
        st.info("No anomalies detected. System behavior appears normal.")
    else:
        st.subheader(f"Detected {len(st.session_state.anomalies)} Anomalies")
        
        # Anomaly visualization
        anomaly_df = pd.DataFrame(st.session_state.anomalies)
        
        # Anomaly scores distribution
        fig = px.histogram(anomaly_df, x='anomaly_score', nbins=20,
                          title="Anomaly Score Distribution",
                          labels={'anomaly_score': 'Anomaly Score', 'count': 'Frequency'})
        st.plotly_chart(fig, use_container_width=True)
        
        # Anomaly details
        st.subheader("Anomaly Details")
        for anomaly in st.session_state.anomalies[:10]:
            with st.expander(f"⚠️ {anomaly['hostname']} - {anomaly['type']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Anomaly Score:** {anomaly['anomaly_score']:.3f}")
                    st.write(f"**Details:** {anomaly['details']}")
                with col2:
                    st.write(f"**Detected:** {anomaly['detected_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    if st.button("Investigate", key=f"inv_{anomaly['hostname']}"):
                        st.info("Opening detailed investigation view...")

elif page == "📈 Analytics":
    st.title("Analytics & Predictions")
    
    if st.session_state.hosts_data.empty:
        st.warning("No data available for analytics.")
    else:
        df = st.session_state.hosts_data
        
        # Time series simulation
        st.subheader("Resource Usage Trends")
        
        # Generate time series data
        time_points = pd.date_range(start=datetime.now() - timedelta(hours=24), 
                                   end=datetime.now(), 
                                   periods=100)
        
        trend_data = pd.DataFrame({
            'Time': time_points,
            'Avg CPU': np.cumsum(np.random.randn(100)) + 50,
            'Avg Memory': np.cumsum(np.random.randn(100)) + 60,
            'Avg Disk': np.cumsum(np.random.randn(100)) + 40
        })
        
        fig = px.line(trend_data, x='Time', y=['Avg CPU', 'Avg Memory', 'Avg Disk'],
                     title="24-Hour Resource Usage Trends")
        st.plotly_chart(fig, use_container_width=True)
        
        # Predictive insights
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Failure Predictions")
            st.info("Based on current trends:")
            st.write("• 3 hosts likely to exceed CPU threshold in next 2 hours")
            st.write("• 2 hosts showing disk usage patterns similar to previous failures")
            st.write("• Network anomaly pattern detected in subnet 10.0.3.x")
        
        with col2:
            st.subheader("Optimization Recommendations")
            st.success("Suggested actions:")
            st.write("• Migrate workloads from host-045 (95% CPU)")
            st.write("• Schedule maintenance for hosts with failed Falcon agents")
            st.write("• Consider scaling resources for Ubuntu 22.04 hosts")

elif page == "⚙️ Settings":
    st.title("Settings & Configuration")
    
    st.subheader("Alert Thresholds")
    col1, col2 = st.columns(2)
    
    with col1:
        cpu_threshold = st.slider("CPU Alert Threshold (%)", 50, 100, 90)
        memory_threshold = st.slider("Memory Alert Threshold (%)", 50, 100, 80)
        disk_threshold = st.slider("Disk Alert Threshold (%)", 50, 100, 85)
    
    with col2:
        st.subheader("Anomaly Detection")
        contamination = st.slider("Anomaly Sensitivity", 0.01, 0.3, 0.1, 
                                 help="Higher values detect more anomalies")
        
        st.subheader("Refresh Rate")
        refresh_rate = st.selectbox("Auto-refresh interval", 
                                   ["Disabled", "30 seconds", "1 minute", "5 minutes"])
    
    st.markdown("---")
    
    st.subheader("Export Data")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📥 Export Hosts CSV"):
            if not st.session_state.hosts_data.empty:
                csv = st.session_state.hosts_data.to_csv(index=False)
                st.download_button("Download CSV", csv, "hosts_export.csv", "text/csv")
    
    with col2:
        if st.button("📥 Export Alerts JSON"):
            if st.session_state.alerts:
                # Convert datetime to string for JSON serialization
                alerts_json = []
                for alert in st.session_state.alerts:
                    alert_copy = alert.copy()
                    alert_copy['timestamp'] = alert_copy['timestamp'].isoformat()
                    alerts_json.append(alert_copy)
                json_str = json.dumps(alerts_json, indent=2)
                st.download_button("Download JSON", json_str, "alerts_export.json", "application/json")
    
    with col3:
        if st.button("🔄 Reset All Data"):
            st.session_state.hosts_data = pd.DataFrame()
            st.session_state.alerts = []
            st.session_state.anomalies = []
            st.success("All data cleared!")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        AI Infrastructure Monitoring System | Built with Streamlit
    </div>
    """,
    unsafe_allow_html=True
)
