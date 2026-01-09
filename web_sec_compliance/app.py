"""
Web Security Compliance Checker - Main Application
Author: Security Engineering Team
Description: Streamlit interface for comprehensive web security assessment
"""

import streamlit as st
import pandas as pd
from controller import SecurityController
import time

st.set_page_config(
    page_title="Web Security Compliance Checker", page_icon="🛡️", layout="wide"
)

# Custom CSS
st.markdown(
    """
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #0066cc;
        color: white;
        font-weight: bold;
        padding: 0.5rem 2rem;
    }
    .stButton>button:hover {
        background-color: #0052a3;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def main():
    # Header
    st.title("🛡️ Web Security Compliance Checker")
    st.markdown("### Comprehensive 28-Point Security Assessment")
    st.markdown("---")

    # Input Section
    col1, col2 = st.columns([3, 1])

    with col1:
        url = st.text_input(
            "Enter Website URL",
            placeholder="https://example.com",
            help="Enter the full URL including https://",
        )

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_button = st.button("🔍 Scan Website", use_container_width=True)

    # Scan Process
    if scan_button:
        if not url:
            st.error("⚠️ Please enter a valid URL")
            return

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            st.error("⚠️ URL must start with http:// or https://")
            return

        # Initialize controller
        controller = SecurityController(url)

        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()

        status_text.text("🔄 Initializing security scan...")
        time.sleep(0.5)
        progress_bar.progress(10)

        # Run scan
        status_text.text("🔍 Performing security checks...")
        results = controller.run_all_checks(progress_callback=progress_bar)
        progress_bar.progress(100)
        status_text.text("✅ Scan completed!")

        time.sleep(0.5)
        status_text.empty()
        progress_bar.empty()

        # Display Results
        st.markdown("---")
        st.markdown("## 📊 Scan Results")

        # Summary Cards
        compliant = sum(1 for r in results if r["status"] == "Y")
        non_compliant = len(results) - compliant
        compliance_rate = (compliant / len(results)) * 100

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                label="✅ Compliant", value=compliant, delta=f"{compliance_rate:.1f}%"
            )

        with col2:
            st.metric(
                label="❌ Non-Compliant",
                value=non_compliant,
                delta=f"{100 - compliance_rate:.1f}%",
                delta_color="inverse",
            )

        with col3:
            st.metric(label="📈 Compliance Rate", value=f"{compliance_rate:.1f}%")

        st.markdown("---")

        # Results Table
        st.markdown("### Detailed Compliance Report")

        # Convert to DataFrame
        df = pd.DataFrame(results)

        # Style the dataframe
        def color_status(val):
            color = "#90EE90" if val == "Y" else "#FFB6C1"
            return f"background-color: {color}; font-weight: bold"

        styled_df = df.style.map(color_status, subset=["status"])

        st.dataframe(styled_df, use_container_width=True, height=800)

        # Download option
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download Report (CSV)",
            data=csv,
            file_name=f"security_report_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.csv",
            mime="text/csv",
        )

    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666; font-size: 0.9em;'>
            <p>⚠️ This tool performs passive security analysis only. No exploitation is performed.</p>
            <p>🔒 Ethical security testing - For authorized use only.</p>
        </div>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
